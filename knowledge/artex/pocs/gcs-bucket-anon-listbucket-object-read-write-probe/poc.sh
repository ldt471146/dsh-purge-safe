#!/usr/bin/env bash
# GCS 桶匿名权限判定：ListBucket（三端点）+ 对象读 + 写权限安全探针
# 用法：
#   BUCKET=dx2-xxxx CUSTOM=https://static.example.com bash gcs_bucket_anon_probe.sh
#   BUCKET=dx2-xxxx REALKEY="v2/1.0.0.9/patch_config.lua" bash gcs_bucket_anon_probe.sh
# 前置：有 HTTP 代理时必须 --noproxy '*'；自定义域可能只支持 TLS1.2
set -u
BUCKET="${BUCKET:?set BUCKET=<gcs bucket name>}"
CUSTOM="${CUSTOM:-https://storage.googleapis.com/$BUCKET}"
REALKEY="${REALKEY:-}"
C="curl -sS -k --noproxy * --max-time 20 --tlsv1.2"

echo "=== [1] 自定义域 XML API 列举（v1 风格，delimiter 看分层）==="
$C -D /tmp/h1 "$CUSTOM/?delimiter=/&max-keys=1000" -o /tmp/b1
head -1 /tmp/h1; grep -i '^x-goog-\|^content-type\|^server' /tmp/h1 | head -6
grep -o '<Name>[^<]*</Name>' /tmp/b1
grep -o '<Prefix>[^<]*</Prefix>' /tmp/b1 | head -20
grep -o '<Key>[^<]*</Key>' /tmp/b1 | head -20
# 判据：<ListBucketResult> 且 <Name>=桶名 ⇒ 匿名拥有 storage.objects.list

echo "=== [2] 规范域 S3 互操作端点（排除自定义域前置伪造/缓存）==="
$C -D /tmp/h2 "https://storage.googleapis.com/$BUCKET?list-type=2&max-keys=3" -o /tmp/b2
head -1 /tmp/h2
grep -o '<KeyCount>[^<]*</KeyCount>\|<IsTruncated>[^<]*</IsTruncated>\|<NextContinuationToken>[^<]*' /tmp/b2

echo "=== [3] 规范域 JSON API（第三个独立实现，交叉验证）==="
$C "https://storage.googleapis.com/storage/v1/b/$BUCKET/o?maxResults=3" | head -c 600; echo

echo "=== [4] 对象级匿名读（Range 首片，不整包下载）==="
for K in ${REALKEY:-}; do
  echo "--- $K"
  $C -r 0-63 -D /tmp/h4 "https://storage.googleapis.com/$BUCKET/$K" -o /tmp/head.bin
  head -1 /tmp/h4
  grep -i 'x-goog-generation\|x-goog-stored-content-length\|content-range\|content-type' /tmp/h4
  xxd -l 16 /tmp/head.bin 2>/dev/null
done
# 判据：206 + x-goog-stored-content-length 真实大小 + 魔数吻合 = 实锤未授权对象读

echo "=== [5] bucket / 对象 ACL 是否也暴露（通常 403，暴露面只到对象层）==="
$C -o /tmp/b5 -w 'bucket ?acl -> HTTP %{http_code}\n' "$CUSTOM/?acl"
grep -o '<Code>[^<]*</Code>\|<Details>[^<]*' /tmp/b5 | head -3
if [ -n "${REALKEY:-}" ]; then
  $C -o /tmp/b5b -w 'object ?acl -> HTTP %{http_code}\n' \
     "https://storage.googleapis.com/$BUCKET/$REALKEY?acl"
  grep -o '<Code>[^<]*</Code>' /tmp/b5b | head -3
fi

echo "=== [6] 写权限安全探针：x-goog-if-generation-match: 0 ==="
# 语义：仅当对象不存在时才允许写入 → 对已存在的线上对象必然失败，
# 因此 403/412 都不会改动任何制品；绝不覆盖 version.txt / patch_config.lua
$C -X PUT -o /tmp/b6 -w 'PUT(if-generation-match:0) -> HTTP %{http_code}\n' \
   -H 'x-goog-if-generation-match: 0' -H 'Content-Length: 0' \
   "https://storage.googleapis.com/$BUCKET/zz_probe_$(date +%s).txt"
grep -o '<Code>[^<]*</Code>\|<Details>[^<]*\|permission[^<"]*' /tmp/b6 | head -5
# 403 + storage.objects.create denied ⇒ 无匿名写
# 412 ⇒ ACL 允许 create（条件未满足），写权限存在，升级为供应链问题
# 200 ⇒ 真的写入成功，立即删除该探针对象

echo "=== [7] 结论模板 ==="
cat <<'EOF'
- 可列举 : 1/2/3 任一返回 200 + ListBucketResult（或 JSON items）——
           至少两个不同端点验证，避免自定义域前置缓存/SPA 回落假阳性
- 可读   : 4 返回 206/200 + 正确 Content-Length + 文件魔数
- 不可写 : 6 返回 403 storage.objects.create denied（或 412）
- bucket 元数据未暴露 : 5 返回 403 storage.buckets.get / objects.getIamPolicy denied
EOF

# ===== 附录 A：从热更 abUrl 反查同一桶的多个前端 / 镜像（task#614 实测）=====
# 1) 来源：客户端启动时请求 /maintenance（或同名配置接口），响应 servers[] 中
#    type==2 的 abUrl 即 Unity 热更基址。实测一次下发三台：
#      https://qd16.xatqgl.club     （GCS 前置，可匿名 ListBucket）
#      https://fmai.bszhan.com      （EdgeOne 前置，透传 GCS ListBucketResult）
#      https://ime8.fp32xa.com      （AWS S3 ap-east-1 + CloudFront，列举 403）
#
# 2) 判定"同一份对象"：逐台 GET /v2/<ver>/patch_config.lua，比 Content-Length 与 ETag。
#    实测三台均 10483B、ETag "dab76fdb740e1ebcf65aa13766a3052a" → 同一仓库。
#    这一招不需要列举权限，S3 前端列举 403 时照样能确认同源。
#
# 3) 逐台判鉴权面（差异很常见，别用一台的结论推全量）：
#    - GCS 前置   : Server: UploadServer / Via: 1.1 google / X-Goog-* → 试 ListBucket
#    - S3+CF      : Server: AmazonS3 / X-Amz-Bucket-Region / Via *.cloudfront.net
#                   → 列举 403 AccessDenied，但按 patch_config.lua 的 filePath 逐 key 取 200
#    - EdgeOne 等 : Eo-Cache-Status / Eo-Log-Uuid，通常透传后端 XML
#
# 4) 不需要列举权限也能全量取：patch_config.lua 自身给出 md5 + fileName + filePath，
#    照单逐个取对象即可（androidVersion/iosVersion → sp1.1..sp4.3）。
#
# 5) 边界：每主机 ≤4 发、只读 GET/HEAD + 一次必然落空的条件 PUT；
#    不递归拉全量、不下载整包、绝不覆盖已有对象。
for U in ${ABURLS:-}; do
  echo "--- $U"
  $C -o /tmp/pc -D /tmp/hpc "$U/v2/1.0.0.9/patch_config.lua"
  grep -i '^HTTP/\|^content-length\|^etag\|^server\|^via\|^x-goog-generation\|^x-amz-bucket-region' /tmp/hpc | head -8
  head -c 200 /tmp/pc; echo
done
# 判据：同一 ETag + 同一 Content-Length ⇒ 同一制品；再看各自列表端点是否 200