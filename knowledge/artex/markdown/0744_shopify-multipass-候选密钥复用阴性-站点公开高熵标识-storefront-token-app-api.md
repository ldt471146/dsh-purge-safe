# Shopify Multipass 候选密钥复用阴性：站点公开高熵标识（Storefront token/app apiKey/主题 GUID/CheckoutProfile GID）不是 Multipass secret（两店 152 次全 422）

- **code**: shopify-multipass-候选密钥复用阴性-站点公开高熵标识-storefront-token-app-api
- **kind**: poc
- **category**: auth-bypass
- **component**: Shopify Multipass（/account/login/multipass/&lt;token&gt;）
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-12 10:55–11:05Z 两店实测：19 个公开高熵标识（614a937da9d7ca28dfbbf69a0f9cf2e1、36895f0e7a8b165121bc0d677d0d9a5c、1c76cf8a2c51f2fcf7a52ae3db9b0d6f、ToxvAmt7lYjnGq8wvey3、00750fd7-0195-4fc2-9582-f9e3ba199188、www/collect 各 5 个 OPP 模板 GUID、CheckoutProfile GID 5731189060/2944860497、registrationUuid 6f6331cf-…/79cc2737-…）×4 种标准构造（sha256 前16/后16 两种分片 + sha256(secret+"encryption"/"signing") + HMAC(secret,"encryption"/"signing")）×2 店 = 152 次 → 全部 HTTP/2 422 "Invalid Multipass request"，canary 邮箱未取得任何登录态；422 下发的 _shopify_essential 为匿名 cookie（带它访问 /account 与无 cookie 同为 302→account 域 buyer_flags {"flags":[]}）。
- **tags**: shopify,multipass,sso,auth-bypass,negative,key-reuse
- **created_at**: 2026-11-12T11:02:45.410Z
- **engine**: https://www.thegamecollection.net; https://collect.thegamecollection.net

## 用法

```
前提：Shopify 店 /account/login/multipass/&lt;畸形token&gt; 返回 422（=Multipass 已启用），404=未启用别做。判据：422=token 级拒绝；任何非 422（302 到 /account 或账户页呈现登录态）=命中。复用时别把公开的 Storefront token / app apiKey / 模板 GUID / CheckoutProfile GID / registrationUuid / Firebase 下载 token 当 secret 反复试（本环境已 152 次全阴）；这些值只用于别的面（extensionMetafields/extensionApiTokens/像素 PII）。真 secret 只能从店铺后台 or 泄露面拿。注意 422 响应本身就带 Set-Cookie（_shopify_essential 等匿名 cookie），不要误判为"下发会话"——用 cookie jar 请求 /account 与无 cookie 对照判断登录态。Bash/Python 实现：token=base64url(HMAC-SHA256(sig_key, iv||AES-128-CBC(PKCS7(json)))||iv||ct)，payload 必含 email+created_at，remote_ip 可省（省了不校验来源 IP）；用已存在客户邮箱可避免成功时创建新客户。
```
