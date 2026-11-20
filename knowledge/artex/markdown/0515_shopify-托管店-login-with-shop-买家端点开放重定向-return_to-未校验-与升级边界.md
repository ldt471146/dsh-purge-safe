# Shopify 托管店 Login with Shop 买家端点开放重定向（return_to 未校验）与升级边界

- **code**: shopify-托管店-login-with-shop-买家端点开放重定向-return_to-未校验-与升级边界
- **kind**: poc
- **category**: methodology
- **component**: Shopify Storefront (Login with Shop)
- **source**: self
- **tags**: open-redirect,shopify,login_with_shop,oauth,negative
- **created_at**: 2026-11-11T14:11:54.405Z
- **engine**: gamersdelight.co.uk

## 描述

Shopify 托管店的 /services/login_with_shop/buyer/complete 与 /buyer/start 对 return_to 不校验，免认证 302 到任意 http/https 绝对 URL，可用 userinfo@ 或 host 后缀绕过同源判断。判据：无 Cookie 直接 GET 带 return_to=<外部绝对URL> 返回 302 且 Location 回显。但该端点不会把 code/state 追加到 return_to，故不构成 OAuth 授权码外带；真正登录链 /customer_authentication/login 会校验 return_to（绝对外链->400），/customer_authentication/callback 需有效 state（否则400）。升级到凭据/会话泄露被阻断，仅余钓鱼落地价值。

## 用法

```
复现：curl -s -D - "https://HOST/services/login_with_shop/buyer/complete?return_to=https://evil.example/poc" | grep -i location。绕过：return_to=https%3A%2F%2FHOST%40evil.example%2F 或 https://evil.example:443@pwn。阴性对照：不带 return_to -> 400；javascript:/data:/相对路径 -> 400。判定升级空间：仅当 /complete 会把 code 追加到 return_to 才具 OAuth 危害，本目标实测不追加。
```
