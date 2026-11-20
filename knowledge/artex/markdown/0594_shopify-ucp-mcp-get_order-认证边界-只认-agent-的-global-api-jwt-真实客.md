# Shopify UCP/MCP get_order 认证边界：只认 agent 的 Global API JWT，真实客户会话令牌全部被拒（阴性封堵）

- **code**: shopify-ucp-mcp-get_order-认证边界-只认-agent-的-global-api-jwt-真实客
- **kind**: poc
- **category**: auth-bypass
- **component**: Shopify UCP / MCP (JSON-RPC 2.0 /api/ucp/mcp)
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 在 www.thegamecollection.net 与 collect.thegamecollection.net 实测：tools/list 匿名200(14工具含get_order)；get_order 匿名403 AuthenticationRequired；Cookie _shopify_essential(account域/www域真实会话值)仍403（cookie完全不被采信）；Bearer <_shopify_essential会话串|Shopify签名shcaat_匿名JWT|账户页App Bridge JWT> 均401 AuthenticationFailed "Invalid global access token."；X-Shopify-Customer-JWT 头403。官方 order-mcp 文档要求 Token-tier agent 的 Global API JWT（scope read_global_api_orders，由 api.shopify.com/auth/access_token 以 client_credentials 换取）+ Shopify-Buyer-IP，且仅能读本 agent 下单订单，v1 不支持 buyer identity linking。
- **tags**: shopify,ucp,mcp,get_order,jwt,auth,negative,customer-token,_shopify_essential,shcaat
- **created_at**: 2026-11-11T17:11:36.856Z
- **engine**: https://www.thegamecollection.net/api/ucp/mcp

## 描述

Shopify 店面 UCP/MCP 网关中 get_order（及 complete_checkout）的 JWT 门禁与客户身份正交：它校验的是 agent 侧 Global API JWT（api.shopify.com/auth/access_token 换取，claim scope 含 read_global_api_orders），不是客户账户令牌。客户账户域的可提取令牌（_shopify_essential 不透明会话、账户页 App Bridge 扩展 JWT、account.thegamecollection.net/oauth/token?resource_id= 无认证签发的 shcaat_ Ed25519匿名JWT[typ=anonymous,无sub]）全部无法通过该门禁。注意 403→401 只是"解析到 Bearer 并判类型不符"，不是授权通过；401 文案固定 "Invalid global access token."。故客户登录态无法用于订单 IDOR/跨店 audience，除非持有 Shopify Dev Dashboard 的 agent client_id/client_secret。

## 用法

```
验证矩阵（单线程≥3s）：POST https://<shop>/api/ucp/mcp  body {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_order","arguments":{"meta":{"ucp-agent":{"profile":"https://<shop>/.well-known/ucp"}},"id":"gid://shopify/Order/1"}}}；匿名/带客户Cookie → 403 AuthenticationRequired；带任意客户侧 Bearer → 401 Invalid global access token。要真正调用需先 POST https://api.shopify.com/auth/access_token {"client_id":...,"client_secret":...,"grant_type":"client_credentials"} 并把返回 JWT 放 Authorization: Bearer，同时加 Shopify-Buyer-IP。
```
