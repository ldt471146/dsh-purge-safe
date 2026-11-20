# Shopify UCP/MCP agent profile「自声明高权限」不构成授权绕过：profile 仅作能力协商，与 JWT 门禁正交（负数情报）

- **code**: shopify-ucp-mcp-agent-profile-自声明高权限-不构成授权绕过-profile-仅作能力协商
- **kind**: poc
- **category**: auth-bypass
- **component**: Shopify UCP / MCP (Universal Commerce Protocol, /api/ucp/mcp)
- **source**: self
- **verified**: 1
- **verified_note**: goffsgames.co.uk /api/ucp/mcp 实测（2026-11-11）：attacker 自建源站(127.0.0.1)经 cloudflared quick tunnel 托管自声明高权限 profile（application/json + Cache-Control public,max-age=600，含 dev.ucp.shopping.order/checkout、scopes[orders:read,checkout:complete,customers:read]、agent.capabilities[get_order,complete_checkout]）→ search_catalog/get_product/lookup_catalog/ask_business/create_cart/get_cart/update_cart/cancel_cart/create_checkout/get_checkout 全 http=200 status:success（证明 profile 被采信）；但同 profile 下 get_order/complete_checkout 仍 http=403 {"code":-32000,"message":"AuthenticationRequired"}。关键判据：profile 缺失(422 invalid_profile_url)/不可达/畸形(422 profile_malformed)时这两个工具也始终 403 而非 422/424 → JWT 门禁先于 profile 校验。伪造 JWT(alg=none / HS256 自签) 均 401 AuthenticationFailed。
- **tags**: shopify,ucp,mcp,agent-profile,auth-bypass,negative,jwt,cloudflared
- **created_at**: 2026-11-11T15:03:29.944Z
- **engine**: goffsgames.co.uk
- **found_by**: work

## 描述

打法/判据：UCP/MCP 的 meta.ucp-agent.profile 只是「能力协商」输入，服务端 fetch 后仅用于协商/合规校验，绝不据此赋予 JWT 权限。想让 get_order/complete_checkout 返回数据只能提供 Shopify 认证服务签发的 JWT，自声明 scopes/permissions/capabilities 无效。另含 profile 抓取硬校验（可用于判断 profile 是否被采信）：必须 HTTPS、无 3xx 重定向、content-type application/json、Cache-Control: public 且 max-age≥60、JSON 可解析；公共 paste 服务（dpaste text/plain / uguu 无 cache-control / catbox json parse 错）均会被 422 profile_malformed 拒；满足条件可用「本机源站 + cloudflared quick tunnel」托管。端点匿名写类操作限速会激化：连续调用后 429 "retry after ~3469s"。

## 用法

```
1) 判断 profile 是否被采信：调 search_catalog(带 profile)，200 status:success=采信，422 profile_malformed=头/内容不合规（按 Invalid content type / Invalid cache control / Json parse error 定位）。
2) 托管合规 profile：本机 python http.server 绑 127.0.0.1 返回 application/json + Cache-Control: public, max-age=600，再 cloudflared tunnel --url http://127.0.0.1:PORT --protocol http2 取 trycloudflare URL（CF 透传源站 Cache-Control）。
3) 授权绕过判定：同 profile 下 get_order/complete_checkout http=403 AuthenticationRequired 即阴性；若 200 或返回真实订单/买家数据则阳性。
4) 别指望自声明 scopes/capabilities 解锁 JWT 工具；也别高频打该端点（限速会涨到 ~1 小时）。
```
