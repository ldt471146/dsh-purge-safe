# RainLoop 1.17.0 admin 登录协议实证：必须带 AppData 下发的 XToken，102=口令错误、101=InvalidToken

- **code**: import-subprocess-re-json-os-from-urllib.parse-import-quo
- **kind**: script
- **category**: methodology
- **component**: RainLoop
- **versions**: 1.17.0（PHP 版，Plesk 托管）
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-12T01:44Z 在 portal.endif.co.uk（源站 92.205.178.49，Host 头路由）实测：GET /?/AppData 匿名 200 返回 __initAppData 且 System.token=c5e01f3e628ad1257e31413c81f8c9d9；POST /?/Ajax/ Action=AdminLogin&Login=admin&Password=admin&XToken=<token> 返回 {"Action":"AdminLogin","Result":false,"ErrorCode":102}（口令错误）；不带 XToken 时同请求返回 ErrorCode 101（InvalidToken，口令未被校验）。5 个候选连测无 429/锁定，连续两次同 token 复用仍有效。
- **tags**: rainloop,admin-login,xtoken,errorcode,baseline
- **created_at**: 2026-11-12T01:49:21.767Z
- **engine**: portal.endif.co.uk / 92.205.178.49

## 描述

RainLoop 1.17.0 管理面板 AdminLogin 的 Ajax 调用必须携带 /?/AppData 下发的 XToken，否则返回 101（InvalidToken）而非口令校验结果；102 才是口令错误。用于离线破解命中后的单次在线验证，或判定在线爆破通道是否真的在验证口令。

## 用法

```
判读要点：只有 ErrorCode 102 才代表服务器真正校验了口令；101 是 CSRF/令牌错误，不能当作"口令错误"基线（历史 worker 曾在 admin/12345 上误读 101）。每次 AdminLogin 前先 GET /?/AppData 取 System.token，POST body 里带上 XToken 且 Header 用 Host: portal.endif.co.uk（直连源站绕过 CF 时必须）。命中判据 Result=true，且再 GET /?/AppData 看 System 中 admin 标志。
```
