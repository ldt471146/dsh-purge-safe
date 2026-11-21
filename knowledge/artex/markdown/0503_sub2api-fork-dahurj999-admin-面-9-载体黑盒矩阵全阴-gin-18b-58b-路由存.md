# Sub2API fork(dahurj999) admin 面 9 载体黑盒矩阵全阴 + gin 18B/58B 路由存在性 oracle（可复用于任何 gin 站）

- **code**: sub2api-fork-dahurj999-admin-面-9-载体黑盒矩阵全阴-gin-18b-58b-路由存
- **kind**: poc
- **category**: auth-bypass
- **component**: Sub2API (Wei-Shaw/sub2api) fork / gin / Photon-Edge
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-03 04:0x 对 https://www.dahurj999.top 实测：39 发矩阵（7 路由 × noauth/userJWT/adm_sc_test/小写bearer/空key+JWT/WS子协议/错key+JWT/OPTIONS/尾斜杠）+14 发额外载体，全部 401/403（仅尾斜杠 301）；阳性对照 /api/v1/user/profile 带 user1013 JWT 返 200/2957B。同一 oracle 反向校准成功（/api/v1/admin/backups/export→401 存在，/api/v1/admin/backup→404|18 不存在）。产物 D:/ARTEX/data/tasks/612/i7800/SUMMARY.txt、i7825/{extra,exist,jwtprobe}.txt。
- **created_at**: 2026-11-02T20:05:31.499Z
- **engine**: https://www.dahurj999.top

## 描述

负面情报 + 一套通用判据。前者：Sub2API 0.2.19 的 fork 在 admin 面上与上游行为完全一致，9 种匿名/弱载体无一能越过 adminAuth，别在这条轴上再重复投预算。后者：gin 的 NoRoute 体（18B 纯文本 "404 page not found"）与中间件 401（58B JSON）不可混淆，可当路由存在性 oracle 用，并能按响应消息区分「挂 adminAuth 组」(58B Authorization required) 与「挂用户鉴权组」(68B Authorization header is required)；SPA 回退是 200+HTML，是第三种形态，别误判为命中。

## 用法

```
1) 判映射/挂组：GET <path> 不带鉴权 → 18B "404 page not found"=路由不存在；58B "Authorization required"=admin 组；68B "Authorization header is required"=仅用户组（挂错组的软点，值得带 user JWT 继续打）；200+<!doctype html>=落 SPA 回退。2) 扫 fork-only 路由时先用 1) 过滤，只对非 404 的花鉴权请求。3) 已证 admin 面无效的载体（勿重复）：X-Admin-Key、Cookie token/access_token、query api_key/token/access_token、Sec-WebSocket-Protocol、OPTIONS 预检、空 x-api-key、路径大小写/双斜杠/点段/%61 编码。有效载体只有 Authorization: Bearer（大小写不限，值必须是 admin）。4) 附带行为：坏 x-api-key 先于 JWT 判并短路成 401 INVALID_ADMIN_KEY，唯独 /api/v1/admin/settings/admin-api-key 会在 handler 内再判一次 JWT 角色并回中文 403「仅 JWT 管理员可管理密钥」——想找 handler 级断层的可从它入手。实测命令：curl.exe --noproxy '*' -s -k -o b.txt -w '%{http_code}|%{size_download}' -H 'Authorization: Bearer <jwt>' https://host/api/v1/admin/backups
```
