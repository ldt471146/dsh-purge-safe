# 端口 banner 抓取器（自动判 SSH/MySQL/HTTP）banner.py

- **code**: 端口-banner-抓取器-自动判-ssh-mysql-http-banner.py
- **kind**: poc
- **category**: recon
- **component**: 红队侦察基础设施
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 靶标上实测 41 个端口，产出可直接进资产库的精确指纹：① **6 台 `OpenSSH_6.0p1 Debian-4+deb7u6`（Debian 7，2016 已 EOL）**（.20/.119/.122/.166/.234/.235）；② `203.0.113.12:22 = OpenSSH_8.0`（**首次发现该端口从 RST 变为 OPEN**，已回写资产）；③ `.238:22` 回 `Exceeded MaxStartups`（sshd 达最大并发）；④ **4 台数据库端口对公网开放**：`.70/.133/.181` MySQL、`.172` MariaDB，均回 `Host '203.0.113.74' is not allowed to connect` —— **由此发现我方出口 IP 已变为 203.0.113.74（早先记录为 203.0.113.119）**；⑤ `.200:8888` 回 302 → `http://203.0.113.16/login` + `Set-Cookie: SESSIONID=`（据此判定是通用应用登录页、非 LHZS 网关）。
- **path**: pocs/端口-banner-抓取器-自动判-ssh-mysql-http-banner.py/banner.py
- **tags**: banner,服务识别,SSH,MySQL,版本指纹,recon
- **created_at**: 2026-10-11T09:41:35.349Z
- **found_by**: recon

## 描述

抓端口 banner 并自动判协议：① 先空读 —— 服务端主动先发的协议（SSH 吐 `SSH-2.0-...`、MySQL 吐握手包）可直接识别版本；② 若不是这两类，再补发一次 HTTP/1.1 请求取状态码与 Server 头。产出每个端口的 service/product/version/banner，是**端口服务识别**的标配工具。原生 socket，不走代理。

## 用法

```
python banner.py "ip:port,ip:port,..." [timeout秒=6.0]
例：python banner.py "203.0.113.12:22,203.0.113.18:3306,203.0.113.16:8888" 6.0
```

## 正文

```
# -*- coding: utf-8 -*-
"""端口 banner 抓取（原生 socket，不走代理）。用法: python banner.py "ip:port,..." [timeout]"""
import socket, os, sys, json, re
from concurrent.futures import ThreadPoolExecutor, as_completed

for k in ("http_proxy","https_proxy","all_proxy","HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"):
    os.environ.pop(k, None)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

def grab(ip, port, timeout=6.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        # 先把 banner 读出来（SSH/MySQL 是服务端先发）
        first = b""
        try:
            s.settimeout(3.0)
            first = s.recv(1024)
        except socket.timeout:
            pass
        out = {}
        if first:
            out["banner"] = first[:300].decode("utf-8", "replace")
            t = first.strip()
            if t.startswith(b"SSH-"):
                out["proto"] = "ssh"
                out["product"] = t.decode("utf-8", "replace")
            elif len(first) > 5 and first[4] == 10:
                # MySQL 握手包
                out["proto"] = "mysql"
                try:
                    nlen = first[0]
                    ver_end = first.index(b"\x00", 5)
                    out["product"] = "MySQL " + first[5:ver_end].decode("utf-8", "replace")
                    # 截断的 auth plugin / capability
                except Exception:
                    out["product"] = "MySQL (handshake)"
        # 再做一次 HTTP 尝试（若还没识别）
        if out.get("proto") not in ("ssh", "mysql"):
            try:
                s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s2.settimeout(timeout)
                s2.connect((ip, port))
                req = ("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
                       "Accept: */*\r\nConnection: close\r\n\r\n" % ip)
                s2.sendall(req.encode())
                buf = b""
                while len(buf) < 3000:
                    try:
                        c = s2.recv(2048)
                    except socket.timeout:
                        break
                    if not c:
                        break
                    buf += c
                s2.close()
                ht = buf.decode("utf-8", "replace")
                m = re.match(r"HTTP/\d\.\d (\d+)", ht)
                if m:
                    srv = ""
                    for line in ht.split("\r\n"):
                        if line.lower().startswith("server:"):
                            srv = line.split(":",1)[1].strip()
                    out["proto"] = "http"
                    out["http"] = {"status": int(target22.example.com(1)), "server": srv,
                                   "head": ht[:250].replace("\r\n", " | ")}
                elif buf:
                    out.setdefault("banner", buf[:200].decode("utf-8","replace"))
            except Exception as e:
                out.setdefault("http_err", type(e).__name__)
        return ip, port, out
    except Exception as e:
        return ip, port, {"err": "%s: %s" % (type(e).__name__, e)}
    finally:
        try: s.close()
        except Exception: pass

def main():
    targets = [t.strip() for t in sys.argv[1].split(",") if t.strip()]
    timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 6.0
    res = {}
    jobs = []
    for t in targets:
        h, _, p = t.partition(":")
        jobs.append((h, int(p)))
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(grab, h, p, timeout) for h, p in jobs]
        for f in as_completed(futs):
            ip, port, out = f.result()
            res["%s:%s" % (ip, port)] = out
            print("%-24s %s" % ("%s:%d" % (ip, port), json.dumps(out, ensure_ascii=False)), flush=True)
    with open(r"C:\Users\user\Desktop\六助新\recon\banners.json","w",encoding="utf-8") as fh:
        json.dump(res, fh, ensure_ascii=False, indent=1)

if __name__ == "__main__":
    main()

```
