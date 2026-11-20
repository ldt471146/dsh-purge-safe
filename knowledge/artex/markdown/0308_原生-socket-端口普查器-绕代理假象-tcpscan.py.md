# 原生 socket 端口普查器（绕代理假象）tcpscan.py

- **code**: 原生-socket-端口普查器-绕代理假象-tcpscan.py
- **kind**: poc
- **category**: recon
- **component**: 红队侦察基础设施
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在靶标「example-com-6hzs6-com-lz2-apk-app-后端」上实测验证：用它对 203.0.113.6/24 全 254 地址铺 7 端口（1778 次探测，283.8s），得 **42 台存活 / 92 端口** —— 而此前用 curl 得到的结论是"整段不可达"（库里当时只有 2 条资产、0 live）。同法扫 203.0.113.54/24（146 端口/65+台）、203.0.113.17/24（386 端口）、203.0.113.66/24（337 端口）、203.0.113.39/24（207 端口）。对照验证：同段 `203.0.113.12` 原生 socket 通、`203.0.113.17` 不通 ⇒ 证明是"目标侧选择性访问控制"而非整段死。
- **path**: pocs/原生-socket-端口普查器-绕代理假象-tcpscan.py/tcpscan.py
- **tags**: 扫端口,原生socket,代理绕过,段普查,recon
- **created_at**: 2026-10-11T09:41:10.481Z
- **found_by**: recon

## 描述

纯 socket 的 CIDR/IP 端口扫描器，进程内**硬清 http_proxy/https_proxy/all_proxy/HTTP_PROXY/HTTPS_PROXY/ALL_PROXY**，因此不受本机代理注入影响（curl/Go 工具会读这些变量走 127.0.0.1:17992 代理，产生"超时/不可达/403"假象；本次战役已多次因此误判）。支持 CIDR 或逗号分隔 IP，可调并发与超时，最后输出 open 列表 + JSON 摘要。

## 用法

```
python tcpscan.py <cidr|ip,ip,...> <ports 逗号分隔> [workers=12] [timeout秒=2.0]
例：python tcpscan.py "203.0.113.6/24" "80,443,8080,8443,8888,22,3306" 12 2.0
```

## 正文

```
# -*- coding: utf-8 -*-
"""原生 socket 端口扫描器 —— 绝不走代理环境变量。
用法: python tcpscan.py <cidr_prefix|ip,ip> <ports> [workers] [timeout]
"""
import socket, sys, json, time, ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

# 硬清代理环境变量（socket 本身不用，但避免任何库偷读）
import os
for k in ("http_proxy","https_proxy","all_proxy","HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","no_proxy","NO_PROXY"):
    os.environ.pop(k, None)

def probe(ip, port, timeout=2.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        try:
            s.settimeout(1.2)
            s.sendall(b"")
        except Exception:
            pass
        return (ip, port, True, None)
    except socket.timeout:
        return (ip, port, False, "timeout")
    except ConnectionRefusedError:
        return (ip, port, False, "refused")
    except OSError as e:
        return (ip, port, False, type(e).__name__)
    finally:
        try: s.close()
        except Exception: pass

def main():
    target = sys.argv[1]
    ports = [int(p) for p in sys.argv[2].split(",")]
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else 12
    timeout = float(sys.argv[4]) if len(sys.argv) > 4 else 2.5

    if "/" in target:
        net = ipaddress.ip_network(target, strict=False)
        ips = [str(x) for x in net.hosts()]
    else:
        ips = [x.strip() for x in target.split(",") if x.strip()]

    tasks = [(ip, p) for ip in ips for p in ports]
    hits, misses = [], []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(probe, ip, p, timeout): (ip, p) for ip, p in tasks}
        for f in as_completed(futs):
            ip, p, ok, err = f.result()
            if ok:
                hits.append({"ip": ip, "port": p})
                print("[OPEN] %s:%d" % (ip, p), flush=True)
            else:
                misses.append({"ip": ip, "port": p, "err": err})
    hits.sort(key=lambda x: (x["ip"], x["port"]))
    print("\n=== RESULT ===")
    print(json.dumps({"target": target, "ports": ports, "open": hits,
                      "open_count": len(hits), "probed": len(tasks),
                      "elapsed": round(time.time()-t0, 1)}, ensure_ascii=False, indent=1))

if __name__ == "__main__":
    main()

```
