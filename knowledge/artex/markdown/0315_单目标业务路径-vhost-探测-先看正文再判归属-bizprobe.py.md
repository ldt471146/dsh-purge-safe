# 单目标业务路径 + vhost 探测（先看正文再判归属）bizprobe.py

- **code**: 单目标业务路径-vhost-探测-先看正文再判归属-bizprobe.py
- **kind**: poc
- **category**: unauthorized
- **component**: 红队侦察基础设施
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 该工具是"业务路径响应指纹法"的单点版实现，本次战役中被反复用来纠正误判：① 印证 `.72:80` 上 `/LHService/` 返 `My JSP 'index.jsp' starting page` + 「六合资料列表页面提交」+ `form action="http://203.0.113.31:8080/LHService/fenleilist"`（内网后端泄露），`/PayBmob/` 返 `<title>在线充值</title>`；② 用它确认 `203.0.113.18`（APK 硬编码后端）六条路径全 404 ⇒ 后端已下线；③ 关键纪律来源：**只看状态码会把 Apache/Tengine/Tomcat 的 404 页里被回显的请求路径 `LHService` 当成命中**，必须看正文内容 —— 本次因此淘汰了 18+ 条假 HIT。
- **path**: pocs/单目标业务路径-vhost-探测-先看正文再判归属-bizprobe.py/bizprobe.py
- **tags**: 业务路径,vhost,正文判读,归属判定,recon
- **created_at**: 2026-10-11T09:41:35.425Z
- **found_by**: recon

## 描述

针对**单台**目标的精细化探测：可同时覆盖多个 Host 头 × 多条业务路径，逐条输出状态码/Server/正文长度/标题/命中签名/正文片段。用于在"某台机到底是不是靶标"这种需要看正文的判断题上做定点核实（比批量 sweep 更细，能拿到正文前 150 字符用于人工判读）。HTTPS 自动按端口走 TLS，原生 socket 不走代理。

## 用法

```
python bizprobe.py "<ip:port>" "[host1,host2,...]" "[path1,path2,...]" [workers=6]
例：python bizprobe.py "203.0.113.18:80" "IP" "/LHService/,/PayBmob/" 4
```

## 正文

```
# -*- coding: utf-8 -*-
"""业务路径 + vhost Host 覆盖探测（原生 socket，不走代理）。
用法: python bizprobe.py <ip:port> [host1,host2,...] [paths]
输出: ip:port@host path -> status/len/title/sigs/snip  (只打印有 LHZS 特征或非404的)
"""
import socket, ssl, os, sys, json, re
from concurrent.futures import ThreadPoolExecutor, as_completed

for k in ("http_proxy","https_proxy","all_proxy","HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"):
    os.environ.pop(k, None)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

UA = "Mozilla/5.0 (Linux; Android 12; lz2025) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36"

DEFAULT_PATHS = ["/PayBmob/", "/UpLoadPic/", "/LHService/", "/Tk_Kj/", "/IMService/",
                 "/LHService/v27/routing/health"]

SIGS = [
    ("在线充值", "在线充值"),
    ("JSP_index", "My JSP 'index.jsp' starting page"),
    ("fenleilist", "LHService/fenleilist"),
    ("LHService", "LHService"),
    ("IMService", "IMService"),
    ("Tk_Kj", "Tk_Kj"),
    ("PayBmob", "PayBmob"),
    ("UpLoadPic", "UpLoadPic"),
    ("六助", "六助"),
    ("lz2025", "lz2025"),
    ("lz2", "lz2"),
    ("appLogin", "appLogin"),
    ("applogin", "applogin"),
    ("jielong", "jielong"),
    ("api/v27", "api/v27"),
    ("v27", "v27"),
    ("springfox", "springfox"),
    ("Whitelabel", "Whitelabel Error"),
]

def raw_http(ip, port, path, host, timeout=6.0, maxbytes=6000):
    https = port in (443, 8443)
    req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
           "Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
           % (path, host, UA))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        if https:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers("DEFAULT@SECLEVEL=1")
            s = ctx.wrap_socket(s, server_hostname=host)
        s.sendall(req.encode())
        buf = b""
        while len(buf) < maxbytes:
            try:
                c = s.recv(4096)
            except socket.timeout:
                break
            if not c:
                break
            buf += c
        head, _, body = buf.partition(b"\r\n\r\n")
        ht = head.decode("utf-8", "replace")
        st = 0
        m = re.match(r"HTTP/\d\.\d (\d+)", ht)
        if m:
            st = int(target22.example.com(1))
        srv = ""
        loc = ""
        for line in ht.split("\r\n"):
            l = line.lower()
            if l.startswith("server:"):
                srv = line.split(":", 1)[1].strip()
            if l.startswith("location:"):
                loc = line.split(":", 1)[1].strip()
        bt = body.decode("utf-8", "replace")
        return {"ok": True, "status": st, "server": srv, "loc": loc, "len": len(body),
                "body": bt, "head": ht[:400]}
    except Exception as e:
        return {"ok": False, "err": "%s: %s" % (type(e).__name__, e)}
    finally:
        try: s.close()
        except Exception: pass

def title_of(b):
    m = re.search(r"<title[^>]*>(.*?)</title>", b, re.I | re.S)
    return re.sub(r"\s+", " ", target22.example.com(1)).strip()[:100] if m else ""

def sigs(t):
    return [n for n, p in SIGS if p in t]

def job(ip, port, host, path):
    r = raw_http(ip, port, path, host)
    return (ip, port, host, path, r)

def main():
    target = sys.argv[1]
    ip, _, port = target.partition(":")
    port = int(port)
    hosts = [h.strip() for h in sys.argv[2].split(",") if h.strip()] if len(sys.argv) > 2 else [ip]
    paths = [p.strip() for p in sys.argv[3].split(",") if p.strip()] if len(sys.argv) > 3 else DEFAULT_PATHS
    workers = int(sys.argv[4]) if len(sys.argv) > 4 else 6

    tasks = [(ip, port, h, p) for h in hosts for p in paths]
    rows = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(job, *t) for t in tasks]
        for f in as_completed(futs):
            rows.append(f.result())
    rows.sort(key=lambda r: (r[2], r[3]))
    interesting = []
    for ip_, port_, host, path, r in rows:
        if not r["ok"]:
            print("[ERR ] %s:%d @%-22s %-32s %s" % (ip_, port_, host, path, r["err"]), flush=True)
            continue
        st, srv, ln = r["status"], r["server"], r["len"]
        sg = sigs(r["body"])
        tl = title_of(r["body"])
        snip = re.sub(r"\s+", " ", r["body"][:150])
        flag = "HIT " if sg else ("--  ")
        print("[%s] %s:%d @%-22s %-32s st=%-4s srv=%-18s len=%-6s title=%r sigs=%s | %s" % (
            flag, ip_, port_, host, path, st, srv, ln, tl, sg, snip), flush=True)
        if sg or (st and st < 400 and ln > 0):
            interesting.append({"host_hdr": host, "path": path, "status": st, "server": srv,
                                "len": ln, "title": tl, "sigs": sg})
    with open(r"C:\Users\user\Desktop\六助新\recon\biz-%s.json" % ip.replace(".", "_"), "w", encoding="utf-8") as fh:
        json.dump(interesting, fh, ensure_ascii=False, indent=1)
    print("\n=== interesting: %d ===" % len(interesting))

if __name__ == "__main__":
    main()

```
