# TLS 证书抓取 + 从 DER 提 CN/SAN（证书归属判定）certgrab.py

- **code**: tls-证书抓取-从-der-提-cn-san-证书归属判定-certgrab.py
- **kind**: poc
- **category**: info-leak
- **component**: TLS / 证书透明
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 靶标上实测，产出本次最硬的一条归属证据：`203.0.113.12:443` 证书 CN=**example.com**（节点清单里的"隐藏网关"域名），`203.0.113.13:443`/`.64:443` 证书 CN=**example.com** —— 把"域名↔IP"用密码学方式绑定。同时一次性把段内无关租户识别出来（.133=pay.qingfu.tech、.179=ourhost.com、.85=*.niaoyun.com、.172=5gbd.jishidaili.com、.204=czssrmyy.com、.223=www.baopiji.com、.120=yinlingjiaoyu.com、.180=push.ydkj2.com、.199=a.ydwl6.com、.215=hanazewa.com、.212=server-150-242-58-151.da.direct、.224=CDN.Server），据此写了 24 条"非靶标→排除"判定。
- **path**: pocs/tls-证书抓取-从-der-提-cn-san-证书归属判定-certgrab.py/certgrab.py
- **tags**: 证书,归属判定,SAN,DER,无代理,tls
- **created_at**: 2026-10-11T09:41:10.647Z
- **found_by**: recon

## 描述

对一组 ip:port 做 TLS 握手，取对端证书并**解析出 CN 与 SAN**。关键技巧：`ssl` 在 `verify_mode=CERT_NONE` 时 `getpeercert()` **返回空 dict** —— 本脚本改为 `getpeercert(binary_form=True)` 拿 DER，再用正则 `[!-~]{4,120}` 从 DER 里提可打印串并过滤出含 `.` 的域名（CN/SAN/OCSP/CRL URL 都能读出来）。证书里的域名是**比业务路径更硬的归属证据**，能把"某 IP 是谁的"直接钉死。原生 socket，不走代理。

## 用法

```
python certgrab.py "ip:port,ip:port,..."
例：python certgrab.py "203.0.113.12:443,203.0.113.13:443"
```

## 正文

```
# -*- coding: utf-8 -*-
"""TLS 证书抓取：CN + SAN 列表（原生 socket，不走代理）。用法: python certgrab.py "ip:port,..." """
import socket, ssl, os, sys, json, re
from concurrent.futures import ThreadPoolExecutor, as_completed

for k in ("http_proxy","https_proxy","all_proxy","HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"):
    os.environ.pop(k, None)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

def get_cert(ip, port, timeout=8.0, sni=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")
    except Exception:
        pass
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        ss = ctx.wrap_socket(s, server_hostname=sni or ip)
        der = ss.getpeercert(binary_form=True)
        cert = None
        try:
            cert = ss.getpeercert()
        except Exception:
            cert = None
        ver = ss.version()
        cipher = ss.cipher()
        ss.close()
        out = {"ok": True, "tls": ver, "cipher": (cipher or [None])[0]}
        if cert:
            subj = {k: v for t in cert.get("subject", ()) for k, v in t}
            iss = {k: v for t in cert.get("issuer", ()) for k, v in t}
            out["subject"] = subj
            out["issuer"] = iss
            out["notAfter"] = cert.get("notAfter")
            san = []
            for t in cert.get("subjectAltName", ()):
                san.append("%s:%s" % t)
            out["SAN"] = san
        else:
            out["note"] = "getpeercert() empty (verify_mode=CERT_NONE); parsing DER strings"
            out["der_len"] = len(der or b"")
            # 从 DER 里提可打印串（CN/SAN/issuer 都是明文 ASCII/UTF8）
            strs = re.findall(rb"[!-~]{4,120}", der or b"")
            names = []
            for s in strs:
                t = s.decode("latin-1")
                if "." in t and " " not in t and not t.startswith("http"):
                    names.append(t)
                elif t in ("CN", "O", "OU", "C", "ST", "L"):
                    continue
            # 去重保序
            seen, uniq = set(), []
            for n in names:
                if n not in seen:
                    seen.add(n); uniq.append(n)
            out["DER_names"] = uniq[:40]
        return out
    except Exception as e:
        return {"ok": False, "err": "%s: %s" % (type(e).__name__, e)}
    finally:
        try: s.close()
        except Exception: pass

def main():
    targets = [t.strip() for t in sys.argv[1].split(",") if t.strip()]
    res = {}
    jobs = []
    for t in targets:
        h, _, p = t.partition(":")
        jobs.append((h, int(p)))
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = {ex.submit(get_cert, h, p): (h, p) for h, p in jobs}
        for f in as_completed(futs):
            h, p = futs[f]
            out = f.result()
            res["%s:%s" % (h, p)] = out
            if out.get("ok"):
                cn = out.get("subject", {}).get("commonName", "") or "(n/a)"
                names = out.get("SAN") or out.get("DER_names") or "(none)"
                print("%-22s TLS=%-10s CN=%-40s NAMES=%s" % (
                    "%s:%d" % (h, p), out.get("tls"), cn, names), flush=True)
            else:
                print("%-22s ERR %s" % ("%s:%d" % (h, p), out.get("err")), flush=True)
    with open(r"C:\Users\user\Desktop\六助新\recon\certs.json","w",encoding="utf-8") as fh:
        json.dump(res, fh, ensure_ascii=False, indent=1)

if __name__ == "__main__":
    main()

```
