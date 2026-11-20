# nginx vhost oracle 枚举（Host 头区分真实虚拟主机，识别同名后端多品牌）

- **code**: nginx-vhost-oracle-枚举-host-头区分真实虚拟主机-识别同名后端多品牌
- **kind**: script
- **category**: recon
- **component**: nginx vhost
- **severity**: info
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-12 在 203.0.113.95 实测 147 个 Host 候选，成功区分出 10 个真实 vhost，并识别出多品牌共用同一后端（762B / 52459B 两份完全一致的响应体）。
- **path**: pocs/nginx-vhost-oracle-枚举-host-头区分真实虚拟主机-识别同名后端多品牌/vhost_oracle_enum.py
- **tags**: nginx,vhost,信息收集,Host头,多品牌
- **created_at**: 2026-10-12T11:52:04.225Z
- **found_by**: vuln-scan

## 描述

当目标把多个业务面板部署在同一 IP 的 nginx 上时，可以用 Host 头枚举真实 vhost：不存在的 server_name 会落到默认 server（在 example 这套环境上是 HTTP 200 且 body 为空），而真实 vhost 会返回非空内容（站点页/302 跳转/nginx 404 页）。据此可以在主域名被封或面板改名后快速定位仍在线的入口，也能识别多品牌共用同一后端的情况。

## 用法

```
python vhost_oracle_enum.py；先用不存在的 Host 校准基线，再枚举候选子域。命中（返回非空）即真实 vhost。适合目标封域名/换域名后重新定位入口。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""nginx vhost oracle 枚举：用 Host 头探测共享同一 IP 的真实虚拟主机"""
import subprocess, re, time
SRC="203.0.113.95"; PROXY="http://127.0.0.1:7892"
def probe(host):
    cmd=["curl.exe","-x",PROXY,"-k","-s","-i","--max-time","12",
         "--connect-to","probe.invalid:443:%s:443"%SRC,"-H","Host: "+host,
         "https://probe.invalid/"]
    r=subprocess.run(cmd,capture_output=True,timeout=30).stdout.decode("utf-8","replace")
    t=r.replace("\r\n","\n"); bs=re.split(r"(?m)^HTTP/1\.1 (\d{3})",t)
    code=bs[-2] if len(bs)>=3 else "?"; body=bs[-1].partition("\n\n")[2].strip() if len(bs)>=3 else t
    return code, len(body), body[:120]
# oracle：不存在的 Host -> 200 且 body 为空；真实 vhost -> 非空（404/200 页面/302）
print("baseline(不存在):", probe("zzz-not-exist-12345.example"))
for w in ["admin","agent","chat","www","api","manage","ht","m","oa"]:
    for d in ["example.com","example.com","example.com"]:
        c,n,s=probe("%s.%s"%(w,d))
        if not (c=="200" and n==0):
            print("REAL  %-28s %s len=%d %s"%("%s.%s"%(w,d),c,n,s.replace("\n"," ")))
        time.sleep(1.3)

```
