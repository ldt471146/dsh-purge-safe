# Apache 直连 Web 的 CL/TE 解析一致性阴性判据（CL+TE 被接受但禁连接复用、双 CL/TE 混淆/CL 归一化一律 400、h2c 不可用）

- **code**: apache-direct-clte-parse-consistency-negative
- **kind**: payload
- **category**: protocol
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-12 01:34~01:41 UTC，本机 Linux 原始 socket(ssl, ALPN=http/1.1, SNI/Host=webmail.goffsgames.co.uk) 直连 88.208.224.249，并用 openssl s_client(-alpn http/1.1) 双工具复核：CL:6+TE:chunked 恒 404/271B body（非 400）；CL:6+CL:7、TE:chunked,identity、TE 头名后空格、重复 TE 头、CL:+6/06 双头 恒 400/284B body；keep-alive 外层 POST(CL+TE)+夹带 GET+收尾 GET 仅 1×404 后连接被 Apache 主动关闭（夹带零响应），阳性对照同连接 3×GET=200/404/404；80 端口 h2c preface=400、Upgrade:h2c=200 无 101。原始字节落 /opt/artex/data/tasks/11/i3460/raw/。
- **path**: pocs/apache-direct-clte-parse-consistency-negative/poc.http
- **tags**: request-smuggling,cl.te,te.cl,apache,h2c,raw-socket,negative
- **created_at**: 2026-11-12T01:39:44.175Z
- **engine**: https://webmail.goffsgames.co.uk（88.208.224.249:443/80，Apache + PHP-FPM）
- **found_by**: vuln-scan

## 用法

```
原样报文（python 原始 socket / openssl s_client 均可，跑前清空 *_proxy，ALPN 显式 http/1.1）：
1) CL+TE：`POST /<随机404路径> HTTP/1.1\r\nHost: <目标域名>\r\nConnection: close\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n` → 期望 404（非 400）且响应后断连；
2) 夹带判定：外层同上但 `Connection: keep-alive`，body = `0\r\n\r\n` + `GET /<另一随机404路径> HTTP/1.1\r\nHost: <目标域名>\r\nConnection: keep-alive\r\n\r\n` → 期望只 1 条 404 + 连接 closed；
3) 阳性对照：同连接连发 3 条普通 GET → 必须 3 条响应，否则方法失效。
```

## 正文

```
# 适用：Apache 直连（无前置代理/CDN）的 Web 端点做 CL/TE 解析一致性/请求走私判定

## 两个关键行为（与 nginx/openresty 不同，别按 kb#441 的「CL+TE→400」直接套）
1. **CL + TE:chunked 并存 → Apache 不拒绝**：按 TE 收体、正常处理请求，然后**禁用连接复用**（响应后主动关连接）。
   - 实测：POST + `Content-Length: 6` + `Transfer-Encoding: chunked` + body 仅 5B `0\r\n\r\n` → 立即 404（若按 CL=6 会挂起等第 6 字节，故证明按 TE 解析）。
   - keep-alive 下同一请求只回 1 条响应后连接即被关（read 终止原因 = closed），夹带在 0-chunk 之后的请求字节被丢弃、不解析。
2. **其余歧义形态一律 400**：双 CL（不同值）、`TE: chunked,identity`、TE 头名后空格（`Transfer-Encoding : chunked`）、重复 TE 头（chunked+identity）、CL 归一化（`+6` 与 `06` 双头）→ 全部 400/284B body（页脚 `<address>Apache Server at default Port 443</address>`，注意 400 页用默认 ServerName）。

## 阴性判据（三条同时成立即封口）
- 所有变体状态码 ∈ {400, 404}，无 200 异常；
- 单连接夹带场景 `响应条数 = 1` 且连接 why=closed，收尾请求 send 成功但 0 字节回包 → 夹带未执行；
- **必须有阳性对照**：同连接 3 条普通 GET（keep-alive/keep-alive/close）应得 200/404/404 三条响应，否则「只有 1 条响应」是测试方法失效而非目标硬化。

## h2c
- `:80` prior-knowledge preface（`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` + 空 SETTINGS 帧）→ 400 纯文本，无任何二进制帧 → 无明文 h2。
- `Upgrade: h2c` + HTTP2-Settings → 200 标准 h1 页、无 101 → 不升级。

## 结论口径
Apache 直连场景「接受 CL+TE 但禁复用」本身安全（无前端-后端解析分叉）；但若同一 vhost 日后被接入 CDN/nginx/负载均衡前置，该差异（前端可能 400 或按 CL、后端按 TE）就是 CL.TE 走私的成立条件，应作为新入口重测。
```
