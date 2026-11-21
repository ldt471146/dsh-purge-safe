# GCP HTTP(S) LB → nginx 的「CL.TE 走私」多为误判：前端 TE 优先，尾随字节是管线请求（判据：尾随 POST 无 CL 返回 GFE 自带 411 页）

- **code**: gcp-http-s-lb-nginx-的-cl.te-走私-多为误判-前端-te-优先-尾随字节是管线请求-判据
- **kind**: payload
- **category**: protocol
- **component**: Google Cloud HTTP(S) Load Balancer + nginx origin
- **severity**: low
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-04 本机 Windows + python313 原生 SSL socket（ALPN http/1.1）直连两台 GCP LB：外层 POST + Content-Length + Transfer-Encoding: chunked，body 写 "0\r\n\r\n"+内嵌请求 → 稳定回 ['502','206']（第二段真实 plist 字节），看似 CL.TE。决定性判据：把内嵌请求换成不带 Content-Length 的 POST，第二段返回 HTTP/1.0 411 且正文为 Google 错误页固定串 "POST requests require a <code>Content-length</code> header."（286B，与直连 GFE 的无 body POST 411 页逐字一致），不是源站 nginx 模板 → 尾随请求由前端解析。另做跨连接投毒自测（A 发走私只读第一段，B 新连接正常 GET）→ B 收到自己的缓存对象（Age 4028），未被串包。所有方法/路径/vhost 绕过均无增益。finding 1234 报告已按此复核为不可利用/疑误报。
- **path**: pocs/gcp-http-s-lb-nginx-的-cl.te-走私-多为误判-前端-te-优先-尾随字节是管线请求-判据/poc.txt
- **created_at**: 2026-11-04T13:50:45.583Z
- **engine**: 34.49.31.132:443 / 136.110.243.85:443 (SNI down.i663r4.com / e9sj.vz4wu8.com)

## 描述

适用条件：目标前置 GCP 外部 HTTP(S) LB（GFE），后端回源到 nginx，观察到「一个 POST 回两段响应（首段 502 + 次段 200/206）」被初判为 CL.TE。判据：GFE 按 RFC 7230 §3.3.3 在同时出现 TE 与 CL 时选择 TE，0-chunk 结束 body，后续字节成为同一客户端连接上的下一条流水线请求（由前端解析并受前端校验），不是源站解出的走私请求。因此不会获得绕过边缘 Host/路径/WAF 的能力，也不会造成跨用户响应队列投毒；仅在源站对非 GET/HEAD 断连时首段显示 502。

## 用法

```
判别脚本要点（低噪声、只读）：1) 发外层 POST：CL=len(body)、TE: chunked、body="0\r\n\r\n"+tail；2) tail 用「POST 且不带 Content-Length」：若第二段为前端自有 411 页（HTTP/1.0 + "POST requests require a Content-length header."）→ 尾随由前端解析，CL.TE 不成立；若第二段为源站模板（server: Microsoft-IIS / nginx 模板、HTTP/1.1）→ 再考虑真走私；3) 跨连接投毒自测：连接 A 发走私后只读首段并保持，另开连接 B 正常 GET 同资源，若 B 收到 A 的走私响应才是共享后端队列；否则多余响应绑定攻击者自身连接。阴性即可结束，别继续堆 payload。
```

## 正文

```
# 结论
「GCP LB → nginx」上看到的 CL.TE 现象，绝大多数是前端 TE 优先 + HTTP/1.1 流水线，不是请求走私。

# 证据（task#614, 2026-11-04）
- 复现：外层 POST /IOSDownload_2/ios.plist Host: down.i663r4.com + CL + TE: chunked，body = "0\r\n\r\n" + 内嵌 GET → 502 + 206（真实 plist）。两 IP（34.49.31.132 / 136.110.243.85）均复现。
- 决定性：内嵌 POST 不带 CL → 第二段为 HTTP/1.0 411，正文 "POST requests require a <code>Content-length</code> header."（GFE 模板，286B），说明尾随请求由前端解析。
- 方法/路径/vhost：走私 POST/PUT → 502（源站断连，无写入）；/.env → 502、/web.config → 404（与直连一致）；Host: mpadmin + /apk/<精确文件名> → 206（直连也 206）。
- 队列：A 连接发走私、B 连接独立 GET → B 收到自己的缓存对象（ETag 6a544a0f-510, Age 4028），无串包。

# 判据速查
1. tail = POST 无 CL：得前端 411 页 → 前端解析，假走私。
2. tail = 源站模板错误（Microsoft-IIS / nginx 模板、HTTP/1.1）→ 才可能是真走私。
3. 跨连接投毒必须用两条自有连接验证；只看到自己连接上的第二段响应不算投毒。

# 启发
GCP GFE 对 TE+CL 共存按 RFC 处理（TE 优先）且做请求规范化；当首请求被源站断连（非 GET/HEAD → 502）时，同连接后续流水线请求仍会被处理，容易被误读成「源站执行了夹带请求」。

```
