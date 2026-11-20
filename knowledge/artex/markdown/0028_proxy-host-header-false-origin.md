# 方法论陷阱：本地 HTTP 代理会按 Host 分流，制造"Host 头命中源站"的假象（必须无代理复核）

- **code**: proxy-host-header-false-origin
- **kind**: script
- **category**: recon
- **component**: 探测方法论 / HTTP 代理
- **severity**: info
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 实测复现：经 127.0.0.1:7892 代理对 5 台 IP:8080 带 Host: target10.example.com → 5/5 返回 200/9132 登录页（响应头含 cf-ray/Server: cloudflare）；同 IP 同 Host 在 VPS 无代理直连 → 全部 404，且 4 种 Host 响应字节完全一致（87 字节）→ 证明前者是代理按 Host 分流所致。据此撤回了一条"源站定位成功"的错误结论（vuln 38 已更正）。
- **path**: pocs/proxy-host-header-false-origin/poc.sh
- **tags**: 方法论,源站定位,Host头,代理陷阱,Cloudflare,对照实验
- **created_at**: 2026-09-28T07:32:59.257Z
- **found_by**: exploit

## 描述

用本地 HTTP 代理做 Host 头 vhost 探测的陷阱：代理会按 Host/域名分流到真实域名（Cloudflare），制造"命中源站"的假象。含无代理复核脚本与判定规则（看 cf-ray/alt-svc 头、多 Host 响应比对）。

## 用法

```
任何"用 Host 头找 CF 源站"的动作前后都读一遍；复核命令见正文第 4 条（curl --noproxy '*' 或在 VPS 上直连）。
```

## 正文

```
# 方法论陷阱：用本地 HTTP 代理做 Host 头 vhost 探测会造出"命中源站"的假象

## 现象（我踩了这个坑，并把错误结论写进了报告）
目标：找一个 Cloudflare 后面的站点的真实源站。
做法：对候选 IP 发 `GET http://<IP>:8080/login` 并带 `Host: <被 CF 代理的域名>`，
      期望返回该域名的页面（= 命中源站 vhost）。
      **经本机 HTTP 代理（127.0.0.1:7892，Clash/V2Ray 类）执行时 → 5/5 台都返回 200 + 该域名的登录页**
      → 我据此判定"源站定位成功"。

## 真相
该代理**按 Host 头/域名做 DNS 解析与分流**，直接把请求送到了**真实域名（经 Cloudflare）**，
目标 IP 被完全忽略。铁证是响应头：
```
Server: cloudflare
Cf-Cache-Status: DYNAMIC
Cf-Ray: a4210cf089b6b486-SIN
Alt-Svc: h3=":443"; ma=86400
```
这些头只可能来自 Cloudflare 边缘 —— 一个直连的阿里云 IP:8080 不可能返回它们。

## 无代理复核（决定性对照）
在 VPS 上用 `http.client` 直连（不经任何代理），对同样 5 台 IP 各试 4 个 Host：
```
Host=(默认) / adminapi.<domain> / app.<domain> / admin.<domain>
  /       -> 四种 Host 全部返回**完全相同**的响应（87 字节 JSON）
  /login  -> 一律 404
```
→ 这些实例忽略 Host、不承载目标 vhost，**根本不是源站**。

## 判定规则（务必遵守）
1. **任何 vhost / 源站判定，必须用"无代理直连"复核一次**；带 Host 头的探测尤其危险。
2. 看响应头做交叉验证：若出现 `cf-ray` / `cf-cache-status` / `server: cloudflare` / `alt-svc: h3`，
   说明你很可能打到了 Cloudflare 边缘而不是源站。
3. 对照组要包含"**不同 Host 是否产生不同响应**"——若多个 Host 响应字节完全一致，
   说明目标忽略 Host（或你根本没打到 vhost 分层的网关）。
4. curl 复现（确保不走系统/环境代理）：
   `curl --noproxy '*' -H 'Host: target.example.com' http://SOURCE_IP:8080/login -D -`
   或直接在跳板机（VPS）上跑，避免本机代理规则干扰。

```
