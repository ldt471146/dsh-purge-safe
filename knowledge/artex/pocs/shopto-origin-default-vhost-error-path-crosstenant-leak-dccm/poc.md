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
