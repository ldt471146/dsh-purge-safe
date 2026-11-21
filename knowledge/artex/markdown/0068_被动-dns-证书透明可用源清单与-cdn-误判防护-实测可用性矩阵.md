# 被动 DNS / 证书透明可用源清单与 CDN 误判防护（实测可用性矩阵）

- **code**: 被动-dns-证书透明可用源清单与-cdn-误判防护-实测可用性矩阵
- **kind**: template
- **category**: recon
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 pockgo-com 靶标实测：crt.sh 补全 9 个品牌域 93 个子域名；hostsearch 拿到 85 条 子域→IP 映射并识别出 203.0.113.122 / 203.0.113.127 / 203.0.113.5 等新 IP；rapiddns sameip 反查把 203.0.113.5 定性为阿里云 Kunlun CDN 边缘、把 203.0.113.122/203.0.113.127 定性为共享托管（各含 100 个无关站点）；OTX / mnemonic / rapiddns-subdomain / viewdns 四个源在本出口不可用或假零命中。
- **path**: pocs/被动-dns-证书透明可用源清单与-cdn-误判防护-实测可用性矩阵/passive-dns-source-matrix.md
- **tags**: 被动DNS,证书透明,源站,CDN误判防护,信息收集
- **created_at**: 2026-09-28T15:43:22.244Z

## 描述

记录在数据中心出口下，哪些免费被动 DNS/CT 源真的可用、哪些返回"假零命中"，以及如何用同 IP 反查区分 CDN 边缘/共享托管与真实源站，避免把 CDN/共享 IP 误报成源站。

## 用法

```
子域补全优先顺序：crt.sh → certspotter → hostsearch（顺带拿 IP）→ getent 实时核对。
源站历史：本轮 OTX/viewdns/mnemonic 全部不可用，因此"DNS 历史找源站"在这套出口下不可靠；
真正有效的是 hostsearch 的当前映射 + rapiddns 同 IP 反查 + PTR 定性。
每条结论都要按"误判防护"小节自检，标注该 IP 是 CDN 边缘 / 共享托管 / 公有云实例 / 疑似独服。
```

## 正文

```
目标：为"找 CF 背后的历史源站"和"补全子域"挑选当前真正可用的免费被动源。
2026-09 实测结论（出口：数据中心 VPS，IPv6/IPv4 均可出网）：

【可用】
1) crt.sh —— 证书透明，拿全量子域最可靠，匿名无鉴权：
   curl -s 'https://crt.sh/?q=%25.<domain>&output=json' | jq -r '.[].name_value' | sort -u
   局限：只给域名，不给 IP。
2) api.certspotter.com —— 证书透明，含 wildcard 与带通配的子域，匿名可用（有限速）：
   curl -s 'https://api.certspotter.com/v1/issuances?domain=<d>&include_subdomains=true&expand=dns_names'
3) api.hackertarget.com/hostsearch —— 一次拿"子域→当前 IP"全映射，匿名可用，是本轮最高性价比入口：
   curl -s 'https://api.hackertarget.com/hostsearch/?q=<domain>'
4) getent ahostsv4 / dig —— 实时解析（用于和上面的历史值对比，识别漂移）。
5) rapiddns.io/sameip/<ip>?full=1 —— 同 IP 反查其它站点，用于判断某 IP 是"独服"还是"CDN/共享托管"。

【不可用 / 需付费 / 需登录（都试过）】
- otx.alienvault.com/api/v1/indicators/domain/<d>/passive_dns —— 连接失败，pDNS 历史拿不到。
- api.mnemonic.no/pdns/v3/<d> —— 返回 0 记录（但返回 200，会误导成"没有历史"）。
- rapiddns.io/subdomain/<d>?full=1 —— 返回 200 但解析不出行，不可依赖。
- viewdns.info/iphistory —— 抓取失败（需要人机/JS）。
- grep.app/api/search、searchcode API —— 见"公开代码托管"条目，均不可脚本化。
- whois 反查 IP 归属（hackertarget whois）—— 需要 API key。

【误判防护（重要）】
把"IP 是共享托管/CDN"当成"运营方源站"是本方向最容易犯的错。判据：
- 同 IP 反查出的 hostname 里出现 `.w.kunlunXX.com` / `.w.alikunlun.com` / `.w.cdngslb.com` 后缀
  ⇒ 该 IP 是阿里云 CDN 边缘节点，不是源站。
- 同一 IP 反查出**上百个彼此无关的站点**（不同行业、不同语种）⇒ 共享托管，不能据此认定是目标的机器。
- PTR 为 ec2-*.compute.amazonaws.com / 云厂商默认 PTR ⇒ 只说明是公有云实例。
- 域名解析出的一批 IP 与 PTR 不匹配，且该域是静态资源域 ⇒ 大概率前置 CDN。

```
