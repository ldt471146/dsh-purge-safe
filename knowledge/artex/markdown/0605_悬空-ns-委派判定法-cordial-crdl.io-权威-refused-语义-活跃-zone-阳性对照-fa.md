# 悬空 NS 委派判定法：Cordial(crdl.io) 权威 REFUSED 语义 + 活跃 zone 阳性对照（fanatical.com 实测定位第二个 dangling NS zone）

- **code**: 悬空-ns-委派判定法-cordial-crdl.io-权威-refused-语义-活跃-zone-阳性对照-fa
- **kind**: poc
- **category**: recon
- **component**: DNS / NS 委派（Cordial crdl.io / Cloudflare 父区）
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 UTC，ARTEX 执行机 dig(dnspython/dig) 实测：parent 1.1.1.1/diva+mario 均委派 email/mailer.fanatical.com→ns1-4.crdl.io；ns1~ns4.crdl.io 对两 zone 的 SOA/NS/A/MX 全 REFUSED；阳性对照 em.abercrombie.com、email.forbes.com（同 NS 委派）在 ns1.crdl.io 回 NOERROR+SOA+NS+MX→证明 REFUSED=zone 不存在而非查询被封；18,548 标签爆破余名零委派。
- **path**: pocs/悬空-ns-委派判定法-cordial-crdl.io-权威-refused-语义-活跃-zone-阳性对照-fa/poc.txt
- **tags**: dns,subdomain-takeover,dangling-ns,cordial,cloudflare,nsec-black-lies,recon
- **created_at**: 2026-11-11T17:21:09.031Z
- **engine**: email.fanatical.com / mailer.fanatical.com

## 描述

子域接管新维度：不只看 CNAME，还要看父区 NS 委派。当子域被 NS 委派给第三方 SaaS 的权威 DNS，而该 SaaS 侧 zone 已被删除/未建时，父区 referral 仍在→悬空 NS 委派，任何能在该 SaaS 重建同名 zone 的租户即取得该子域全部 DNS 控制权（MX/SPF/DKIM/任意记录/TLS DNS-01）。关键判据与陷阱：第三方权威对 zone 查询返回 REFUSED 时，必须用同一 NS 舰队上“确证活跃”的客户 zone 做阳性对照（否则 REFUSED 可能只是该服务器不承载该域/ACL）。Cloudflare 父区（diva/mario）用 NSEC black-lies（不存在名返回 \000.<name> 合成 NSEC）且拒绝 AXFR，故白名单遍历不可行，只能靠被动源+定向标签爆破。

## 正文

```
【适用】目标域用 Cloudflare 托管父区，需系统排查是否存在“父区委派仍在、第三方权威 zone 已消失”的悬空 NS 委派（区别于悬空 CNAME）。
【步骤】
1) 取父区权威：dig +short NS <domain> @1.1.1.1（如 diva/mario.ns.cloudflare.com），确认两台上委派一致。
2) 对候选名逐个查委派：dig NS <name> @diva.ns.cloudflare.com +noall +comments +authority
   - 真委派 = status NOERROR、ANSWER 0、AUTHORITY 含 owner=<name> 的 NS RRset（flags 无 aa，referral）。
   - 普通存在但非委派 = NOERROR + AUTHORITY 只有 SOA；不存在 = NXDOMAIN + SOA。
3) 无清单时补盲：Cloudflare 用 NSEC black-lies（不存在名回 \000.<name> NSEC），AXFR 被拒 → 放弃 NSEC/AXFR，改用被动源(subfinder/CT/OTX/rapiddns)+单标签字典爆破（dnspython 多线程直查权威，RD=0；注意 dns.query.udp(host=...) 不接受主机名，必须传权威 NS 的 IP，否则 ValueError）。
4) 判定第三方 zone 是否已消失：对委派 NS 的每个 IP 查 SOA/NS/A/MX（UDP+TCP）。
   - REFUSED 本身不等于 zone 不存在；必须做阳性对照：在公开情报里找同一 NS 舰队上确证活跃的客户 zone（本例 em.abercrombie.com、email.forbes.com → Cordial），若它们回 NOERROR+SOA 而目标 zone 全 REFUSED → 目标 zone 在 SaaS 侧确已不存在。
   - 递归 1.1.1.1/8.8.8.8 对目标回 SERVFAIL 与死委派一致；NXDOMAIN 则说明委派已清。
5) 历史佐证：OTX passive_dns（https://otx.alienvault.com/api/v1/indicators/hostname/<name>/passive_dns）、mnemonic api.mnemonic.no/pdns/v3/<name>、certspotter/crt.sh。曾 CNAME→SaaS 追踪域、或有旧 A/AAAA 记录 = zone 曾活跃；无任何 CT 证书的纯信件子域也要查 NS 维度（A 记录检查会漏）。
6) 归属与可认领性：NS 后缀→SaaS（crdl.io=Cordial，ns 落在 AWS Route53 anycast）；查该 SaaS 是否自助注册/试用、是否强制域名所有权验证（需账号实测）。
【实测结论（fanatical.com）】仅两处委派：mailer.fanatical.com 与 email.fanatical.com，均 ns1-4.crdl.io；两 zone 全部 REFUSED（无 SOA），阳性对照 abercrombie/forbes 正常 → 两个悬空 NS zone；OTX 显示 mailer 子树 2020 年曾 CNAME cname.cordial.com、2021-2022 有 CF A 记录；email 无 CT/被动 DNS（纯信件子域）。18,548 标签+142 已知名枚举无第三处委派。
【命令速查】
dig NS <name> @diva.ns.cloudflare.com +noall +comments +authority
dig SOA/NS/A/MX <name> @ns1.crdl.io +noall +answer +comments
curl https://otx.alienvault.com/api/v1/indicators/hostname/<name>/passive_dns
【坑】crdl.io 自身不在 ns1-4.crdl.io 上（在 AWS Route53），拿 crdl.io 做对照会误判 REFUSED；必须用其客户 zone。
```
