# greenmangaming.com + gmgfarm.com 全量悬空 CNAME 清单（10 子域 / 9 目标，全部厂商生成名不可认领，唯一 SoloCDN 未验证）

- **code**: greenmangaming.com-gmgfarm.com-全量悬空-cname-清单-10-子域-9-目标
- **kind**: poc
- **category**: recon
- **component**: DNS / 子域接管（AWS ELB / AWS API Gateway / F5 Distributed Cloud / SoloCDN）
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 18:00-18:10 UTC，ARTEX 执行机 Windows/Git Bash 实测：1813 个已知子域（#1848/#531/#190/#1755 清单 + crt.sh 1506 + subfinder 1376 合并去重）经 dnsx -cname -resp 得 45 条 CNAME / 31 个唯一目标；dnsx -a + comm -23 得 9 个未解析目标，逐条用 nslookup 8.8.8.8/1.1.1.1（部分 9.9.9.9）复核 NXDOMAIN 一致；10 个悬挂子域 curl HTTPS 全 000（代理 http 502）。grep 31 个目标无任何 s3/heroku/github/azure/netlify/vercel/shopify/statuspage/freshdesk 类可认领名（唯一命中为 cloudfront 随机串内含 s3 的误报）。whois/Verisign：lxcvc.com 注册 2011-06-20、到期 2027-06-20、NS=com1/2/3.solocdn.cn，SOA 应答、无泛解析 → 无域名过期路径，仅剩 SoloCDN 账号重建加速域一条未验证路径。96 个唯一 NS 目标全部解析（无悬空 NS 委派）。
- **path**: pocs/greenmangaming.com-gmgfarm.com-全量悬空-cname-清单-10-子域-9-目标/poc.md
- **tags**: subdomain-takeover,dangling-cname,dns,nxdomain,dnsx,greenmangaming,gmgfarm,negative,aws-elb,aws-api-gateway,f5-xc,solocdn
- **created_at**: 2026-11-11T18:09:38.747Z
- **engine**: greenmangaming.com / gmgfarm.com

## 描述

负面情报 + 清单基线：greenmangaming.com 与 gmgfarm.com 当前全部悬空 CNAME 已枚举并按厂商可认领性分类，除 SoloCDN(api-cn) 需第三方账号未验证外，其余全部为 AWS/Google/F5 生成名不可复刻。后续任务不必重复枚举这批名字，除非出现新的证书/被动 DNS 源或拿到 SoloCDN 账号。

## 用法

```
直接复用本清单作为“已排查”基线：\n1) 复核命令：dnsx -l subs.txt -cname -resp -silent -r 8.8.8.8,1.1.1.1；awk -F'[][]' '{print $4}' | sed 's/\\.$//' | sort -u 得目标；dnsx -l targets.txt -a -resp -silent；comm -23 比出 NXDOMAIN 目标。\n2) 新增子域时只需对新名字重跑上述流水线，对照本清单 diff。\n3) 唯一可继续投入的方向：若获得 SoloCDN 账号，尝试把 api-cn.greenmangaming.com 添加为加速域，观察 api-cn.greenmangaming.com.lxcvc.com 是否重建同名 CNAME；若 SoloCDN 强制域名归属校验则此路彻底关闭。\n4) 同一目标域下其它待挖向：dev.gmgfarm.com 的 A 记录 173.203.109.39（Rackspace 已释放 IP，IP 复用型候选）。
```

## 正文

```
# greenmangaming.com + gmgfarm.com 悬空 CNAME 全量清单（2026-11-11 18:00 UTC）

数据源：1813 个已知子域（#1848/#531/#190/#1755 清单 + crt.sh 1506 + subfinder 1376 合并去重），无泛解析。45 条 CNAME / 31 个唯一目标。

## 悬挂子域（CNAME 目标 NXDOMAIN，子域 HTTP 000）

| 子域 | CNAME 目标 | 厂商 | 可认领性 |
|---|---|---|---|
| api-cn.greenmangaming.com | api-cn.greenmangaming.com.lxcvc.com | SoloCDN | 理论可控：需 SoloCDN 账号添加同名加速域；lxcvc.com 注册至 2027-06-20（NS=solocdn.cn）→ 无域名过期路径。未验证 |
| email-prod.greenmangaming.com | d-gagbjg3yxc.execute-api.us-east-1.amazonaws.com | AWS API Gateway | 不可认领（d- 随机名） |
| email-staging.greenmangaming.com | d-ez8ebkwgof.execute-api.us-east-1.amazonaws.com | AWS API Gateway | 不可认领 |
| secure.greenmangaming.com | secure-022014-1254520137.us-east-1.elb.amazonaws.com | AWS ELB | 不可认领（Not vulnerable） |
| team17.greenmangaming.com | soupkitchenwebfe-2018403816.us-east-1.elb.amazonaws.com | AWS ELB | 不可认领 |
| neom.greenmangaming.com / neo.greenmangaming.com | neofrontal-1025432939.us-east-1.elb.amazonaws.com | AWS ELB | 不可认领（neo 为本轮新增，与 neom 同目标） |
| new.greenmangaming.com | staging-1-heimdall-584160956.us-east-1.elb.amazonaws.com | AWS ELB | 不可认领（本轮新增，此前未登记） |
| talos.tooling.greenmangaming.com | talos-lb-lb-4d0dc8b-1053706526.us-east-1.elb.amazonaws.com | AWS ELB | 不可认领 |
| machine-f5.ddp.greenmangaming.com | ves-io-388e0a56-3387-4781-93ee-15f189b96c5b.ac.vh.ves.io | F5 XC | 不可认领（UUID 生成名） |

## 其它判定
- 31 个 CNAME 目标中不存在 S3/Heroku/GitHub Pages/Azure/Netlify/Vercel/Shopify/Statuspage/Freshdesk 类可认领名（grep 唯一命中 d3qrs3l040t5wi.cloudfront.net 为随机串内含 "s3" 的误报）。
- 35 个 CNAME 子域解析成功且均为 GMG 自用或供应商正常服务：Fastly、AWS ELB（staging-1/admin.tooling/pricing.tooling）、CloudFront（blog/freegame/goldenjoysticks/www.corporate/images-nocdn/workerlog/hosted.gmgfarm，distro 均存活，301 或 S3 AccessDenied 默认页）、SendGrid、ThreatMetrix、Pingdom、Emarsys、Looker、Google(ghs)、GCP、AWS EC2（www.gmgfarm）。
- 96 个唯一 NS 目标（awsdns / googledomains）全部解析，无悬空 NS 子区委派（44 个委派子区）。
- gmgfarm.com：82 个已知名仅 2 条 CNAME（hosted→CloudFront 存活、mail.i→ghs.google.com 存活）；dev.gmgfarm.com A=173.203.109.39（Rackspace 静态 IP，HTTP 000/TCP80 closed，IP 复用型候选，见 #1783）。

## 限制
无被动 DNS 历史源，结论仅覆盖当前仍存在的 CNAME；历史已删除的 S3/Heroku 类记录无法从本轮发现。
```
