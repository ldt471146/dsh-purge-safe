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