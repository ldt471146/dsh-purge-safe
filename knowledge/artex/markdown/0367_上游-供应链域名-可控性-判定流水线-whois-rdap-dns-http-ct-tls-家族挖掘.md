# 上游/供应链域名「可控性」判定流水线（whois+RDAP+DNS+HTTP+CT+TLS+家族挖掘）

- **code**: 上游-供应链域名-可控性-判定流水线-whois-rdap-dns-http-ct-tls-家族挖掘
- **kind**: script
- **category**: recon
- **component**: 通用 · 供应链域名接管面判定
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-12 在靶标 example-com 上实测有效：正确判出 16 个候选域**全部不可控**，并给出关键反证——example.com 实测 HTTP 200/1389B 返回实时真实开奖 JSON（{"issue":"20261012058","opendate":"2026-10-12 23:30:00","code":"9,9,1,8,8"}），TLS 证书 2026-09-24 刚签发（notAfter 2026-12-23）；lkag3.com RDAP 到期 2027-01-08 且状态为 client*Prohibited（非 pendingDelete）。无需认证即可复现（纯公开数据源）。踩坑记录：① `ls | Select-String` 式的 whois 默认 referral 对 .click/.pro/.kim 会返回 "Tld not supported"，必须指定 whois.namecheap.com / whois.aflicias / RDAP；② `rdap.org` 直连在部分出口不可达，改用数据源端直连（rdap.verisign.com / rdap.radix.host / rdap.identitydigital.services）稳；③ .space 注册局 whois 易 rate limit，改用 https://rdap.radix.host/rdap/domain/&lt;d&gt;；④ .vip 的 RDAP 端点因注册局而异，优先用注册商 whois（Gname 的默认 whois 就够）；⑤ TLS 证书 CN 常与域名不一致（example.com 的证书是 CN=*.0ogkt.com）——那恰恰暴露了真源站域名，务必记下来查。
- **path**: pocs/上游-供应链域名-可控性-判定流水线-whois-rdap-dns-http-ct-tls-家族挖掘/upstream-domain-takeover-check.sh
- **tags**: 供应链,域名接管,whois,rdap,ct,recon
- **created_at**: 2026-10-12T15:47:02.453Z
- **found_by**: recon

## 描述

判定一批第三方/上游域名是否处于"无人有效控制"状态（过期未续 / 待释放 / parked / 待售），从而判断能否通过"控制上游 = 目标主动来请求我们"绕开目标自身防御。核心判据：whois/RDAP 到期日与域名状态（pendingDelete / redemptionPeriod / clientHold 才是机会）+ DNS 是否仍解析 + HTTP 是否活业务或 parked 页 + CT/TLS 最后一次签发时间（最准的"还活着吗"证据）。含家族挖掘（CT common_name 轮换 / NS 归并 / 注册时间戳批量比对），因为单域不可控 ≠ 家族不可控。纪律：全程只读，不注册、不询价、不联系持有者。

## 用法

```
bash upstream_probe.sh（改 DOMAINS 变量）；配套 probe2/3/4/5/6 分别做：显式注册局 whois + 单次 HTTP parked 判定 / 完整 DNS 链+重定向链+TLS / IANA RDAP bootstrap + 权威 RDAP / 家族域 RDAP / CT 历史族域补充。实测靶标 example-com：一次跑完给出 16 个候选域的到期日、状态、解析与活业务判定，并挖出同供应商家族 lkag3.com/0ogkt.com/sg7du.com/manycai.com（同 NS + 同秒批量注册）。
```

## 正文

```
#!/bin/bash
# 上游/供应链域名「可控性」判定 —— 只做查询，不做任何注册/抢注/联系
# 用法：把待判域名填进 DOMAINS，在 VPS 上跑（本机出口常被 Cloudflare 挑战/被墙）
# 判定三选一：可控（已过期/待释放/parked/待售）| 不可控（在册+活业务+近期证书）| 不确定

DOMAINS="lkag3.com t4nmvxp8jsgq.net 0r7qihccdywv.vip srjby9kysmjx.space ng777.net api-bet.net ng-demo.xyz okwink6.com lbpal.click artd.pro bakbitionb.com"

# ---------- 1) whois（默认 referral）----------
for d in $DOMAINS; do
  echo "### $d"
  whois "$d" 2>/dev/null | grep -iE 'domain name:|registrar:|creation date|created:|updated date|registry expiry|expiry|expiration|domain status:|name server:|dnssec:'
  sleep 3
done

# ---------- 2) RDAP 权威补位（whois 被 privacy/rate-limit 挡住时用）----------
# IANA bootstrap 找端点：curl -s https://data.iana.org/rdap/dns.json
rdap(){ curl -sS --max-time 25 -H 'Accept: application/rdap+json' "$2" \
  | jq -r '"status: \(.status//[]|join(","))", ([.events[]?|"\(.eventAction): \(.eventDate)"]|join("\n")), ([.nameservers[]?|"ns: \(.ldhName)"]|join("\n"))'; }
rdap x https://rdap.verisign.com/com/v1/domain/EXAMPLE.com      # .com
rdap x https://rdap.verisign.com/net/v1/domain/EXAMPLE.net      # .net
rdap x https://rdap.radix.host/rdap/domain/EXAMPLE.space        # .space/.site (Radix)
rdap x https://rdap.identitydigital.services/rdap/domain/EXAMPLE.pro  # .pro/.kim (Identity Digital)
# 注意：.vip/.xyz/.top 的 RDAP 端点因注册局而异，先查 IANA bootstrap

# ---------- 3) 指定注册局的 whois（部分注册局不支持默认 referral）----------
whois -h whois.namecheap.com  lbpal.click     # NameCheap 客户
whois -h whois.nic.space      x.space         # Radix（可能 rate limit，隔 30s 重试）
whois -h whois.verisign-grs.com x.com         # 注册局层（只给创建/到期/NS/状态，最稳）

# ---------- 4) DNS：解析链（判"是否还有解析 / 是不是 parked IP"）----------
for d in $DOMAINS; do
  echo "$d  NS=$(dig +short NS $d @203.0.113.1 | tr '\n' ' ')"
  dig "$d" A @203.0.113.1 +noall +answer +authority   # 看完整 CNAME 链
  sleep 2
done

# ---------- 5) HTTP/HTTPS：单次只读 GET，判 parked/活业务/NXDOMAIN ----------
# 每域名只打一次，间隔 ≥5s，不要骚扰别人的站
curl -sS -k -L --max-time 20 -A 'Mozilla/5.0' \
  -o /tmp/body.html -w '%{http_code} %{size_download} %{url_effective} %{remote_ip}\n' "$url"
grep -oiE '<title[^>]*>[^<]{0,120}' /tmp/body.html | head -1
sleep 5

# ---------- 6) CT（判"大约何时停用"）----------
curl -sS --max-time 40 "https://crt.sh/?q=%25.$d&output=json" -o ct.json
jq -r 'sort_by(.entry_timestamp)|reverse|.[0:5]|.[]|"\(.entry_timestamp) expires=\(.not_after) \(.common_name)"' ct.json

# ---------- 7) TLS 证书实际有效期（最准的"还活着吗"证据）----------
openssl s_client -connect $d:443 -servername $d </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates

# ---------- 8) 家族挖掘（关键！单个域不可控不等于家族不可控）----------
# a) CT 历史里轮换的 common_name 往往就是同一供应商的兄弟域：
jq -r '.[].common_name' ct.json | sort -u
# b) NS 归并：同一组自建 NS 基本就是同一运营者
# c) 创建/到期时间戳比对：精确到同一秒 = 批量注册 = 同一批人
# d) 对挖出来的兄弟域重复 1)-7)

```
