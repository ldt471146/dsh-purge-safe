# greenmangaming.com `origin.*` 子域公共 DNS 泄露 Fastly 源站公网 IP（origin.checkout→GCP 136.68.235.246 / origin.account→AWS ALB 35.168.247.19·44.196.109.144，破 CDN 隔离假设）

- **code**: greenmangaming-origin-subdomain-public-dns-fastly-origin-ip
- **kind**: poc
- **category**: info-leak
- **component**: Fastly CDN 前端 + GCP 负载均衡 / AWS ALB 源站（checkout.greenmangaming.com、account.greenmangaming.com）
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: task#6 / finding_id=93（finding_checks.verdict=verified），2026-11-11 15:35-15:50 UTC 在 ARTEX 执行机（Windows/Git Bash，工具 crt.sh + dnsx + nslookup + openssl s_client + curl --noproxy）对 greenmangaming.com 实测：① nslookup -type=A origin.checkout.greenmangaming.com 8.8.8.8 → 136.68.235.246（GCP）；② nslookup -type=A origin.account.greenmangaming.com 8.8.8.8 → 35.168.247.19 / 44.196.109.144（AWS ALB）；③ openssl s_client 取 origin.account.greenmangaming.com:443 证书 → subject=CN=account.greenmangaming.com，SAN 含 account.greenmangaming.com / *.account.greenmangaming.com / admin.uther.tooling.greenmangaming.com，确认该 IP 持有生产 account 域名证书；④ 直连 --noproxy '*' --resolve checkout…136.68.235.246 → HTTP 403/134B（源站 ACL 拒绝，同一 IP 对未知 Host 亦 403）；⑤ 经 Fastly 访问 checkout.greenmangaming.com 同路径 → 404/22646B 真实应用响应，反证 136.68.235.246 确为该服务源站；⑥ 直连 account 源站 35.168.247.19 → 404/0B server: awselb/2.0（ALB 默认无匹配规则），经 Fastly 同 URL → server: uvicorn 404/3316B。结论：源站 IP/主机名已暴露，但因源站按 Fastly/ACL 只信任边缘，直连未取得额外绕过，故 severity=low。
- **path**: pocs/greenmangaming-origin-subdomain-public-dns-fastly-origin-ip/poc.md
- **tags**: greenmangaming,fastly,cdn-bypass,origin-ip-leak,dns,info-disclosure,tls-cert-san,gcp,aws-alb,checkout,account,crt.sh,dnsx
- **created_at**: 2026-11-11T15:53:32.963Z
- **engine**: origin.checkout.greenmangaming.com (A 136.68.235.246) / origin.account.greenmangaming.com (A 35.168.247.19, 44.196.109.144)

## 描述

原理：CDN（本例 Fastly）赖以隔离源站的前提是「源站 IP/主机名对外不可知」，但组织常为运维方便给源站也建了 `origin.<service>.<domain>` 公共 DNS 记录，于是公共 DNS / 证书透明日志即可反解出真实源站公网 IP。适用面：任何「CDN/WAF 前置 + 源站另有 origin.* 命名」的目标；拿到源站 IP 后可尝试直连绕过 CDN 的 WAF/缓存/限速层（是否成功取决于源站 ACL/Host 白名单）。本例 checkout/account 两服务源站 IP 均泄露，但直连被源站 ACL 拒绝（403 / ALB 默认 404），故为信息暴露而非 CDN 绕过。

## 用法

```
【前置】能发公共 DNS 查询 + 出网 443 即可，全程只读、零凭据。

【Step 0 — 从 CT 日志找 origin. 候选（crt.sh）】
curl -s "https://crt.sh/?q=%25.greenmangaming.com&output=json" | jq -r '.[].name_value' | sort -u | grep -i '^origin\.'
# 或用 dnsx 全量枚举子域后再筛 origin./origin- 前缀
dnsx -l subs.txt -a -resp -silent | grep -i origin

【Step 1 — 主判据：origin.* 主机名解析出「非 CDN 段」的公网 IP】
nslookup -type=A origin.checkout.greenmangaming.com 8.8.8.8   # → 136.68.235.246（GCP，非 Fastly 段）
nslookup -type=A origin.account.greenmangaming.com  8.8.8.8   # → 35.168.247.19 / 44.196.109.144（AWS ALB）
# 判据：解析结果是云厂商（GCP/AWS/Azure）自有 IP，而不是 Fastly/Cloudflare/Akamai 边缘段 → 即源站

【Step 2 — 用 TLS 证书 SAN 确认「这个 IP 就是该服务生产源站」】
echo | openssl s_client -connect origin.account.greenmangaming.com:443 \
  -servername origin.account.greenmangaming.com 2>/dev/null | \
  openssl x509 -noout -subject -ext subjectAltName
# → subject=CN = account.greenmangaming.com
#   X509v3 Subject Alternative Name: DNS:account.greenmangaming.com, DNS:*.account.greenmangaming.com,
#                                  DNS:admin.uther.tooling.greenmangaming.com   （内网管理域也在同一证书里）

【Step 3 — 直连源站，验证能否绕过 CDN 层（关键：必须 --noproxy '*'，否则本机代理会重解析 DNS 使 --resolve 失效）】
curl -sk -o /dev/null -w "%{http_code}/%{size_download}\n" --noproxy '*' \
  --resolve checkout.greenmangaming.com:443:136.68.235.246 https://checkout.greenmangaming.com/
#  → 403/134   直连被源站 ACL 拒绝（同一 IP 对未知 Host 也 403）→ 源站只信任 Fastly 边缘
curl -sk -w "%{http_code}/%{size_download}\n" https://checkout.greenmangaming.com/
#  → 404/22646 经 Fastly 命中真实应用 → 反向确认 136.68.235.246 就是该服务源站
curl -sk -o /dev/null -w "%{http_code}/%{size_download} %{header_json}\n" --noproxy '*' \
  --resolve account.greenmangaming.com:443:35.168.247.19 https://account.greenmangaming.com/
#  → 404/0 (server: awselb/2.0)  直连落到 ALB 默认无匹配规则
curl -sk -D - -o /dev/null https://account.greenmangaming.com/
#  → 经 Fastly: server: uvicorn 404/3316  → 源站应用只对 Fastly 侧呈现

【判据汇总】同时成立才算「源站 IP 泄露」：
  1) origin.* 主机名在公共 DNS 可解析，且解析到云厂商自有 IP（非 CDN 边缘段）；
  2) 该 IP 的 443 证书 CN/SAN 覆盖被保护的生产域名（证明是同一生产站点源站）；
  3) 经 CDN 的正常响应与直连源站的响应「不同」→ 说明二者确实是边缘/源站两层。
【失败/常见原因】
  - 直连源站恒 403 / ALB 默认 404：源站 ACL 或 Host 白名单只放行 CDN 回源，属常见防护，此时仅剩「IP/内网信息暴露」，不构成绕过；
  - curl 忘加 --noproxy '*'：本机代理会重新解析域名，--resolve 失效，请求其实又走了 CDN，判据作废（参见方法论条目 proxy-host-header-false-origin）；
  - CT 日志可能滞后：新上的 origin.* 记录需补充 hostsearch/rapiddns 等被动 DNS 源交叉确认。
```

## 正文

```
# greenmangaming.com `origin.*` 源站子域泄露 Fastly 前置服务的真实公网源站 IP

## 结论（一句话）
Fastly 前置的 `checkout.greenmangaming.com` / `account.greenmangaming.com`，其真实源站主机名
`origin.checkout.greenmangaming.com` / `origin.account.greenmangaming.com` **在公共 DNS 中可解析**，
直接泄露 GCP / AWS 源站公网 IP；证书透明日志 + 证书 SAN 可进一步确认该 IP 就是生产源站。
属于 info-expose（low）：源站 IP 已暴露、CDN 隔离假设被破坏；但直连被源站 ACL 拒绝，未取得进一步的
CDN-WAF/缓存/限速绕过。

## 暴露的源站
| 服务（受 Fastly 保护） | 源站主机名 | 解析到的公网 IP | 云厂商 | 证书 CN |
|---|---|---|---|---|
| https://checkout.greenmangaming.com | origin.checkout.greenmangaming.com | 136.68.235.246 | GCP（负载均衡） | — |
| https://account.greenmangaming.com  | origin.account.greenmangaming.com  | 35.168.247.19 / 44.196.109.144 | AWS ALB | CN = account.greenmangaming.com |

## 复现步骤

### 0) 从证书透明日志找 origin. 候选
```bash
# crt.sh 拉全量子域，筛 origin 前缀
curl -s "https://crt.sh/?q=%25.greenmangaming.com&output=json" \
  | jq -r '.[].name_value' | sort -u | grep -i 'origin'
# 或先 dnsx 全量枚举再筛
dnsx -l subs.txt -a -resp -silent | grep -i origin
```

### 1) 主判据：origin.* 主机名解析到「非 CDN 段」的公网 IP（= 源站）
```bash
nslookup -type=A origin.checkout.greenmangaming.com 8.8.8.8
#   Name:    origin.checkout.greenmangaming.com
#   Address: 136.68.235.246                     → GCP，非 Fastly 边缘段 ⇒ 源站

nslookup -type=A origin.account.greenmangaming.com 8.8.8.8
#   Address: 35.168.247.19
#   Address: 44.196.109.144                     → AWS ALB ⇒ 源站
```
判据：解析结果落在云厂商自有 IP（GCP/AWS/Azure），而不是 Fastly/Cloudflare/Akamai 边缘 IP 段。

### 2) 用 TLS 证书 SAN 确认「该 IP 就是该服务生产源站」
```bash
echo | openssl s_client -connect origin.account.greenmangaming.com:443 \
  -servername origin.account.greenmangaming.com 2>/dev/null \
  | openssl x509 -noout -subject -ext subjectAltName
# subject=CN = account.greenmangaming.com
# X509v3 Subject Alternative Name:
#     DNS:account.greenmangaming.com, DNS:*.account.greenmangaming.com,
#     DNS:admin.uther.tooling.greenmangaming.com
```
证书即为生产 account 域名证书（同证书还覆盖一个内网管理域），坐实源站身份。

### 3) 直连源站 vs 经 Fastly —— 两层对照（`--noproxy '*'` 为硬要求）
```bash
# (a) 直连 checkout 源站，被源站 ACL 拒（同一 IP 对未知 Host 亦 403）
curl -sk -o /dev/null -w "%{http_code}/%{size_download}\n" --noproxy '*' \
  --resolve checkout.greenmangaming.com:443:136.68.235.246 https://checkout.greenmangaming.com/
#   403/134

# (b) 经 Fastly 同 URL → 命中真实应用 ⇒ 反向确认 136.68.235.246 就是该服务源站
curl -sk -w "%{http_code}/%{size_download}\n" https://checkout.greenmangaming.com/
#   404/22646

# (c) 直连 account 源站 → 落到 ALB 默认无匹配规则
curl -sk -o /dev/null -w "%{http_code}/%{size_download}\n" --noproxy '*' \
  --resolve account.greenmangaming.com:443:35.168.247.19 https://account.greenmangaming.com/
#   404/0   (server: awselb/2.0)

# (d) 经 Fastly 同 URL → 源站应用只对 Fastly 侧呈现
curl -sk -D - -o /dev/null https://account.greenmangaming.com/
#   server: uvicorn  → 404/3316
```

## 判据（同时成立才算「源站 IP 泄露」）
1. `origin.*` 主机名公共 DNS 可解析，且解析到云厂商自有 IP（非 CDN 边缘段）；
2. 该 IP:443 证书 CN/SAN 覆盖被保护的生产域名（证明是同一生产站点源站）；
3. 经 CDN 与直连源站的响应「不同」⇒ 确认二者是边缘/源站两层，而非同一层。

## 失败时常见原因
- **直连源站恒 403 / ALB 默认 404**：源站 ACL 或 Host 白名单只放行 CDN 回源。本例即如此，
  所以只能算信息暴露（low），不是 CDN 绕过。
- **忘记 `--noproxy '*'`**：本机 HTTP 代理会按 Host/域名重新解析，`--resolve` 失效，请求其实
  又回到 CDN —— 会误判成「直连成功」。复核见方法论条目 `proxy-host-header-false-origin`。
- **CT 日志滞后**：新上的 origin.* 记录可能还没进 crt.sh，需用 hostsearch / rapiddns 等被动 DNS
  源交叉确认当前映射。

## 信息来源
crt.sh（证书透明日志）+ dnsx（子域枚举）+ nslookup（8.8.8.8）+ openssl s_client（证书 SAN）
+ curl --noproxy '*'（直连对照）。全程只读、无凭据、无破坏性操作。

## 备注
与本库既有条目区分：
- id 566（`cache.greenmangaming.com` CNAME → internal ELB → RFC1918 私网 IP）泄露的是**内网私网 IP**；
  本条泄露的是**可直连的公网源站 IP**，机制与价值不同（本条旨在破坏 CDN 隔离假设）。
- id 94 是「TLS 证书 CN 反查找不走 CDN 的子域 → 源站 IP 泄露」的**通用方法**；
  本条是该方法的 greenmangaming 具体实例，且额外含 origin.* 命名被发现 + 直连 ACL 判死的结论。

```
