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
