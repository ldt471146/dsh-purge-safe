# 公共 DNS 泄露内网 ELB 主机名 + RFC1918 私网 IP（cache.<域名> → internal-prod-…elb.amazonaws.com → 10.100.31.158，泄露内网命名规范/网段/技术栈）

- **code**: public-dns-cname-internal-elb-rfc1918-ip-leak
- **kind**: poc
- **category**: info-leak
- **component**: DNS / AWS ELB (us-east-1) / 内网源站
- **severity**: low
- **language**: markdown
- **source**: manual
- **verified**: 1
- **verified_note**: task#6 / finding_id=94（finding_checks.verdict=verified），2026-11-11 15:40 UTC 在 ARTEX 执行机对 greenmangaming.com 公共 DNS 只读实测：`nslookup -type=CNAME cache.greenmangaming.com 8.8.8.8` → canonical name = internal-prod-heimdall-episerver-cache-468340629.us-east-1.elb.amazonaws.com.；`nslookup cache.greenmangaming.com 8.8.8.8` → Address: 10.100.31.158。8.8.8.8 与 1.1.1.1 两公共解析器结果一致，10.100.31.158 属 RFC1918 私网段（公网不可达），据此判定内部 ELB 主机名与内网网段/命名规范/技术栈(EPiServer/heimdall)经公共 DNS 泄露成立。对应探索事实 1086。
- **path**: pocs/public-dns-cname-internal-elb-rfc1918-ip-leak/public-dns-internal-elb-rfc1918-leak.md
- **tags**: dns,info-leak,internal-hostname,rfc1918,elb,aws,subdomain,recon,internal-topology
- **created_at**: 2026-11-11T15:51:36.916Z
- **engine**: cache.greenmangaming.com

## 描述

原理：某个子域（本例 cache.<域名>，内网缓存/EPiServer 站）的 CNAME 指向 AWS 内部 ELB 主机名 internal-prod-heimdall-episerver-cache-468340629.us-east-1.elb.amazonaws.com，且该记录的 A 记录解析为 RFC1918 私网地址（10.100.31.158 而非公网 ELB 的 52.x/54.x）。公共解析器（8.8.8.8/1.1.1.1/9.9.9.9）都能查到，等于把生产内网的主机命名规范（internal-prod-<服务>-<栈>-<功能>）、网段（10.100.0.0/x）与技术栈（EPiServer/heimdall）公开。前提：无，纯公共 DNS 只读查询。适用面：任何把内网 split-horizon 记录误发布到公网 DNS 的品牌域名，是源站定位与横向前的免费情报。注意：私网 IP 公网不可达，本项只算情报泄露不是直接利用面。

## 用法

```
【前置】能发公共 DNS 查询即可（8.8.8.8 / 1.1.1.1 / 9.9.9.9），全程只读、无凭据。

【单发判据（两条都要命中）】
1) CNAME 暴露内部 ELB 主机名：
   nslookup -type=CNAME cache.<domain> 8.8.8.8
   → canonical name = internal-prod-heimdall-episerver-cache-<数字>.us-east-1.elb.amazonaws.com.
   （AWS 公网 ELB 典型主机名形如 xxx-<10位数字>.us-east-1.elb.amazonaws.com；出现 internal-* / *-internal-* 前缀即内网 ELB）
2) A 记录为 RFC1918 私网地址：
   nslookup cache.<domain> 8.8.8.8
   → Address: 10.100.31.158   （10/8、172.16/12、192.168/16 即在名单；公网 ELB 应返回 52.x/54.x/3.x 公网 IP）

【批量筛法（一次把全部子域过一遍）】
   # subs.txt 为子域清单
   dnsx -l subs.txt -cname -resp -silent > cname.txt          # 抓 CNAME 目标
   grep -Ei 'internal|\.internal\.|elb\.amazonaws\.com' cname.txt   # 找内部 ELB 命名
   dnsx -l subs.txt -a -resp -silent | grep -E '^([a-z0-9.-]+) (10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'   # A 记录落在私网段
   # 每条结论用 8.8.8.8/1.1.1.1/9.9.9.9 三解析器交叉确认一致再采信（避免本地/运营商 DNS 缓存误判）

【拿到泄露信息后怎么用】
 - 内网主机命名规范 internal-prod-<服务>-<栈>-<功能>：可据此推断同级内网资源名（如 origin / admin / api 侧），配合该族其它子域的证书 SAN 反查同批 us-east-1 生产/运维主机；
 - 网段 10.100.0.0/x 与技术栈 EPiServer/heimdall：一旦拿到 SSRF / 内网代理 / 反代绕过，可直接按该网段与主机名定点探测；
 - 结合同族子域证书 SAN（例：origin.account.<domain> 的 ALB 证书 SAN 含 admin.uther.tooling.<domain>）可拼出生产/运维主机清单。

【失败常见原因】
 - 只有本地/运营商 DNS 缓存：必须显式指定 8.8.8.8/1.1.1.1 再判；
 - 误判：若 A 记录是 52.x/54.x 公网 IP，只是公网 ELB 且用了 internal 字样，不算私网泄露；
 - 已修（split-horizon 生效）：公网查该子域返回 NXDOMAIN 或无 A 记录，说明记录已收回内网解析，本条不成立；
 - 私网 IP 本身公网不可达——不要试图直接连，仅做情报。
```

## 正文

```
# 公共 DNS 泄露内网 ELB 主机名 + RFC1918 私网 IP

## 前置条件
- 能发公共 DNS 查询（8.8.8.8 / 1.1.1.1 / 9.9.9.9 可达）
- 只读操作，无需目标凭据
- 工具：nslookup / dig / dnsx(ProjectDiscovery)

## 单条复核（两条都要命中）
```bash
# 1) CNAME 暴露内部 ELB 主机名
$ nslookup -type=CNAME cache.<domain> 8.8.8.8
cache.<domain> canonical name = internal-prod-heimdall-episerver-cache-<digits>.us-east-1.elb.amazonaws.com.

# 2) A 记录为 RFC1918 私网地址
$ nslookup cache.<domain> 8.8.8.8
Name:    cache.<domain>
Address: 10.100.31.158     # 10/8 | 172.16/12 | 192.168/16 即在名单
```

三解析器交叉确认（8.8.8.8 / 1.1.1.1 / 9.9.9.9）结论一致才采信。

## 批量筛法
```bash
# subs.txt = 子域清单
dnsx -l subs.txt -cname -resp -silent > cname.txt
grep -Ei 'internal|elb\.amazonaws\.com' cname.txt           # 内部 ELB 命名

dnsx -l subs.txt -a -resp -silent \
  | grep -E '^([a-z0-9.-]+) (10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'   # A 落在私网段
```

## 判据
- 子域 CNAME 指向 `internal-*` / `*-internal-*` 前缀的 ELB 主机名（AWS 公网 ELB 一般是 `xxx-<10位数字>.us-east-1.elb.amazonaws.com`，不带 internal）
- 该子域 A 记录返回 RFC1918 私网地址（公网 ELB 应返回 52.x/54.x/3.x 公网 IP）
- 两个条件同时成立 → 内网拓扑/命名规范/网段/技术栈经公共 DNS 泄露

## 实测实例（target = greenmangaming.com，2026-11-11 15:40 UTC）
```bash
$ nslookup -type=CNAME cache.greenmangaming.com 8.8.8.8
cache.greenmangaming.com canonical name = internal-prod-heimdall-episerver-cache-468340629.us-east-1.elb.amazonaws.com.
$ nslookup cache.greenmangaming.com 8.8.8.8
Name:    cache.greenmangaming.com
Address: 10.100.31.158
```
- 多个公共解析器 8.8.8.8 / 1.1.1.1 结果一致
- 10.100.31.158 为 RFC1918 私网地址，公网不可达，但泄露了：
  - 生产内网主机命名规范 `internal-prod-<服务>-<栈>-<功能>`
  - 内网网段 `10.100.0.0/x`
  - 技术栈 EPiServer / heimdall
- 同族佐证：origin.account.greenmangaming.com 的 AWS ALB 证书 SAN 含 admin.uther.tooling.greenmangaming.com，指向同一批 us-east-1 生产/运维主机

## 影响 / 用途
- 不是直接利用面（私网 IP 不可直连），是**免费情报**：为源站定位、内网横向、SSRF/内网代理后的定点探测提供依据
- 命名规范可反推同级内网资源名；配合证书 SAN 反查可拼出生产/运维主机清单

## 证伪条件
- 公网查该子域返回 NXDOMAIN / 无 A 记录（split-horizon 已收回内网解析）→ 不成立
- A 记录为 52.x/54.x 公网 IP → 只是公网 ELB 用了 internal 字样，不算私网泄露

## 失败常见原因
- 用本地/运营商 DNS 缓存 → 必须显式指定 8.8.8.8/1.1.1.1 再判
- 把公网 ELB 误判为内网 ELB（看是否有 internal 前缀 + 是否私网 IP 双重确认）
- 试图直连私网 IP（公网不可达，会超时）

```
