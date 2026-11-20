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
