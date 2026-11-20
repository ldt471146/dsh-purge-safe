# 悬空 CNAME 的可认领性判定：AWS ELB/API Gateway、F5 XC 名不可复刻（greenmangaming.com 实测不可接管）

- **code**: dangling-cname-claimability-not-claimable-elb-apigw-f5
- **kind**: poc
- **category**: recon
- **component**: DNS / 子域接管（AWS ELB / AWS API Gateway / F5 Distributed Cloud / SoloCDN）
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 UTC，ARTEX 执行机 dig/nslookup（8.8.8.8/1.1.1.1/9.9.9.9）+ can-i-take-over-xyz 复核：greenmangaming.com 的 7 条悬挂 CNAME（api-cn/email-prod/email-staging/secure/team17/neom/machine-f5.ddp）目标全部 NXDOMAIN、子域 HTTP 000、无 NS/MX/TXT 委派。逐厂商判定：3 条 AWS ELB 经官方矩阵「Not vulnerable」(issue #137) 不能认领；2 条 AWS API Gateway（d-随机名）与 1 条 F5 XC（ves-io-UUID）名为厂商生成不可复刻；唯一命名可控的 SoloCDN(api-cn) 需其账号添加同名加速域，本环境无账号。最终未取得任何子域控制权。
- **path**: pocs/dangling-cname-claimability-not-claimable-elb-apigw-f5/poc.md
- **tags**: subdomain-takeover,dangling-cname,negative,aws-elb,aws-api-gateway,f5-xc,solocdn,nxdomain,claimability
- **created_at**: 2026-11-11T15:11:40.682Z
- **engine**: greenmangaming.com

## 描述

负面情报：判别「悬挂 CNAME」是否真能接管时，先按厂商把目标名分成「外部可复刻」与「厂商生成不可复刻」两类，避免对有洞无利用面的记录反复投入。原理：子域接管成立的必要条件是外部账户能在该厂商侧创建与 CNAME 目标同名的资源；若目标名由厂商按账号/UUID/随机数生成，则任何外部账户都无法复刻，记录虽悬挂但不可利用。

## 正文

```
# 悬空 CNAME 的可认领性判定（哪些厂商不可接管）

## 判据（先分类再决定是否投入）
悬挂本身（子域有 CNAME 且目标 NXDOMAIN）**不等于**可接管。接管成立的充要条件是：外部账户能在该厂商侧创建**与 CNAME 目标同名**的资源。按此把目标名分两类：

**A. 外部不可复刻 → 直接判不可利用（不要硬打）**
- `*.elb.amazonaws.com`（AWS ELB，含 ALB/NLB 经典名 `<name>-<hash>.us-east-1.elb.amazonaws.com`）：官方矩阵 can-i-take-over-xyz「AWS/Load Balancer (ELB) = **Not vulnerable**」(issue #137)。DNS 名由 AWS 生成，第三方账户无法复刻。
- `d-<10位随机>.execute-api.<region>.amazonaws.com`（AWS API Gateway 默认端点）：删除后由 AWS 随机重分配，外部不可指定同名。
- `ves-io-<UUID>.ac.vh.ves.io`（F5 Distributed Cloud）：virtual-host 的厂商生成 UUID 名，外部不可复刻。
- 经验规则：目标名含**随机串/UUID/账号派生哈希**者，一律按不可复刻处理。

**B. 命名可控 → 存在理论接管路径（需该厂商账号才能实证）**
- CDN 回源型 CNAME，如 SoloCDN `<加速域>.lxcvc.com`（lxcvc.com，SOA=com1.solocdn.cn）：客户添加加速域后由 CDN 生成记录，删除后记录消失；若 CDN 允许无域名所有权校验地添加同名加速域，即可重建记录接管。
- 同类：S3（`The specified bucket does not exist` → Vulnerable）、Heroku、GitHub Pages、Elastic Beanstalk、部分 SaaS（详见 can-i-take-over-xyz 矩阵）。

## 复核命令
```
git(或 WebFetch) https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/README.md   # 权威厂商矩阵
dig +short CNAME <sub> @8.8.8.8 ; dig <sub> @8.8.8.8 | grep status:      # 悬挂判据（NXDOMAIN）
dig +short A/CNAME <目标> @8.8.8.8 ; dig <目标> @1.1.1.1                 # 目标是否存在
curl -s -k -o /dev/null -w '%{http_code}\n' https://<sub>/               # 期望 000
dig +short SOA <CDN父域> @8.8.8.8 ; dig +short A zz<rand>.<CDN父域> @8.8.8.8  # 判 CDN 是否泛解析/活跃
curl -s "https://crt.sh/?q=<sub>&output=json"                            # 历史证书=曾托管真实服务(影响佐证)
```

## 实测实例（greenmangaming.com，task#6）
7 条悬挂 CNAME：ELB×3（不可认领）、API Gateway×2（不可认领）、F5 XC×1（不可认领）、SoloCDN×1（理论可认领但需其账号）。三解析器一致 NXDOMAIN，子域 HTTP 全 000，无 NS/MX/TXT 委派。历史证书：secure 2017~2024 DigiCert、machine-f5.ddp 2022~2023 LE、api-cn 2020 DigiCert。**最终结论：确认悬挂，无认领可能，未取得任何子域控制权。**

## 坑
- 别把「目标 NXDOMAIN」直接写成可接管——必须再判厂商侧命名是否可控。
- 别用本地/运营商 DNS 判悬挂，要显式指定 8.8.8.8/1.1.1.1/9.9.9.9。
- 泛解析域会误判：先 Prove `<rand>.<父域>` 是否解析。
- AWS ELB 虽悬挂，业内公认 Not vulnerable，投入前先查矩阵。

```
