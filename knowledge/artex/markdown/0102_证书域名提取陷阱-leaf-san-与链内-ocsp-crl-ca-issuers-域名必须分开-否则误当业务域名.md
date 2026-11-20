# 证书域名提取陷阱：leaf SAN 与链内 OCSP/CRL/CA-Issuers 域名必须分开（否则误当业务域名）

- **code**: 证书域名提取陷阱-leaf-san-与链内-ocsp-crl-ca-issuers-域名必须分开-否则误当业务域名
- **kind**: script
- **category**: recon
- **severity**: info
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-09-29 实测：本队既有脚本用正则从 leaf 证书 DER 提取域名，对 203.0.113.73/.178/.188:8443 输出 yr1.c.lencr.org 与 yr1.i.lencr.org，若按业务域名解读会误判为"该机跑 lencr.org 相关业务"。改用 X509Certificate2 只读 203.0.113.81 后，三台 leaf 的真实 SAN 均为 example.com；同时单列 AIA=http://yr1.i.lencr.org/ 与 CRLDP=http://yr1.c.lencr.org/74.crl，证实二者是 leaf 的扩展字段而非链证书或业务域名。
- **path**: pocs/证书域名提取陷阱-leaf-san-与链内-ocsp-crl-ca-issuers-域名必须分开-否则误当业务域名/cert-domain-extract-pitfall.md
- **tags**: 证书,SAN,AIA,CRL,取证陷阱,资产测绘,避坑
- **created_at**: 2026-09-28T23:42:29.976Z
- **found_by**: vuln-scan

## 描述

从证书 DER 里用正则批量捞域名，会把 leaf 证书 AIA/CRLDP 扩展中的 OCSP/CRL/CA-Issuers 服务域名（如 yr1.c.lencr.org、yr1.i.lencr.org）当成业务域名，污染资产表并可能误把第三方基础设施当目标。正确做法是只读 subjectAltName（OID 203.0.113.81）。

## 用法

```
1) 提取业务域名：只读 leaf 证书的 subjectAltName（OID 203.0.113.81）。
2) 需要展示"链内 URL"时，单独读 AIA（203.0.113.9.203.0.113.124.1）与 CRLDP（203.0.113.82），不要并入域名集合。
3) 复核命令：
   curl.exe -kv --resolve <host>:443:<ip> https://<host>/ 2>&1 | findstr "subject: issuer:"
   或用 .NET：$ssl.RemoteCertificate -> X509Certificate2 -> Extensions | ? Oid -eq "203.0.113.81"
```

## 正文

```
# 从 TLS 证书里提取域名时，必须区分「leaf SAN」与「证书链/AIA/CRLDP 里的基础设施域名」
#
# ============ 症状 ============
# 常见写法（从 DER 里正则捞所有像域名的字符串）：
#     txt = der.decode("latin-1")
#     names = re.findall(r"[A-Za-z0-9*][A-Za-z0-9*._\-]{3,90}", txt)
#     names = [n for n in names if any(n.lower().endswith(t) for t in TLD)]
# 结果里会混进 **Let's Encrypt 的 OCSP / CRL / CA Issuers 服务域名**，例如：
#     yr1.i.lencr.org      <- AIA 扩展里的 "CA Issuers" URL（i = issuer）
#     yr1.c.lencr.org      <- CRL Distribution Point URL（c = CRL），形如 http://yr1.c.lencr.org/74.crl
#     r10.o.lencr.org      <- AIA 扩展里的 OCSP URL（o = ocsp）
# 这些是 **leaf 证书自身携带的扩展字段值**，不是业务域名。
#
# ============ 为什么危险 ============
# 它们看起来完全像一个正常域名（还有 TLD .org），会被直接写进资产表，
# 于是报告里出现"该机部署了 lencr.org 相关业务""同证书反查出 lencr.org 体系"这类错误结论，
# 甚至把 ocsp/crl 端点当成新资产去测绘、去攻击（第三方基础设施，越界风险）。
#
# ============ 正确做法（.NET / 只看 leaf 的 SAN 扩展） ============
#   $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
#   $cn   = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
#   $e    = $cert.Extensions | ? { $_.Oid.Value -eq "203.0.113.81" }      # subjectAltName —— 真正的业务域名
#   if ($e) { $san = $e.Format($false) -replace 'DNS Name=','' }
#   # 想单独看"哪些是链内 URL"，就另外取这两个扩展，别和 SAN 混在一个字段里：
#   #   AIA   : 203.0.113.9.203.0.113.124.1
#   #   CRLDP : 203.0.113.82
#
# 关键点：`$ssl.RemoteCertificate` 取到的是 **leaf**；
# 用 X509Certificate2 的扩展 API 读 SAN，天然不会把 AIA/CRLDP 里的 URL 当成域名。
#
# ============ 判读基准（本次实测） ============
# 203.0.113.73:8443 / .178:8443 / .188:8443，任意 SNI 下：
#   leaf CN  = example.com   <- 真实业务域名（SAN 也只有这一个）
#   AIA      = http://yr1.i.lencr.org/
#   CRLDP    = http://yr1.c.lencr.org/74.crl
#   ⇒ 三台共用同一张 Let's Encrypt 证书，与"8443 是同一份 10B 占位页代码"自洽。

```
