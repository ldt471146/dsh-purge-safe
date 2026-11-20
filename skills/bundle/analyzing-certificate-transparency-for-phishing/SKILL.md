---
name: analyzing-certificate-transparency-for-phishing
description: 使用 crt.sh 和 Certstream 监控证书透明度日志，检测钓鱼域名、仿冒证书以及针对您所在组织的未经授权的证书签发行为。
domain: cybersecurity
subdomain: threat-intelligence
tags: [certificate-transparency, ct-logs, phishing, crt-sh, certstream, ssl, domain-monitoring, threat-intelligence]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# 通过证书透明度分析钓鱼威胁

## 概述

证书透明度（Certificate Transparency，CT）是一种互联网安全标准，为所有已签发的 SSL/TLS 证书创建公开的、仅可追加的日志记录。监控 CT 日志能够实现对以下威胁的早期检测：模仿合法品牌注册证书的钓鱼（Phishing）域名、针对自有域名的未授权证书签发，以及基于证书的攻击基础设施。本技能涵盖通过 crt.sh 查询 CT 日志、使用 Certstream 进行实时监控、构建可疑证书的自动化告警，以及将发现结果整合到威胁情报（Threat Intelligence）工作流程中。

## 前置条件

- Python 3.9+，安装 `requests`、`certstream`、`tldextract`、`Levenshtein` 库
- 访问 crt.sh (https://crt.sh/) 进行历史 CT 日志查询
- Certstream (https://certstream.calidog.io/) 用于实时监控
- 需监控的组织域名和品牌关键词列表
- 了解 SSL/TLS 证书结构和签发流程

## 核心概念

### 证书透明度日志

CT 日志是经过密码学保证的、可公开审计的、仅可追加的 TLS 证书签发记录。主要 CA（Let's Encrypt、DigiCert、Sectigo、Google Trust Services）将所有签发的证书提交到多个 CT 日志。截至 2025 年，Chrome 和 Safari 要求所有公开信任的证书必须支持 CT。

### 通过 CT 检测钓鱼

攻击者注册仿冒域名并获取免费证书（通常来自 Let's Encrypt），使钓鱼网站通过 HTTPS 显得合法。CT 监控能够早期发现这些行为，因为证书在钓鱼活动发起前就已出现在日志中，为主动封锁提供了时间窗口。

### crt.sh 数据库

crt.sh 是由 Sectigo 运营的免费 Web 界面和 PostgreSQL 数据库，对 CT 日志进行索引。支持通配符搜索（`%.example.com`）、直接 SQL 查询和 JSON API 响应。跨所有主要 CT 日志追踪证书签发、到期和吊销情况。

## 实践步骤

### 步骤 1：通过 crt.sh 查询证书历史

```python
import requests
import json
from datetime import datetime
import tldextract

class CTLogMonitor:
    CRT_SH_URL = "https://crt.sh"

    def __init__(self, monitored_domains, brand_keywords):
        self.monitored_domains = monitored_domains
        self.brand_keywords = [k.lower() for k in brand_keywords]

    def query_crt_sh(self, domain, include_expired=False):
        """查询 crt.sh 中匹配域名的证书。"""
        params = {
            "q": f"%.{domain}",
            "output": "json",
        }
        if not include_expired:
            params["exclude"] = "expired"

        resp = requests.get(self.CRT_SH_URL, params=params, timeout=30)
        if resp.status_code == 200:
            certs = resp.json()
            print(f"[+] crt.sh: {len(certs)} certificates for *.{domain}")
            return certs
        return []

    def find_suspicious_certs(self, domain):
        """查找可能是钓鱼尝试的证书。"""
        certs = self.query_crt_sh(domain)
        suspicious = []

        for cert in certs:
            common_name = cert.get("common_name", "").lower()
            name_value = cert.get("name_value", "").lower()
            issuer = cert.get("issuer_name", "")
            not_before = cert.get("not_before", "")
            not_after = cert.get("not_after", "")

            # 检查精确域名匹配（合法证书）
            extracted = tldextract.extract(common_name)
            cert_domain = f"{extracted.domain}.{extracted.suffix}"
            if cert_domain == domain:
                continue  # 合法证书，跳过

            # 标记可疑模式
            flags = []
            if domain.replace(".", "") in common_name.replace(".", ""):
                flags.append("contains target domain string")
            if any(kw in common_name for kw in self.brand_keywords):
                flags.append("contains brand keyword")
            if "let's encrypt" in issuer.lower():
                flags.append("free CA (Let's Encrypt)")

            if flags:
                suspicious.append({
                    "common_name": cert.get("common_name", ""),
                    "name_value": cert.get("name_value", ""),
                    "issuer": issuer,
                    "not_before": not_before,
                    "not_after": not_after,
                    "serial": cert.get("serial_number", ""),
                    "flags": flags,
                    "crt_sh_id": cert.get("id", ""),
                    "crt_sh_url": f"https://crt.sh/?id={cert.get('id', '')}",
                })

        print(f"[+] Found {len(suspicious)} suspicious certificates")
        return suspicious

monitor = CTLogMonitor(
    monitored_domains=["mycompany.com", "mycompany.org"],
    brand_keywords=["mycompany", "mybrand", "myproduct"],
)
suspicious = monitor.find_suspicious_certs("mycompany.com")
for cert in suspicious[:5]:
    print(f"  [{cert['common_name']}] Flags: {cert['flags']}")
```

### 步骤 2：使用 Certstream 进行实时监控

```python
import certstream
import Levenshtein
import re
from datetime import datetime

class CertstreamMonitor:
    def __init__(self, watched_domains, brand_keywords, similarity_threshold=0.8):
        self.watched_domains = [d.lower() for d in watched_domains]
        self.brand_keywords = [k.lower() for k in brand_keywords]
        self.threshold = similarity_threshold
        self.alerts = []

    def start_monitoring(self, max_alerts=100):
        """启动 CT 日志实时监控。"""
        print("[*] 正在启动 Certstream 监控...")
        print(f"    监控域名: {self.watched_domains}")
        print(f"    关键词: {self.brand_keywords}")

        def callback(message, context):
            if message["message_type"] == "certificate_update":
                data = message["data"]
                leaf = data.get("leaf_cert", {})
                all_domains = leaf.get("all_domains", [])

                for domain in all_domains:
                    domain_lower = domain.lower().strip("*.")
                    if self._is_suspicious(domain_lower):
                        alert = {
                            "domain": domain,
                            "all_domains": all_domains,
                            "issuer": leaf.get("issuer", {}).get("O", ""),
                            "fingerprint": leaf.get("fingerprint", ""),
                            "not_before": leaf.get("not_before", ""),
                            "detected_at": datetime.now().isoformat(),
                            "reason": self._get_reason(domain_lower),
                        }
                        self.alerts.append(alert)
                        print(f"  [ALERT] {domain} - {alert['reason']}")

                        if len(self.alerts) >= max_alerts:
                            raise KeyboardInterrupt

        try:
            certstream.listen_for_events(callback, url="wss://certstream.calidog.io/")
        except KeyboardInterrupt:
            print(f"\n[+] 监控已停止。共收集 {len(self.alerts)} 条告警。")
        return self.alerts

    def _is_suspicious(self, domain):
        """检查域名是否相对于监控域名存在可疑性。"""
        for watched in self.watched_domains:
            # 精确关键词匹配
            watched_base = watched.split(".")[0]
            if watched_base in domain and domain != watched:
                return True

            # Levenshtein 距离（域名抢注检测）
            domain_base = tldextract.extract(domain).domain
            similarity = Levenshtein.ratio(watched_base, domain_base)
            if similarity >= self.threshold and domain_base != watched_base:
                return True

        # 品牌关键词匹配
        for keyword in self.brand_keywords:
            if keyword in domain:
                return True

        return False

    def _get_reason(self, domain):
        """确定域名被标记的原因。"""
        reasons = []
        for watched in self.watched_domains:
            watched_base = watched.split(".")[0]
            if watched_base in domain:
                reasons.append(f"contains '{watched_base}'")
            domain_base = tldextract.extract(domain).domain
            similarity = Levenshtein.ratio(watched_base, domain_base)
            if similarity >= self.threshold and domain_base != watched_base:
                reasons.append(f"similar to '{watched}' ({similarity:.0%})")
        for kw in self.brand_keywords:
            if kw in domain:
                reasons.append(f"brand keyword '{kw}'")
        return "; ".join(reasons) if reasons else "unknown"

cs_monitor = CertstreamMonitor(
    watched_domains=["mycompany.com"],
    brand_keywords=["mycompany", "mybrand"],
    similarity_threshold=0.75,
)
alerts = cs_monitor.start_monitoring(max_alerts=50)
```

### 步骤 3：从 CT 日志枚举子域名

```python
def enumerate_subdomains_ct(domain):
    """从证书透明度日志中发现所有子域名。"""
    params = {"q": f"%.{domain}", "output": "json"}
    resp = requests.get("https://crt.sh", params=params, timeout=30)

    if resp.status_code != 200:
        return []

    certs = resp.json()
    subdomains = set()
    for cert in certs:
        name_value = cert.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name.endswith(f".{domain}") or name == domain:
                name = name.lstrip("*.")
                subdomains.add(name)

    sorted_subs = sorted(subdomains)
    print(f"[+] CT subdomain enumeration for {domain}: {len(sorted_subs)} subdomains")
    return sorted_subs

subdomains = enumerate_subdomains_ct("example.com")
for sub in subdomains[:20]:
    print(f"  {sub}")
```

### 步骤 4：生成 CT 情报报告

```python
def generate_ct_report(suspicious_certs, certstream_alerts, domain):
    report = f"""# 证书透明度情报报告
## 目标域名: {domain}
## 生成时间: {datetime.now().isoformat()}

## 摘要
- 发现可疑证书数量: {len(suspicious_certs)}
- 触发实时告警数量: {len(certstream_alerts)}

## 可疑证书（crt.sh）
| 通用名称 | 签发机构 | 标记 | crt.sh 链接 |
|------------|--------|-------|-------------|
"""
    for cert in suspicious_certs[:20]:
        flags = "; ".join(cert.get("flags", []))
        report += (f"| {cert['common_name']} | {cert['issuer'][:30]} "
                   f"| {flags} | [查看]({cert['crt_sh_url']}) |\n")

    report += f"""
## 实时 Certstream 告警
| 域名 | 签发机构 | 原因 | 检测时间 |
|--------|--------|--------|----------|
"""
    for alert in certstream_alerts[:20]:
        report += (f"| {alert['domain']} | {alert['issuer']} "
                   f"| {alert['reason']} | {alert['detected_at'][:19]} |\n")

    report += """
## 建议措施
1. 将标记域名添加到 DNS 黑洞 / Web 代理封锁列表
2. 对确认的钓鱼域名提交撤销申请
3. 持续监控 CT 日志，检测新的证书注册
4. 为自有域名实施 CAA DNS 记录，限制证书签发
5. 部署 DMARC 防止仿冒域名发送欺诈邮件
"""
    with open(f"ct_report_{domain.replace('.','_')}.md", "w") as f:
        f.write(report)
    print(f"[+] CT 报告已保存")
    return report

generate_ct_report(suspicious, alerts if 'alerts' in dir() else [], "mycompany.com")
```

## 验收标准

- crt.sh 查询成功返回目标域名的证书数据
- 基于仿冒模式识别出可疑证书
- Certstream 实时监控检测到新的钓鱼证书
- 子域名枚举从 CT 日志生成完整列表
- 告警附带原因分类信息
- CT 情报报告包含可执行的建议措施

## 参考资料

- [crt.sh Certificate Search](https://crt.sh/)
- [Certstream Real-Time CT Monitor](https://certstream.calidog.io/)
- [River Security: CT Logs for Attack Surface Discovery](https://riversecurity.eu/finding-attack-surface-and-fraudulent-domains-via-certificate-transparency-logs/)
- [Let's Encrypt: Certificate Transparency Logs](https://letsencrypt.org/docs/ct-logs/)
- [SSLMate Cert Spotter](https://sslmate.com/certspotter/)
- [CyberSierra: CT Logs as Early Warning System](https://cybersierra.co/blog/ssl-certificate-transparency-logs/)
