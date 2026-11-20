---
name: cszh-hunting-for-dns-tunneling-with-zeek
description: "通过分析 Zeek dns.log 中的高熵子域名查询、超量查询量、超长查询长度以及异常 DNS 记录类型，检测 DNS 隧道和数据外泄中的隐蔽通道通信。适用于：当需要狩猎基于 DNS 的 C2 或数据外泄通道、调查异常 DNS 查询模式、或响应涉及 DNS 隧道工具（iodine、dnscat2、DNSExfiltrator）的威胁情报时使用。"
---

> 来源：killvxk/cybersecurity-skills-zh 上游技能 `hunting-for-dns-tunneling-with-zeek`，正文为中文原文照录（仅剥离上游 frontmatter）。
> 定位：使用 Zeek 狩猎 DNS 隧道。
> 用法：按正文的「工作流程 / 命令清单 / 输出格式」执行；本技能在 dsh 中的名字是 cszh-hunting-for-dns-tunneling-with-zeek。

# 使用 Zeek 狩猎 DNS 隧道

## 适用场景

- 狩猎通过 DNS 隐蔽通道进行的数据外泄时
- 威胁情报显示针对所在行业的基于 DNS 的 C2 框架活动时
- dns.log 显示向特定域名的查询量异常偏高时
- 调查未发现 HTTP/S 外泄的疑似数据窃取事件时
- 监控 iodine、dnscat2、DNSExfiltrator 或 DNS-over-HTTPS 隧道工具时

## 前置条件

- Zeek 部署在网络分流点或 SPAN 端口以捕获 DNS 流量
- 包含完整查询和响应字段的 Zeek dns.log
- 用于 dns.log 分析的 SIEM 平台（Splunk、Elastic）
- 用于自动化 DNS 分析的 RITA（Real Intelligence Threat Analytics）
- 用于域名历史解析上下文的被动 DNS 数据

## 工作流程

1. **分析查询长度分布**：计算每个域名查询长度的均值和标准差。阈值：正常 20-30 字符，隧道 > 50 字符。
2. **计算子域名熵值**：计算子域名标签的 Shannon 熵。阈值：> 3.5 比特/字符提示编码数据。
   - **检查点**：确认已标记长度 > 50 且熵 > 3.5 的查询后再继续。
3. **统计每个域名的唯一子域名数量**：单个父域名下超过 100 个唯一子域名/小时为异常。
4. **监控 DNS 记录类型分布**：标记向单个域名发出的过量 TXT/NULL/CNAME/MX 查询（比例 > 50%）。
   - **检查点**：至少满足 2 项以上指标（长度、熵、唯一数、记录类型）才升级为高优先级。
5. **检测高查询量**：标记单源每小时 > 100 次查询，尤其结合高子域名唯一性。
6. **分析查询时序**：对 DNS 查询时间戳应用频率分析，识别信标（规律）或突发（传输）模式。
7. **与 conn.log 交叉关联**：将 DNS 查询与连接元数据关联，识别源进程或终端。
   - **检查点**：确认可疑域名已关联至具体终端后再进入情报验证。
8. **验证域名情报**：针对 WHOIS、证书透明度和威胁情报 feeds 核查可疑域名。

## 检测查询

### Zeek 脚本——DNS 隧道检测
```zeek
@load base/protocols/dns
module DNSTunnel;

export {
    redef enum Notice::Type += { DNSTunnel::Long_DNS_Query };
    const query_length_threshold = 50 &redef;
    const query_count_threshold = 100 &redef;
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    if ( |query| > query_length_threshold ) {
        NOTICE([$note=DNSTunnel::Long_DNS_Query,
                $msg=fmt("Long DNS query detected: %s (%d chars)", query, |query|),
                $conn=c]);
    }
}
```

### Splunk——Zeek DNS 隧道指标
```spl
index=zeek sourcetype=bro_dns
| rex field=query "(?<subdomain>[^.]+)\.(?<basedomain>[^.]+\.[^.]+)$"
| stats count dc(subdomain) as unique_subs avg(len(query)) as avg_len max(len(query)) as max_len by src basedomain
| where count > 100 AND (unique_subs > 50 OR avg_len > 40)
| sort -unique_subs
```

### Splunk——高熵子域名检测
```spl
index=zeek sourcetype=bro_dns
| rex field=query "^(?<subdomain>[^.]+)"
| where len(subdomain) > 20
| eval char_count=len(subdomain)
| stats count dc(query) as unique_queries avg(char_count) as avg_sub_len by src query_type_name basedomain
| where unique_queries > 30 AND avg_sub_len > 25
| sort -unique_queries
```

### RITA 分析
```bash
rita import /path/to/zeek/logs dataset_name
rita show-dns-fqdn-ips-long dataset_name
rita show-exploded-dns dataset_name
rita show-dns-tunneling dataset_name --csv > dns_tunnel_results.csv
```

## 常见场景

1. **dnscat2 C2**：将命令与控制流量编码在 DNS CNAME/TXT 查询中，使用 Base64 编码的子域名标签。产生大量高熵长子域名查询。
2. **iodine IPv4 隧道**：通过 DNS 创建虚拟网络接口，隧传所有 IP 流量。产生大量使用 NULL 记录类型的 DNS 查询。
3. **DNS 数据外泄**：敏感数据编码在子域名标签中（如 `aGVsbG8gd29ybGQ.exfil.attacker.com`），以 A 或 TXT 查询形式发送。每次查询携带约 63 字节数据。
4. **DNS-over-HTTPS 隧道**：通过向公共解析器（8.8.8.8、1.1.1.1）发送 HTTPS 上的 DNS 查询，绕过传统 DNS 监控，需要 TLS 检查才能检测。
5. **Cobalt Strike DNS 信标**：使用 DNS A/TXT 记录进行 C2 通信，支持可配置的子域名编码方案。

## 输出格式

```
狩猎 ID：TH-DNSTUNNEL-[日期]-[序号]
源 IP：[内网 IP]
源主机：[主机名]
目标域名：[基础域名]
查询次数：[时间窗口内的总查询数]
唯一子域名数：[数量]
平均查询长度：[字符数]
最大查询长度：[字符数]
子域名熵值：[比特/字符]
主要记录类型：[A/TXT/CNAME/NULL]
估算数据量：[外泄字节数]
风险等级：[严重/高/中/低]
```
