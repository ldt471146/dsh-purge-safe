# 详细狩猎工作流程 - 使用 Zeek 检测 DNS 隧道

## 阶段 1：查询长度与流量分析

### 步骤 1.1 - 识别具有长查询的域名
```spl
index=zeek sourcetype=bro_dns
| eval query_len=len(query)
| where query_len > 50
| rex field=query "\.(?<basedomain>[^.]+\.[^.]+)$"
| stats count avg(query_len) as avg_len max(query_len) as max_len dc(query) as unique_queries by id.orig_h basedomain
| where count > 50
| sort -avg_len
```

### 步骤 1.2 - 对单一域名的高频 DNS 查询
```spl
index=zeek sourcetype=bro_dns
| rex field=query "\.(?<basedomain>[^.]+\.[^.]+)$"
| bin _time span=1h
| stats count by id.orig_h basedomain _time
| where count > 100
| sort -count
```

## 阶段 2：熵分析

### 步骤 2.1 - Shannon 熵计算
```python
import math
from collections import Counter

def shannon_entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())

# 标记熵值 > 3.5 的子域名
```

### 步骤 2.2 - Splunk 熵近似计算
```spl
index=zeek sourcetype=bro_dns
| rex field=query "^(?<subdomain>[^.]+)"
| where len(subdomain) > 20
| eval has_numbers=if(match(subdomain, "[0-9]"), 1, 0)
| eval has_mixed_case=if(match(subdomain, "[A-Z]") AND match(subdomain, "[a-z]"), 1, 0)
| stats count avg(len(subdomain)) as avg_sub_len sum(has_numbers) as numeric_count by id.orig_h basedomain
| eval numeric_ratio=numeric_count/count
| where avg_sub_len > 25 AND numeric_ratio > 0.3
```

## 阶段 3：记录类型分析

### 步骤 3.1 - 异常记录类型
```spl
index=zeek sourcetype=bro_dns
| where qtype_name IN ("TXT", "NULL", "CNAME", "MX", "KEY", "SRV")
| rex field=query "\.(?<basedomain>[^.]+\.[^.]+)$"
| stats count dc(query) as unique by id.orig_h basedomain qtype_name
| where count > 50
| sort -count
```

## 阶段 4：RITA 自动化分析

```bash
# 完整 Zeek 日志导入和 DNS 分析
rita import /opt/zeek/logs/current dns_hunt
rita show-dns-tunneling dns_hunt
rita show-exploded-dns dns_hunt | sort -k2 -n -r | head -20
```

## 阶段 5：关联分析与响应

### 步骤 5.1 - 将 DNS 源映射至终端
将 dns.log 中的源 IP 与 DHCP 日志或终端清单关联，识别受影响的主机和进程。

### 步骤 5.2 - 响应动作
1. 对识别出的隧道域名进行 DNS 沉洞（Sinkhole）
2. 在 DNS 解析器和防火墙处封锁
3. 隔离源终端
4. 捕获内存和磁盘取证
5. 评估数据外泄范围
