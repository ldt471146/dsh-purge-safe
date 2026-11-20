# API 参考：使用 Zeek 检测 DNS 隧道

## 检测启发式规则

| 指标 | 阈值 | 评分 |
|------|------|------|
| Shannon 熵 | > 3.5 | +40 |
| 平均子域名长度 | > 30 字符 | +30 |
| 隧道查询类型比例 | > 50% TXT/NULL/CNAME | +20 |
| 高查询量 | > 500 次查询 | +10 |

## Zeek dns.log 字段

| 索引 | 字段 | 描述 |
|------|------|------|
| 0 | `ts` | 时间戳 |
| 2 | `id.orig_h` | 源 IP |
| 4 | `id.resp_h` | DNS 服务器 |
| 9 | `query` | 查询名称 |
| 13 | `qtype_name` | 查询类型（A、TXT 等） |
| 21 | `answers` | 响应答案 |

## DNS 隧道工具（用于检测参考）

| 工具 | 编码方式 | 查询类型 |
|------|---------|---------|
| iodine | Base128 | NULL、TXT |
| dnscat2 | Hex/Base64 | CNAME、TXT、MX |
| dns2tcp | Base64 | TXT |
| Cobalt Strike | Hex | A、AAAA、TXT |

## Shannon 熵参考值

| 数据类型 | 熵值 |
|---------|------|
| 正常主机名 | 2.0 - 3.0 |
| Base32 编码 | 3.5 - 4.0 |
| Base64 编码 | 4.0 - 5.0 |
| Hex 编码 | 3.5 - 4.0 |

## Python 库

| 库 | 用途 |
|----|------|
| `math` | 熵值计算 |
| `csv` | TSV 日志解析 |
| `collections.defaultdict` | 域名聚合 |
| `dpkt` | PCAP DNS 解析 |
| `dnslib` | DNS 数据包构造 |

## Zeek DNS 分析脚本

```zeek
@load base/protocols/dns
redef DNS::max_pending_queries = 1000;
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count) {
    if (|query| > 50) print fmt("Long query: %s", query);
}
```
