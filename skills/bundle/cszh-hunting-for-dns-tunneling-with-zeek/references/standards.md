# 标准与参考资料 - DNS 隧道检测

## MITRE ATT&CK 参考

| 技术编号 | 名称 | 描述 |
|-----------|------|-------------|
| T1071.004 | Application Layer Protocol: DNS | 基于 DNS 的 C2 通信 |
| T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | 通过 DNS 窃取数据 |
| T1572 | Protocol Tunneling | IP-over-DNS 隧道 |
| T1568.002 | Domain Generation Algorithms | 算法生成域名 |
| T1132.001 | Data Encoding: Standard Encoding | DNS 查询中的 Base32/64 |

## DNS 隧道检测阈值

| 指标 | 阈值 | 理由 |
|-----------|-----------|-----------|
| 查询长度 | > 50 字符 | 正常查询平均 20-30 字符 |
| 子域标签长度 | > 30 字符 | 最大标签为 63；隧道使用接近最大值 |
| 子域熵 | > 3.5 位/字符 | Base32/64 编码产生高熵 |
| 每个域的唯一子域数 | > 100 次/小时 | 合法域名的唯一子域较少 |
| 单个域的查询量 | > 100 次/小时 | 持续高量表明存在隧道 |
| TXT 记录查询比例 | > 50%（针对该域） | TXT 查询携带更多数据 |
| NULL 记录查询 | 任何量 | 合法使用极少 |

## DNS 隧道工具

| 工具 | 协议 | 记录类型 | 数据速率 | 检测难度 |
|------|----------|-------------|-----------|---------------------|
| iodine | IP-over-DNS | NULL, TXT, CNAME, A | ~100 Kbps | 中等 |
| dnscat2 | DNS 上的 C2 | TXT, CNAME, MX | ~10 Kbps | 中等 |
| DNSExfiltrator | DNS 外泄 | TXT, A | ~5 Kbps | 中等偏难 |
| Cobalt Strike DNS | C2 | A, TXT | 可变 | 难 |
| dns2tcp | TCP-over-DNS | TXT, KEY | ~50 Kbps | 中等 |
| Heyoka | DNS 外泄 | 所有类型 | 可变 | 难 |

## DNS 分析的 Zeek 日志字段

| 字段 | 描述 | 隧道关联性 |
|-------|-------------|-----------------|
| query | 完整 DNS 查询名称 | 长度和熵分析 |
| qtype_name | 查询记录类型 | TXT/NULL/CNAME 异常 |
| answers | 响应内容 | 响应大小分析 |
| rcode_name | 响应码 | NXDOMAIN 模式 |
| id.orig_h | 来源 IP | 来源识别 |
| AA | 权威答复 | 非权威响应 |
| rejected | 查询被拒绝 | 过滤有效性 |
