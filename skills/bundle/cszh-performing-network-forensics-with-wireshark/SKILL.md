---
name: cszh-performing-network-forensics-with-wireshark
description: 使用 Wireshark 和 tshark 捕获并分析网络流量，重建网络事件、提取制品并识别恶意通信。
---

> 来源：killvxk/cybersecurity-skills-zh 上游技能 `performing-network-forensics-with-wireshark`，正文为中文原文照录（仅剥离上游 frontmatter）。
> 定位：使用 Wireshark 执行网络取证。
> 用法：按正文的「工作流程 / 命令清单 / 输出格式」执行；本技能在 dsh 中的名字是 cszh-performing-network-forensics-with-wireshark。

# 使用 Wireshark 执行网络取证

## 适用场景
- 分析安全事件中捕获的网络流量（PCAP 文件）时
- 在捕获的流量中识别命令与控制（C2）通信时
- 从数据包捕获中重建数据窃取活动时
- 进行恶意软件分析以识别网络入侵指标时
- 提取通过网络传输的文件、凭据和制品时

## 前置条件
- 已安装 Wireshark 或 tshark 用于数据包分析
- 来自网络捕获的 PCAP/PCAPNG 文件（tcpdump、Wireshark、网络 TAP）
- NetworkMiner 用于自动化制品提取
- 处理大型捕获文件所需的足够内存（1GB+ 的 PCAP 需要 8GB+ 内存）
- 了解 TCP/IP、HTTP、DNS、TLS 协议
- 用于 IP 地理定位的 GeoIP 数据库

## 工作流程

### 步骤 1：准备并验证捕获文件

```bash
# 安装 Wireshark 和 tshark
sudo apt-get install wireshark tshark

# 验证 PCAP 文件
capinfos /cases/case-2024-001/network/capture.pcap

# 输出包括：文件类型、数据包数量、捕获时长、数据大小
# 示例输出：
# File name:           capture.pcap
# File type:           Wireshark/tcpdump/... - pcap
# Number of packets:   1,245,678
# File size:           856 MB
# Data size:           823 MB
# Capture duration:    3600.123456 seconds
# First packet time:   2024-01-15 14:00:00.000000
# Last packet time:    2024-01-15 15:00:00.123456

# 对 PCAP 进行完整性哈希
sha256sum /cases/case-2024-001/network/capture.pcap \
   > /cases/case-2024-001/network/pcap_hash.txt

# 获取协议层次统计概览
tshark -r /cases/case-2024-001/network/capture.pcap -q -z io,phs
```

### 步骤 2：过滤并识别可疑流量

```bash
# 提取会话统计
tshark -r /cases/case-2024-001/network/capture.pcap -q -z conv,tcp

# 按传输字节数找出最活跃主机
tshark -r /cases/case-2024-001/network/capture.pcap -q -z endpoints,ip \
   | sort -t$'\t' -k3 -rn | head -20

# 过滤 DNS 查询（可能是 C2 或数据渗出）
tshark -r /cases/case-2024-001/network/capture.pcap \
   -Y "dns.qr == 0" \
   -T fields -e frame.time -e ip.src -e dns.qry.name \
   > /cases/case-2024-001/analysis/dns_queries.txt

# 查找针对异常 TLD 或超长域名的 DNS 查询（DNS 隧道）
tshark -r /cases/case-2024-001/network/capture.pcap \
   -Y "dns.qr == 0 && dns.qry.name matches \"[a-z0-9]{30,}\"" \
   -T fields -e frame.time -e ip.src -e dns.qry.name \
   > /cases/case-2024-001/analysis/suspicious_dns.txt

# 过滤 HTTP 流量
tshark -r /cases/case-2024-001/network/capture.pcap \
   -Y "http.request" \
   -T fields -e frame.time -e ip.src -e ip.dst -e http.request.method \
   -e http.host -e http.request.uri -e http.user_agent \
   > /cases/case-2024-001/analysis/http_requests.txt

# 查找连接到已知恶意端口的流量
tshark -r /cases/case-2024-001/network/capture.pcap \
   -Y "tcp.dstport == 4444 || tcp.dstport == 8080 || tcp.dstport == 1337 || tcp.dstport == 6667" \
   -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport \
   > /cases/case-2024-001/analysis/suspicious_ports.txt

# 检测信标模式（定时间隔连接）
tshark -r /cases/case-2024-001/network/capture.pcap \
   -Y "ip.dst == 185.0.0.1" \
   -T fields -e frame.time_epoch \
   > /tmp/beacon_times.txt
```

### 步骤 3：从流量中提取文件和对象

```bash
# 导出 HTTP 对象（通过 HTTP 传输的文件）
tshark -r /cases/case-2024-001/network/capture.pcap \
   --export-objects http,/cases/case-2024-001/analysis/http_objects/

# 导出 SMB 对象
tshark -r /cases/case-2024-001/network/capture.pcap \
   --export-objects smb,/cases/case-2024-001/analysis/smb_objects/

# 导出 DICOM 对象（医学影像）
tshark -r /cases/case-2024-001/network/capture.pcap \
   --export-objects dicom,/cases/case-2024-001/analysis/dicom_objects/

# 导出 FTP 数据传输
tshark -r /cases/case-2024-001/network/capture.pcap \
   -Y "ftp-data" \
   -T fields -e ftp-data.data \
   --export-objects ftp-data,/cases/case-2024-001/analysis/ftp_objects/

# 对所有提取对象进行哈希
find /cases/case-2024-001/analysis/http_objects/ -type f -exec sha256sum {} \; \
   > /cases/case-2024-001/analysis/extracted_file_hashes.txt

# 在 VirusTotal 上检查提取文件哈希
while read hash filepath; do
   echo "正在检查 $filepath ($hash)"
   curl -s "https://www.virustotal.com/api/v3/files/$hash" \
      -H "x-apikey: YOUR_API_KEY" | python3 -c "
import json,sys
data=json.load(sys.stdin)
if 'data' in data:
   stats=data['data']['attributes']['last_analysis_stats']
   print(f'  恶意：{stats[\"malicious\"]}，未检出：{stats[\"undetected\"]}')
else:
   print('  在 VT 上未找到')
"
done < /cases/case-2024-001/analysis/extracted_file_hashes.txt
```

### 步骤 4：重建 TCP 流和会话

```bash
# 跟踪特定 TCP 流（流索引 42）
tshark -r /cases/case-2024-001/network/capture.pcap \
   -q -z "follow,tcp,ascii,42" \
   > /cases/case-2024-001/analysis/stream_42.txt

# 提取与可疑主机相关的所有 HTTP 请求-响应对
tshark -r /cases/case-2024-001/network/capture.pcap \
   -Y "http && ip.addr == 185.0.0.1" \
   -T fields -e frame.time -e http.request.method -e http.host \
   -e http.request.uri -e http.response.code -e http.content_length \
   > /cases/case-2024-001/analysis/suspicious_http.txt

# 提取 TLS/SSL 证书信息
tshark -r /cases/case-2024-001/network/capture.pcap \
   -Y "tls.handshake.type == 11" \
   -T fields -e ip.dst -e tls.handshake.certificate \
   > /cases/case-2024-001/analysis/tls_certs.txt

# 提取 TLS SNI（服务器名称指示）值
tshark -r /cases/case-2024-001/network/capture.pcap \
   -Y "tls.handshake.extensions_server_name" \
   -T fields -e frame.time -e ip.src -e ip.dst \
   -e tls.handshake.extensions_server_name \
   > /cases/case-2024-001/analysis/tls_sni.txt

# 从未加密协议中提取凭据
tshark -r /cases/case-2024-001/network/capture.pcap \
   -Y "ftp.request.command == \"USER\" || ftp.request.command == \"PASS\"" \
   -T fields -e frame.time -e ip.src -e ftp.request.command -e ftp.request.arg

tshark -r /cases/case-2024-001/network/capture.pcap \
   -Y "http.authorization" \
   -T fields -e frame.time -e ip.src -e http.host -e http.authorization
```

### 步骤 5：使用 NetworkMiner 进行自动化分析

```bash
# 安装 NetworkMiner（Linux 上需要 Mono）
sudo apt-get install mono-complete
wget https://www.netresec.com/?download=NetworkMiner -O NetworkMiner.zip
unzip NetworkMiner.zip -d /opt/NetworkMiner/

# 运行 NetworkMiner
mono /opt/NetworkMiner/NetworkMiner.exe /cases/case-2024-001/network/capture.pcap

# NetworkMiner 自动提取：
# - 主机清单（操作系统指纹、开放端口）
# - 通过 HTTP、FTP、SMB、TFTP 传输的文件
# - 网页流量中的图片
# - 凭据（明文和 NTLM 哈希）
# - DNS 记录
# - 会话参数
# - 异常和告警
```

### 步骤 6：生成网络取证报告

```bash
# 汇编调查结果
cat << 'EOF' > /cases/case-2024-001/analysis/network_forensics_report.txt
网络取证分析报告
===================================
案例：2024-001
捕获文件：capture.pcap（856 MB，1,245,678 个数据包）
捕获时段：2024-01-15 14:00 至 15:00 UTC
分析员：[检验员姓名]

流量概述：
  数据包总数：1,245,678
  唯一源 IP：45
  唯一目的 IP：234
  协议：TCP（78%）、UDP（18%）、ICMP（2%）、其他（2%）

C2 通信：
  目标：185.0.0.1:443
  信标间隔：约 60 秒
  连接总数：58
  数据传输：4.2 MB 出站，12.3 MB 入站
  TLS SNI：update-service.malware-c2.com

数据渗出：
  方式：通过 HTTPS POST 发送至 185.0.0.1
  数据量：45 分钟内 4.2 MB
  文件：从 HTTP 对象中提取的 3 个 ZIP 压缩包

DNS 隧道：
  可疑查询目标：data.evil-dns.com
  平均子域名长度：45 个字符
  查询次数：1,234 次（正常基线：50 次）
EOF
```

## 关键概念

| 概念 | 描述 |
|------|------|
| PCAP/PCAPNG | 存储原始网络流量的数据包捕获文件格式 |
| TCP 流（TCP stream） | 两个端点之间完整的双向通信 |
| 深度包检测（Deep packet inspection） | 分析超出头部信息的数据包载荷内容 |
| 信标行为（Beaconing） | 恶意软件定时回调 C2 服务器的行为 |
| DNS 隧道（DNS tunneling） | 将数据编码在 DNS 查询中以进行隐蔽渗出 |
| TLS/SNI | 服务器名称指示，在加密连接中揭示目标主机名 |
| 网络流（Network flow） | 端点间通信摘要（IP、端口、字节数、时长） |
| 协议层次（Protocol hierarchy） | 捕获文件中各协议的统计分布 |

## 工具与系统

| 工具 | 用途 |
|------|------|
| Wireshark | 基于 GUI 的数据包分析器，支持深度协议解析 |
| tshark | Wireshark 的命令行版本，用于脚本化分析 |
| NetworkMiner | 自动化网络取证分析和文件提取 |
| tcpdump | 命令行数据包捕获工具 |
| zeek（Bro） | 生成结构化连接日志的网络安全监控器 |
| ngrep | 用于数据包内容模式匹配的网络 grep |
| capinfos | PCAP 文件统计和元数据工具 |
| mergecap | 将多个 PCAP 文件合并为单一捕获文件 |

## 常见场景

**场景 1：恶意软件 C2 通信分析**
在 Wireshark 中加载 PCAP，识别向外部 IP 的信标模式，检查 TLS 证书是否为自签名或来自异常颁发者，提取包含编码命令的 HTTP POST 数据，将 C2 IP 与威胁情报源关联。

**场景 2：数据渗出检测**
分析流量统计，查找异常大的出站传输；检查 DNS 查询长度，识别 DNS 隧道指标；追踪 FTP 和 HTTP 文件上传至外部服务器；从数据包数据重建已渗出文件。

**场景 3：企业网络内部横向移动**
过滤内部主机间的 SMB、RDP、WMI 和 PSExec 流量，识别多个系统间的凭据使用模式，追踪攻击者在网络中的传播路径，与 Windows 事件日志中的认证事件关联。

**场景 4：Web 应用攻击重建**
过滤 Web 服务器的 HTTP 流量，识别 SQL 注入、XSS 和目录遍历尝试，跟踪成功利用的 TCP 流，提取上传的 Webshell 或恶意载荷，为事件报告记录攻击链。

## 输出格式

```
网络取证摘要：
  捕获：capture.pcap
  时长：1 小时（2024-01-15 14:00-15:00 UTC）
  数据包：1,245,678 个 | 大小：856 MB

  最可疑连接：
    192.168.1.50 -> 185.0.0.1:443   （C2，58 次连接，4.2MB 出站）
    192.168.1.50 -> 10.0.0.25:445   （SMB 横向移动）
    192.168.1.50 -> 10.0.0.30:3389  （RDP 横向移动）

  提取的制品：
    文件：        23 个（3 个被 VT 标记为恶意）
    凭据：        2 组明文 FTP 登录凭据
    DNS 查询：    1,234 条可疑记录（可能的隧道行为）
    TLS 证书：    5 张自签名证书

  已识别的 IOC：
    IP：     185.0.0.1, 203.0.113.50
    域名：   update-service.malware-c2.com, data.evil-dns.com
    哈希：   3 个文件哈希被标记为恶意软件
```
