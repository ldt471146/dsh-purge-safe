# API 参考：使用 Wireshark 执行网络取证

## pyshark API

```python
import pyshark

# 打开捕获文件
cap = pyshark.FileCapture("capture.pcap")
cap = pyshark.FileCapture("capture.pcap", display_filter="http.request")

# 访问数据包字段
for pkt in cap:
    print(pkt.ip.src, pkt.ip.dst)
    print(pkt.tcp.dstport)
    print(pkt.http.request_uri)
```

## tshark CLI

| 命令 | 描述 |
|------|------|
| `tshark -r <pcap> -q -z conv,tcp` | TCP 会话统计 |
| `tshark -r <pcap> -Y "dns.qr==0" -T fields -e dns.qry.name` | 提取 DNS 查询 |
| `tshark -r <pcap> --export-objects http,<dir>` | 导出 HTTP 对象 |
| `tshark -r <pcap> -q -z io,phs` | 协议层次统计 |
| `tshark -r <pcap> -q -z endpoints,ip` | IP 端点统计 |

## 显示过滤器

| 过滤器 | 描述 |
|--------|------|
| `dns.qr==0` | 仅 DNS 查询 |
| `http.request` | HTTP 请求 |
| `tls.handshake.extensions_server_name` | TLS SNI 值 |
| `tcp.flags.syn==1 && tcp.flags.ack==0` | TCP SYN 数据包 |
| `ip.dst==<ip> && tcp.dstport==443` | 到特定主机的流量 |

## Python 库

| 库 | 版本 | 用途 |
|----|------|------|
| `pyshark` | >=0.6 | tshark 数据包分析的 Python 封装 |
| `dpkt` | >=1.9 | 不依赖 tshark 的底层 PCAP 解析 |
| `scapy` | >=2.5 | 数据包构造和分析 |

## 参考资料

- pyshark: https://github.com/KimiNewt/pyshark
- Wireshark 显示过滤器: https://wiki.wireshark.org/DisplayFilters
- dpkt: https://github.com/kbandla/dpkt
- NetworkMiner: https://www.netresec.com/?page=NetworkMiner
