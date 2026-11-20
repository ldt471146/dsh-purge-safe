# SCADA HMI 安全评估 - API 参考

## SCADA 协议端口

| 端口 | 协议 | 描述 |
|------|------|------|
| 102 | S7comm | 西门子 S7 PLC 通信 |
| 502 | Modbus TCP | 工业自动化协议 |
| 2222 | EtherNet/IP | Allen-Bradley、Rockwell |
| 4840 | OPC UA | 开放平台通信统一架构 |
| 20000 | DNP3 | 分布式网络协议 |
| 47808 | BACnet | 楼宇自动化和控制 |

## 端口扫描（socket 标准库）

```python
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2.0)
result = sock.connect_ex((target, port))  # 0 = 开放
sock.close()
```

## pyshark 协议分析

```python
import pyshark
cap = pyshark.FileCapture("traffic.pcap")
for pkt in cap:
    for layer in pkt.layers:
        print(layer.layer_name)  # modbus, s7comm, dnp3 等
cap.close()
```

### 不安全的 SCADA 协议
这些协议缺乏内置加密和认证：
- **Modbus TCP** - 无认证、无加密、命令明文传输
- **S7comm** - 无认证（V4 之前版本）、无加密
- **DNP3** - 可选安全认证（SA），实际很少部署
- **BACnet** - 无原生安全机制
- **EtherNet/IP** - 无加密，可枚举设备

## HMI 配置检查项

| 检查项 | 严重性 | 描述 |
|--------|--------|------|
| 认证已禁用 | 严重 | HMI 允许匿名访问 |
| 无会话超时 | 高危 | 会话无限期持续 |
| TLS 已禁用 | 高危 | 通信明文传输 |
| 无 VPN 的远程访问 | 严重 | HMI 在无隧道情况下对外暴露 |
| 无 RBAC | 高危 | 单一角色或无访问控制 |
| 默认凭据 | 严重 | 使用出厂默认用户名/密码 |

## 常见默认凭据

| 用户名 | 密码 | 平台 |
|--------|------|------|
| admin | admin | 通用 HMI |
| admin | 1234 | Siemens WinCC |
| operator | operator | Wonderware |
| engineer | engineer | GE iFIX |
| guest | guest | 各类平台 |

## ICS 安全标准

- **IEC 62443** - 工业通信网络安全
- **NIST SP 800-82** - ICS 安全指南
- **NERC CIP** - 关键基础设施保护（电网）

## 输出 Schema

```json
{
  "report": "scada_hmi_security_assessment",
  "target": "192.168.1.100",
  "total_findings": 6,
  "severity_summary": {"critical": 2, "high": 3, "medium": 1},
  "findings": [{"type": "open_scada_port", "severity": "high"}]
}
```

## CLI 用法

```bash
python agent.py --target 192.168.1.100 --pcap traffic.pcap --config hmi.json --output report.json
```
