---
name: hfh-ics-ot-security
description: 网络安全知识库「工控安全」分类技能包，源自 Hi-FullHouse/CyberSecurity-Skills 上游 19-工控安全-ICS-OT-Security。覆盖 SCADA 系统安全评估（Nmap NSE modbus-discover/s7-info/bacnet-info/dnp3-info、PLCScan 设备发现、pymodbus 功能码读写测试、工控流量 tshark 分析、工控安全基线）、PLC 与 RTU 深度测试（ISF 框架、S7-1200/1500 与 Modicon 漏洞利用、python-snap7 读取 DB 块与保护级别、Ladder Logic 审计清单、固件 binwalk/Firmadyne 分析、常见 PLC CVE 速查）、工控网络协议安全（Modbus/DNP3/S7comm/EtherNet-IP/PROFINET/OPC UA/MQTT 安全特性对比、Scapy 构包、DNP3 SAv5、OPC UA 安全策略、MQTT 未授权、加固基准）、IEC 62443 合规审计（SL 等级评估矩阵、C2M2 十域成熟度、62443-2-1 控制项优先级、十条审计清单）、工控应急预案（OT IoC 检测层、六阶段响应流程、PLC 流量取证与 YARA、Stuxnet/TRISIS/Industroyer 响应参考）以及工业防火墙与网络分段（Purdue 五级模型、iptables/DPI 功能码过滤、Snort 规则、安全区与管道设计、分段成熟度评估），含 7 份中文原文 references。
---

# 工控安全（ICS / OT Security）

本技能覆盖工控与 OT 环境的**授权**安全评估、合规审计与应急响应：先按 Purdue 模型理清网络层级与资产，再针对 Modbus / DNP3 / S7comm / EtherNet-IP / PROFINET / OPC UA / MQTT 做协议级测试，向上做 IEC 62443 安全等级与成熟度评估，向下做 PLC/RTU 固件与逻辑审查。

三条铁律：**① 可用性优先于机密性**（OT 与 IT 的安全目标顺序不同）；**② 严禁在生产环境做写入类测试**（功能码 05/06/15/16、重启类命令会引发物理后果）；**③ 不要直接关闭 PLC**（可能造成物理损坏，应先切手动/旁路）。关键工具：nmap NSE、PLCScan、pymodbus、python-snap7、ISF、binwalk、Firmadyne、Wireshark/tshark、Scapy、Snort/Suricata、Dragos/Claroty/Nozomi。

## 一、SCADA 系统安全评估

### 1. 设备发现与识别

```bash
nmap -sV -p 502,102,20000,44818,2404,1911,2222 <target> --script modbus-discover
nmap -p 502 --script modbus-discover <target-range>
nmap -p 502 --script modbus-discover -sV --script-args modbus-discover.aggressive=true
nmap -p 102 --script s7-info <target>          # Siemens PLC
nmap -p 102 --script s7-enumerate <target-range>
nmap -p 47808 --script bacnet-info <target>    # BACnet
nmap -p 20000 --script dnp3-info <target>      # DNP3

git clone https://github.com/me easily/PLCScan.git
python PLCScan.py --target 192.168.1.100 --timeout 10
python PLCScan.py --range 192.168.1.0/24 --verbose
```

### 2. Modbus 协议测试

```python
from pymodbus.client import ModbusTcpClient
client = ModbusTcpClient('192.168.1.100', port=502); client.connect()
coils    = client.read_coils(0, 10, unit=1)              # 功能码 01
discrete = client.read_discrete_inputs(0, 10, unit=1)    # 功能码 02
holding  = client.read_holding_registers(0, 10, unit=1)  # 功能码 03
input_regs = client.read_input_registers(0, 10, unit=1)  # 功能码 04
# ⚠️ 写入测试仅在授权后执行
client.write_coil(0, True, unit=1)        # 功能码 05
client.write_register(0, 100, unit=1)     # 功能码 06
client.close()
```

```bash
pip install modbus-tk pymodbus
nmap -p 502 --script modbus-enum <target>
```

### 3. 工控流量分析

```bash
tshark -i eth0 -Y "modbus"  -T fields -e modbus.func_code -e modbus.unit_id
tshark -i eth0 -Y "dnp3"    -T fields -e dnp3.function_code -e dnp3.object_type
tshark -i eth0 -Y "s7comm"  -T fields -e s7comm.param.func
tshark -i eth0 -Y "cip"     -T fields -e cip.service
tshark -i eth0 -Y "pn_rt"   -T fields -e pn_rt.frame_id
```

```python
from scapy.all import *
def analyze_modbus(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].dport == 502:
        print(f"Modbus pkt: {pkt[IP].src} -> {pkt[IP].dst}")
        print(f"Unit ID: {pkt[Raw].load[6]}")
        print(f"Func Code: {pkt[Raw].load[7]}")
sniff(filter="tcp port 502", prn=analyze_modbus, count=10)
```

### 4. 工控安全基线

| 检查项 | 严重程度 | 典型配置 |
|:---|:---:|:---|
| 使用默认密码 | 🔴 严重 | admin/admin, 空密码 |
| Modbus 无认证 | 🔴 严重 | 协议本身无认证机制 |
| DNP3 安全模式未启用 | 🟠 高危 | Secure Authentication (SAv5) |
| PLC 固件未更新 | 🟠 高危 | 厂商安全公告未应用 |
| 工程站安装无关软件 | 🟠 高危 | 如浏览器、Office 等 |
| 网络分段不足（PLC 直连公司网） | 🔴 严重 | 缺少 Purdue 级别隔离 |
| 远程访问未加固 | 🟠 高危 | 未使用 Jump Box/VPN |
| 无线工控网络未加密 | 🟠 高危 | WiFi 未使用 WPA3 |
| HMI/SCADA 服务器未加固 | 🟡 中危 | 多余端口开放 |
| 日志审计未启用 | 🟡 中危 | 无法追踪异常操作 |
| 无备用/冗余控制 | 🟡 中危 | 单点故障风险 |

## 二、PLC 与 RTU 安全测试

### 1. ICS Exploitation Framework（ISF）

```bash
git clone https://github.com/dark-labs/ISF.git && cd ISF
pip install -r requirements.txt
python isf.py            # isf > show exploits / show scanners

use scanners/siemens_s7_scanner ; set target 192.168.1.100 ; run
use exploits/siemens/s7_plc     ; set target 192.168.1.100 ; set slot 1 ; check ; run
use scanner/modbus_scanner      ; set target 192.168.1.0/24 ; run
```

### 2. PLC 固件分析

```bash
binwalk -e firmware.bin
binwalk -Me firmware.bin                       # 递归扫描
firmware-mod-kit/extract-firmware.sh firmware.bin

strings firmware.bin | grep -iE "password|secret|key|admin|user"
strings firmware.bin | grep -iE "pass|pwd|login"
strings firmware.bin | grep -iE "version|firmware|build"   # 版本对照 CVE 库

# Ghidra：原始二进制导入 → 识别架构（ARM/ARC/MIPS）→ 定位访问控制与密码校验函数
git clone https://github.com/firmadyne/firmadyne.git && cd firmadyne && ./setup.sh
./run.sh -i firmware.bin -q
```

### 3. Ladder Logic 安全审查

```python
import snap7
plc = snap7.client.Client()
plc.connect('192.168.1.100', 0, 2)          # IP, rack, slot
db_data = plc.db_read(1, 0, 100)            # DB1, 偏移 0, 长度 100
print(f"DB1 Data: {db_data}")
print(f"CPU Info: {plc.get_cpu_info().ModuleTypeName}")
print(f"Protection: {plc.get_protection()}")
print(f"CPU State: {plc.get_cpu_state()}")
plc.disconnect()
```

审计清单：✅ 是否使用安全功能块（如西门子 Safety Matrix）｜✅ 紧急停止逻辑是否硬件触发｜✅ 关键输出是否有互锁条件｜❌ 是否存在可远程触发的危险操作｜❌ 是否存在未保护的在线修改通道。

### 4. 物理接口攻击面

| 接口类型 | 攻击面 | 防护 |
|:---|:---|:---|
| Ethernet | Modbus/DNP3 未认证 | 网络隔离 |
| Serial(RS232) | 控制台访问 | 物理锁 |
| USB 端口 | 固件上传/逻辑注入 | 禁用 |
| SD 卡槽 | 固件替换 | 密封 |
| 调试接口(JTAG) | 固件提取/逆向 | 禁用 JTAG |
| 数字 I/O | 物理信号注入 | 光隔离 |
| 拨码开关 | 配置篡改 | 密封保护 |

### 5. 常见 PLC 漏洞速查

| 漏洞类型 | 受影响 PLC | CVE | CVSS |
|:---|:---|:---:|:---:|
| 硬编码凭证 | Allen-Bradley ControlLogix | CVE-2020-6995 | 9.8 |
| 拒绝服务 | Siemens S7-1200 | CVE-2021-31800 | 7.5 |
| 认证绕过 | Schneider Modicon | CVE-2021-22776 | 8.1 |
| 远程代码执行 | Rockwell MicroLogix | CVE-2020-6994 | 9.8 |
| 信息泄露 | Omron NJ/NX | CVE-2021-27504 | 5.3 |
| 逻辑篡改 | Mitsubishi MELSEC | CVE-2020-16862 | 7.5 |
| 固件降级 | Delta DVP | CVE-2021-22818 | 6.5 |

## 三、工控网络协议安全

### 1. 协议安全特性对比

| 协议 | 默认端口 | 加密 | 认证 | 适用场景 |
|:---|:---:|:---:|:---:|:---|
| Modbus TCP | 502 | ❌ | ❌ | SCADA/PLC 通用 |
| DNP3 | 20000 | 可选 | SAv5 | 电力/能源 |
| S7comm | 102 | ❌ | 弱 | Siemens PLC |
| EtherNet/IP | 44818 | 可选 | 可选 | Allen-Bradley |
| PROFINET | 34964 | ❌ | ❌ | Siemens/Schneider |
| OPC UA | 4840 | ✅ | ✅ | 工控数据交换 |
| MQTT | 1883 | 可选 | 可选 | IoT/传感器 |

### 2. Modbus / DNP3

Modbus 三大弱点：无认证（任意客户端可读写）、无加密（明文）、无完整性校验（可被中间人篡改）。危险功能码：05 写单线圈、06 写单寄存器、15 写多线圈、16 写多寄存器。

```python
# Scapy 构造 Modbus TCP 包（仅在授权环境）
from scapy.all import *
def send_modbus_cmd(target, unit_id, func_code, data):
    transaction_id = 1; protocol_id = 0
    length = 2 + len(data)
    modbus_pkt = (
        IP(dst=target) / TCP(sport=RandShort(), dport=502) /
        Raw(load=bytes([transaction_id >> 8, transaction_id & 0xFF,
                        protocol_id >> 8, protocol_id & 0xFF,
                        length >> 8, length & 0xFF,
                        unit_id, func_code]) + data))
    send(modbus_pkt, verbose=False)
# send_modbus_cmd("192.168.1.100", 0, 0x05, b"\x00\xFF")   # 写线圈
```

```bash
# DNP3 SAv5 提供挑战-响应会话认证、HMAC 完整性、时间戳+序列号防重放
tshark -r ics_capture.pcap -Y "dnp3" -T fields -e dnp3.unsolicited -e dnp3.function_code
# 关键功能码：0x02 Write / 0x03 Select / 0x04 Operate / 0x05 Direct Operate（最危险）
#              0x17 Cold Restart / 0x18 Warm Restart
pip install opendnp3     # https://github.com/automatak/dnp3
```

### 3. OPC UA 安全评估

安全策略：Basic128Rsa15、Basic256、Basic256Sha256；消息模式：None、Sign、SignAndEncrypt。

```python
from opcua import Client
client = Client("opc.tcp://192.168.1.100:4840")
try:
    client.connect()                     # 无安全连接成功 = 配置缺陷
    print("[!] 无安全连接成功! 需要启用安全策略")
    objects = client.get_objects_node(); print(f"Objects: {objects}")
    client.disconnect()
except Exception as e:
    print(f"连接失败(预期行为): {e}")

# 正确方式
client.set_security_string("Basic256Sha256,SignAndEncrypt,my_cert.der,my_private_key.pem")
client.connect()
```

工具：OPC UA Expert（<https://www.unified-automation.com/downloads/>）。

### 4. MQTT 安全评估

审计基线：① 用 `mqtts://` 替代 `mqtt://` ② 启用客户端证书 ③ 即便有 TLS 也要用户名/密码 ④ 配置 topic ACL。

```bash
mosquitto_sub -h 192.168.1.100 -t "#" -v                       # 匿名订阅所有 topic
mosquitto_pub -h 192.168.1.100 -t "factory/PLC1/set" -m "STOP" # 未授权发布

git clone https://github.com/akamai/mqtt-pwn.git && cd mqtt-pwn
pip install -r requirements.txt
python mqtt-pwn.py --host 192.168.1.100 --port 1883
```

### 5. 协议加固基准

| 协议 | 风险 | 推荐加固措施 | 紧急程度 |
|:---|:---|:---|:---:|
| Modbus TCP | 无认证/加密 | Modbus/TCP Security (MTS)，或 VPN 隧道 | 🔴 紧急 |
| DNP3 | SAv5 未启用 | 启用 Secure Authentication v5 | 🟠 重要 |
| S7comm | 弱认证 | 启用 PLC 写保护，限制访问 IP | 🔴 紧急 |
| EtherNet/IP | 未加密 | 使用 CIP Security 扩展 | 🟠 重要 |
| PROFINET | 无认证 | 使用 PROFINET Security Class 3 | 🔴 紧急 |
| OPC UA | 安全模式为 None | 强制 SignAndEncrypt | 🟠 重要 |
| MQTT | 无 TLS 匿名连接 | 启用 TLS + 客户端证书 + ACL | 🔴 紧急 |

## 四、IEC 62443 合规审计

### 1. 标准框架与安全等级

| 部分 | 标准编号 | 内容 | 受众 |
|:---|:---|:---|:---|
| Part1 | 62443-1-1 | 术语与概念 | 所有人 |
| Part2 | 62443-2-1 | 工控安全管理体系 | 资产所有者 |
| | 62443-2-4 | 工控服务提供商安全 | 集成商 |
| Part3 | 62443-3-1 | 安全技术 | 所有人 |
| | 62443-3-2 | 安全等级评估(SL) | 资产所有者 |
| | 62443-3-3 | 系统安全要求和等级 | 系统集成商 |
| Part4 | 62443-4-1 | 产品安全开发生命周期 | 供应商 |
| | 62443-4-2 | 组件安全要求 | 供应商 |

SL 0 无特殊要求｜SL 1 防随意违规（无意失误）｜SL 2 防简单手段故意违规｜SL 3 防复杂手段（中等资源）｜SL 4 防高级手段（充足资源）。

### 2. SL 评估矩阵与行业基线

| 后果严重度 | 威胁能力低 | 中等 | 高 | 极高 |
|:---|:---:|:---:|:---:|:---:|
| 灾难性 | SL 2 | SL 3 | SL 4 | SL 4 |
| 严重 | SL 1 | SL 2 | SL 3 | SL 4 |
| 中等 | SL 1 | SL 1 | SL 2 | SL 3 |
| 轻微 | SL 0 | SL 1 | SL 1 | SL 2 |

典型要求：电力 SL 3-4｜水处理 SL 2-3｜制造业 SL 1-2｜楼宇自动化 SL 0-1。

### 3. C2M2 成熟度评估

十个域：资产管理(RM)、威胁与漏洞管理(TVM)、风险管理(RISK)、供应链风险管理(SCRM)、身份与访问管理(IAM)、安全架构(SA)、事件响应(IR)、态势感知(SAW)、培训与意识(TRAINING)、持续改进(CI)。

成熟度等级 MIL 0 未执行 / MIL 1 初始执行 / MIL 2 制度化执行 / MIL 3 量化管理。组织级自评问句：是否建立 OT 资产清单（含型号/固件版本）？是否有 OT 网络安全策略？是否做过工控风险分析？是否有变更管理流程？是否限制 USB/可移动介质？

### 4. 62443-2-1 关键控制优先级

| 控制域 | 控制项 | 优先级 |
|:---|:---|:---:|
| 安全策略 | OT 安全策略文档化 / 年度审查 | P0 / P1 |
| 资产管理 | OT 资产清单 / 资产关键性分级 | P0 / P0 |
| 访问控制 | OT 网络分段 / 远程访问 MFA / 物理安全 | P0 / P0 / P1 |
| 变更管理 | 变更审批流程 / 变更前安全评估 | P0 / P1 |
| 事件管理 | OT 事件响应预案 / OT 应急演练 | P0 / P1 |
| 供应商管理 | 供应商安全评估 / 补丁管理策略 | P1 / P0 |
| 安全意识 | OT 人员专项培训 | P1 |
| 备份恢复 | 工控系统备份 / 恢复演练 | P0 / P1 |

### 5. 合规审计检查清单

| # | 检查项 | IEC 62443 参考 | 验证方法 |
|:---:|:---|:---:|:---|
| 1 | OT 资产是否 100% 纳入清单 | 62443-2-1 | 资产扫描 + 人工核对 |
| 2 | OT 网络是否有拓扑图 | 62443-3-3 | 审查文档 |
| 3 | OT 与 IT 网络是否有效隔离 | 62443-3-3 | 渗透测试 |
| 4 | PLC/HMI 是否修改默认密码 | 62443-4-2 | 现场检查 |
| 5 | 是否禁用不必要的物理接口 | 62443-4-2 | 现场检查 |
| 6 | 固件是否更新至安全版本 | 62443-4-1 | 固件版本核查 |
| 7 | 是否存在远程访问控制策略 | 62443-2-1 | 审查策略 + 审计日志 |
| 8 | 是否有 OT 安全事件响应计划 | 62443-2-1 | 审查文档 + 演练记录 |
| 9 | 是否定期进行安全评估 | 62443-2-1 | 审查评估报告 |
| 10 | 供应商是否提供安全开发生命周期 | 62443-4-1 | 供应商认证审查 |

## 五、工控安全应急预案（ICS Incident Response）

### 1. OT 事件检测指标（分层 IoC）

| 检测层 | 具体指标 | 工具 |
|:---|:---|:---|
| 网络层 | 异常 Modbus/DNP3 功能码、向 PLC 的未授权写入、异常协议流量模式 | Wireshark、Zeek、Nozomi |
| 主机层 | 工程站恶意软件、异常进程/计划任务 | AV+EDR、Sysmon |
| 物理层 | PLC LED 异常闪烁、HMI 显示异常 | 人工巡检 |
| PLC 内部 | Ladder Logic 被篡改、程序校验和不匹配 | 固件校验、PLC 诊断 |
| 应用层 | HMI/SCADA 告警被静音、历史数据缺失 | 日志审计、数据库检查 |

### 2. 六阶段响应流程

1. **识别与分类（5 分钟）**：OT 事件 vs IT 事件；影响范围单台 PLC vs 整条产线；安全影响是生产安全还是数据安全。
2. **遏制（15 分钟）**：⚠️ 先确认「断开网络 vs 确保生产安全」；网络隔离切断受影响 OT 网段；**不要直接关闭 PLC（可能物理损坏）**；切换到手动/旁路模式。
3. **取证（1-4 小时）**：镜像 PLC 固件与配置、捕获 PCAP、收集 HMI/历史库日志、记录 PLC LED 物理状态。
4. **根因分析（4-24 小时）**：定位攻击入口点、复现攻击路径、确定受影响资产。
5. **恢复（按业务需求）**：从已验证备份恢复 PLC 程序、更新固件补丁、改默认密码、逐步恢复生产。
6. **复盘与改进（1 周内）**：事件复盘报告、改进安全控制、更新应急预案。

### 3. 取证与 YARA

```bash
tshark -r ics_incident.pcap -Y "modbus.func_code == 5 || modbus.func_code == 6 || modbus.func_code == 15 || modbus.func_code == 16" \
  -T fields -e ip.src -e ip.dst -e modbus.func_code -e modbus.reference_num -e modbus.data
tshark -r ics_incident.pcap -Y "s7comm" -T fields -e s7comm.param.func -e s7comm.param.item_count
tshark -r ics_incident.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields -e ip.src -e ip.dst -e tcp.dstport | grep -v "102\|502\|20000"
# PLC 程序校验：Siemens S7 比对备份；Allen-Bradley 用 RSLogix 校验 CRC
```

```yara
rule OT_Malicious_Modbus {
    meta:
        description = "检测已知OT恶意软件签名"
    strings:
        $modbus_cmds = { 05 00 FF 00 06 00 01 00 0F 00 10 }
        $stuxnet_str = "Stuxnet" nocase
        $trisis_str  = "TRISIS" nocase
        $industroyer = "Industroyer" nocase
    condition:
        any of them
}
```

```bash
yara -r ot_malware.yar /evidence/
```

### 4. 历史 OT 攻击响应参考

| 攻击 | 目标 | 响应要点 |
|:---|:---|:---|
| Stuxnet (2010) | 伊朗核离心机 | 检查 PLC 逻辑 + 固件完整性 |
| TRISIS (2017) | Schneider Triconex SIS | 隔离 SIS 系统，物理检查，验证安全仪表系统未被篡改 |
| Industroyer (2016) | 乌克兰电力网 | 切断所有外部连接，手动切换变电站操作 |
| Colonial Pipeline (2021) | 美国燃油管道 | 关闭关键管道系统，启用离线备份系统 |
| Pipedream (2022) | 多供应商 PLC | 识别受影响设备型号，应用厂商安全公告 |

### 5. 应急准备检查清单

| # | 应急准备项 | 责任人 | 频次 |
|:---:|:---|:---:|:---:|
| 1 | OT 资产清单（含网络拓扑）是否最新 | OT 运维 | 每月 |
| 2 | PLC/HMI 程序备份是否有效 | OT 工程师 | 每周 |
| 3 | OT 应急联系人名单是否更新 | 安全经理 | 每季 |
| 4 | OT 安全演练是否执行 | 联合团队 | 每半年 |
| 5 | 物理旁路/手动操作是否可用 | 操作员 | 每次启动前 |
| 6 | OT 监控系统是否覆盖所有网段 | 安全团队 | 部署时 |
| 7 | 是否有防爆区域的取证预案 | 安全+HSE | 年度 |
| 8 | 供应商应急联系方式是否有效 | 采购 | 年度 |

## 六、工业防火墙与网络分段

### 1. Purdue 企业参考架构（PERA）

| 等级 | 内容 |
|:---:|:---|
| 5 | 企业网络：Email, Web, ERP |
| 4 | 数据中心（DMZ）：补丁服务器, 远程访问网关, 历史数据库 |
| 3 | 制造运营管理（MOM）：MES, 生产调度, 质量系统 |
| 2 | 过程控制：SCADA, HMI, 工程师站 |
| 1 | 基本控制：PLC, RTU, DCS, 远程 I/O |
| 0 | 物理过程：传感器, 执行器, 电机, 阀门 |

安全要求：等级 3-5 以 IT 安全策略为主；等级 0-2 用 OT 安全策略（**可用性 > 完整性 > 机密性**）；跨等级通信必须通过工业防火墙；DMZ 实施双向访问控制。

### 2. 工业防火墙部署

```bash
# 规则方向：WAN→OT 全部阻止（仅特定 VPN）；OT→WAN 仅特定补丁服务器；DMZ→OT 仅必要端口白名单
iptables -A FORWARD -i eth0 -o eth1 -s 192.168.10.0/24 -d 192.168.100.0/24 -p tcp --dport 102 -j ACCEPT  # Siemens S7
iptables -A FORWARD -i eth0 -o eth1 -s 192.168.10.0/24 -d 192.168.100.0/24 -p tcp --dport 502 -j ACCEPT  # Modbus
iptables -A FORWARD -i eth0 -o eth1 -j DROP                                                              # 默认拒绝

# Tofino (Hirschmann) 规则示例
# 规则1: 允许工程站->PLC (S7 TCP 102)，源 10.10.1.0/24，目标 10.10.2.100，动作 允许+告警
# 规则2: 允许 HMI->PLC 读操作（Modbus 功能码 01,02,03,04）
# 规则3: 拒绝 HMI->PLC 写操作（Modbus 功能码 05,06,15,16）
```

### 3. IEC 62443 安全区与管道

```yaml
安全区 1: "S1-控制区"
  描述: 关键生产线PLC和HMI
  安全等级: SL 3
  元素: [PLC_PRODUCT_LINE_1, PLC_PRODUCT_LINE_2, HMI_LINE_1, HMI_LINE_2]
安全区 2: "S2-工程区"
  安全等级: SL 2
  元素: [ENG_WORKSTATION_1, ENG_WORKSTATION_2, GIT_SERVER]
安全区 3: "DMZ区"
  安全等级: SL 1
  元素: [PATCH_SERVER, HISTORIAN_SERVER]

Conduit 1: "C1-工程访问"
  源区: S2-工程区 ; 目标区: S1-控制区
  协议白名单: [S7 (TCP 102), Modbus (TCP 502)]
  安全要求: [源IP白名单, 深度包检测(DPI), 会话日志]
Conduit 2: "C2-数据采集"
  源区: S1-控制区 ; 目标区: S3-DMZ
  协议白名单: [OPC UA (TCP 4840), MQTT (TCP 8883)]
  安全要求: [单向数据流 (Read Only), TLS加密]
```

### 4. 工业协议深度包检测

```bash
# 仅放行 Modbus 读功能码 01-04，拒绝写操作
iptables -A FORWARD -p tcp --dport 502 -m u32 --u32 "0>>22&0x3C@8=0x1" -j ACCEPT
iptables -A FORWARD -p tcp --dport 502 -m u32 --u32 "0>>22&0x3C@8=0x2" -j ACCEPT
iptables -A FORWARD -p tcp --dport 502 -m u32 --u32 "0>>22&0x3C@8=0x3" -j ACCEPT
iptables -A FORWARD -p tcp --dport 502 -m u32 --u32 "0>>22&0x3C@8=0x4" -j ACCEPT
iptables -A FORWARD -p tcp --dport 502 -j DROP
```

```
alert tcp any any -> $OT_NET 502 (
  msg:"Modbus尝试写入操作";
  content:"|00 00 00 00 00 05 01 05|";
  classtype:attempted-recon;
  sid:1000001;
)
```

### 5. OT 网络分段成熟度

| 等级 | 描述 | 特征 | 安全级别 |
|:---:|:---|:---|:---:|
| 0 | 无分段 | PLC 直接连公司网 | ❌ 极其危险 |
| 1 | 基本防火墙 | IT/OT 间有防火墙，控制层无分段 | ⚠️ 基本 |
| 2 | 基于 Purdue 的分段 | 每层之间有防火墙 | ✅ 推荐 |
| 3 | 应用层控制 | 工业协议 DPI + 功能码过滤 | ✅ 增强 |
| 4 | 零信任分段 | 所有 PLC 间通信也受控 | 🏆 最佳 |

## 七、常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| PLCScan | PLC 设备扫描 | https://github.com/neohapsis/PLCScan |
| Modbus CLI | Modbus 协议测试 | https://github.com/tallakt/modbus-cli |
| ISF (ICS Exploitation Framework) | 工控漏洞利用框架 | https://github.com/dark-labs/ISF |
| python-snap7 | S7 协议客户端 | https://github.com/gijzelaerr/python-snap7 |
| Binwalk | 固件分析 | https://github.com/ReFirmLabs/binwalk |
| Firmadyne | 固件仿真 | https://github.com/firmadyne/firmadyne |
| OpenPLC | PLC 测试平台 | https://www.openplcproject.com/ |
| Wireshark | 工控协议分析 | https://www.wireshark.org/ |
| Scapy | 协议包构造 | https://scapy.net/ |
| MQTT PWN | MQTT 安全测试 | https://github.com/akamai/mqtt-pwn |
| OPC UA Expert | OPC UA 客户端调试 | https://www.unified-automation.com/ |
| PLCinject | PLC 逻辑注入 | https://github.com/0x0mar/PLCinject |
| C2M2 Self-Assessment | 工控安全成熟度自评 | https://www.energy.gov/ceser/c2m2 |
| CSET (CISA) | 工控安全评估工具 | https://github.com/cisagov/cset |
| Dragos Platform | OT 威胁检测与响应 | https://www.dragos.com/ |
| Claroty | OT 安全与资产可见性 | https://claroty.com/ |
| Nozomi Guardian | OT 网络监控 | https://www.nozominetworks.com/ |
| Tofino Xenon Security | 工业防火墙 | https://www.hirschmann.com/ |
| pfSense | 开源防火墙 | https://www.pfsense.org/ |
| Snort/Suricata | 工控 IDS | https://suricata.io/ |
| YARA | OT 恶意软件检测 | https://virustotal.github.io/yara/ |

## 八、参考资源

- [IEC 62443 Series](https://www.iec.ch/standards/62443)
- [NIST SP 800-82 Rev.3 — Guide to ICS Security](https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final)
- [ICS-CERT Advisories](https://www.cisa.gov/ics)
- [CISA — ICS Incident Response](https://www.cisa.gov/ics-incident-response)
- [NIST SP 800-61 Rev.2 — Incident Response](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/techniques/ics/)
- [SANS ICS Security Resources](https://www.sans.org/ics-security/)
- [Kaspersky ICS CERT](https://ics-cert.kaspersky.com/)
- [Dragos ICS Vulnerability Database](https://www.dragos.com/vulnerability-database/)

## 九、上游原文（references/）

| 上游文件 | 本包路径 |
|:---|:---|
| `README.md`（分类导读与技能清单） | `references/README.md` |
| `skills/SCADA系统安全评估-SCADASecurityAssessment.md` | `references/SCADA系统安全评估-SCADASecurityAssessment.md` |
| `skills/PLC与RTU安全测试-PLC-RTU-SecurityTesting.md` | `references/PLC与RTU安全测试-PLC-RTU-SecurityTesting.md` |
| `skills/工控网络协议安全-ICS-NetworkProtocolSecurity.md` | `references/工控网络协议安全-ICS-NetworkProtocolSecurity.md` |
| `skills/工控安全合规审计-IEC62443-Audit.md` | `references/工控安全合规审计-IEC62443-Audit.md` |
| `skills/工控安全应急预案-ICS-IncidentResponse.md` | `references/工控安全应急预案-ICS-IncidentResponse.md` |
| `skills/工业防火墙与网络分段-Industrial-Firewall-Segmentation.md` | `references/工业防火墙与网络分段-Industrial-Firewall-Segmentation.md` |
