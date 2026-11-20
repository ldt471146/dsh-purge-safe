---
name: hfh-iot-security
description: 网络安全知识库「物联网安全」分类技能包，源自 Hi-FullHouse/CyberSecurity-Skills 上游 21-物联网安全-IoT-Security。覆盖固件逆向与分析（Binwalk 提取与熵分析、Firmadyne/QEMU 仿真、硬编码凭证与私钥/调试接口扫描、Ghidra 定位后门、固件安全基线）、BLE/Zigbee/Z-Wave 无线协议测试（gatttool/BlueZ 服务枚举、Ubertooth/BTLEJack 嗅探、KillerBee/z3sec 抓包与密钥提取、S0 与 S2 差异、协议安全对比与防护优先级）、IoT 通信协议安全（MQTT pwn/MQTTSA 扫描、mosquitto ACL 与 TLS 配置、CoAP 资源发现、LoRaWAN OTAA 与帧计数、八种协议安全等级对比、通信安全基线十项）、嵌入式硬件安全（JTAG/SWD 引脚与 OpenOCD 读写 Flash、UART 波特率枚举与 Bootloader 进入、SPI/I2C、ChipWhisperer SPA/DPA 侧信道、八项硬件加固措施）、IoT 云平台安全（AWS IoT 证书与最小权限策略、Azure IoT Hub SAS 与 IP 过滤、X.509 设备身份全流程、OTA 签名验证）以及智能家居与车联网安全（智能家居攻击面与 UPnP/mDNS、Matter DAC/CASE/ACL 检查清单、SocketCAN 与 can-utils、ICSim 模拟、OBD-II 蓝牙/WiFi 风险、车联网八项基线），含 7 份中文原文 references。
---

# 物联网安全（IoT Security）

本技能覆盖 IoT 设备的**授权**安全评估全生命周期：芯片/接口 → 固件 → 无线协议 → 通信协议 → 云平台 → 应用生态（智能家居、车联网）。评估时按这条链路自底向上推进，任何一层失守都可能导致设备被完全接管。

关键工具：Binwalk、Firmadyne、QEMU、Ghidra、Firmwalker、JTAGulator、OpenOCD、Saleae Logic、Bus Pirate、ChipWhisperer、gatttool/BlueZ、Ubertooth、BTLEJack、KillerBee、z3sec、HackRF、MQTT PWN、MQTTSA、aiocoap、can-utils、ICSim、AWS/Azure CLI。硬件层操作需注意电压与静电，仿真固件应放在隔离网段运行。

## 一、固件逆向与分析

### 1. 提取与仿真

```bash
binwalk firmware.bin              # 扫描文件签名
binwalk -Me firmware.bin          # 递归解包
binwalk -D 'png:raw' firmware.bin # 提取特定类型
binwalk -B firmware.bin           # 字节熵分析
binwalk -A firmware.bin           # CPU 架构识别
binwalk -W firmware.bin           # 文件类型统计

git clone https://github.com/firmadyne/firmadyne.git && cd firmadyne && ./setup.sh
./scripts/extract.sh firmware.bin <firmware-id>
./scripts/makeNetwork.py -i <firmware-id>
./scripts/run.sh <firmware-id>
```

```bash
# QEMU 全系统仿真
qemu-system-arm  -M virt  -kernel vmlinuz  -initrd initrd.img -append "console=ttyAMA0" -nographic
qemu-system-mips -M malta -kernel vmlinux  -initrd initrd.img -append "console=ttyS0"   -nographic
```

### 2. 漏洞与后门分析

```bash
grep -r "password" extracted_fs/
grep -r "secret" extracted_fs/
grep -rP "[A-Za-z0-9+/]{20,}={0,2}" extracted_fs/           # Base64 疑似密钥
grep -r "http" extracted_fs/ | grep -v "http_parser\|mhttpd\|libhttp"   # 后端 URL/API
find extracted_fs/ -name "*.pem" -o -name "*.key" -o -name "*.cert" -o -name "*.p12"
grep -r "debug\|telnet\|gdb\|gdbserver" extracted_fs/        # 调试接口
find extracted_fs/ -name "*.conf" -o -name "*.cfg" -o -name "*.ini"
ls extracted_fs/etc/init.d/ ; cat extracted_fs/etc/inittab
grep -r "session\|token\|secret" extracted_fs/www/           # Web 硬编码会话密钥
```

Ghidra 深度逆向：导入固件并选 CPU 架构 → 定位 entry → 分析密码验证逻辑 → 查后门函数。

### 3. 固件安全基线

| # | 检查项 | 严重程度 | 修复建议 |
|:---:|:---|:---:|:---|
| 1 | 硬编码凭证（密码/令牌） | 🔴 严重 | 移除硬编码，改用配置或 HSM |
| 2 | 未加密固件存储 | 🟠 高危 | 固件加密存储 + 签名验证 |
| 3 | 调试接口（GDB/telnet）开放 | 🔴 严重 | 生产固件禁用调试接口 |
| 4 | 嵌入式私钥/证书 | 🟠 高危 | 使用 TPM/SE 存储私钥 |
| 5 | 硬编码 API 端点/密钥 | 🟠 高危 | 通过 OTA 更新配置 |
| 6 | 未签名固件更新 | 🔴 严重 | 实现固件签名 + 验证 |
| 7 | 敏感信息在日志中 | 🟡 中危 | 日志过滤敏感信息 |
| 8 | 缓冲区溢出漏洞 | 🔴 严重 | 使用安全编译选项（-fstack-protector） |

## 二、BLE / Zigbee / Z-Wave 无线安全测试

### 1. BLE

```bash
pip install bleson bluepy
sudo hcitool lescan                  # 扫描
sudo python3 -m blescan              # BLEAH 扫描

gatttool -b <MAC> -t random -I
# [CONNECTED] > primary          # 列出主服务
#             characteristics    # 列出特征值
gatttool -b <MAC> -t random --char-read -a 0x0003   # 读取未保护特征

bluetoothctl
# scan on / devices / connect <MAC> / menu gatt / list-attributes / select-attribute <handle>

ubertooth-btle -f -c capture.pcap    # Ubertooth 嗅探
wireshark -r capture.pcap

git clone https://github.com/virtualabs/btlejack.git && cd btlejack
pip install -r requirements.txt
sudo btlejack -s                                   # 扫描连接
sudo btlejack -f -c <access_address> -d            # 嗅探连接
```

### 2. Zigbee（2.4GHz / 915MHz / 868MHz，AES-128-CCM，Trust Center 分发网络密钥）

```bash
git clone https://github.com/attify/z3sec.git && cd z3sec
pip install -r requirements.txt
python z3sec.py -sniff -c 11 -o capture.pcap
python z3sec.py -extract-keys -c capture.pcap

git clone https://github.com/riverloopsec/killerbee.git && cd killerbee
pip install -r requirements.txt
sudo zbid                       # 适配器扫描
sudo zbstumbler -c 11           # 网络发现
sudo zbdump -c 11 -w zigbee_capture.pcap
zbreplay -f zigbee_capture.pcap -l | grep -i "key\|password\|token"
```

检查是否使用默认网络密钥：ZLL（Zigbee Light Link）为全零，HA（Home Automation）常为厂商自定义。

### 3. Z-Wave（908.42MHz US / 868.42MHz EU，Mesh 拓扑）

S0 为单钥匙加密、节点间共享；S2 为双向认证、每节点单独密钥。S0 攻击路径：捕获网络包含过程 → 提取网络密钥（支持 TrueZT）→ 解密全部通信。

```bash
hackrf_transfer -r zwave_capture.iq -f 908420000 -s 2000000   # HackRF 捕获
# 之后用 GnuRadio 做 Z-Wave 解调
```

### 4. 无线协议安全对比

| 特性 | BLE | Zigbee | Z-Wave | Wi-Fi (IoT) |
|:---|:---:|:---:|:---:|:---:|
| 加密 | AES-128-CCM | AES-128-CCM | AES-128-GCM/S0/S2 | WPA2/WPA3 |
| 认证 | Pairing Bonding | Trust Center | S2 认证 | WPA-PSK/EAP |
| 默认安全等级 | 低（Join Without Auth） | 中（Network Key） | 中(S0) → 高(S2) | 高（WPA3） |
| 已知攻击 | MITM, Eavesdrop | Key Extraction | Key Extraction | 暴力破解 |
| 配对安全 | Just Works（弱） | Out-of-Band | PIN 输入 | QR/按钮 |
| 嗅探距离 | ~100m | ~100m | ~100m | ~300m |
| 重放防护 | 随机地址 | Frame Counter | Nonce | 802.11w |

### 5. 防护建议优先级

| 攻击类型 | 防护建议 | 优先级 |
|:---|:---|:---:|
| BLE Just Works 配对劫持 | 使用 OOB 或 Passkey Entry 配对 | 🔴 紧急 |
| Zigbee 默认网络密钥 | 改为随机生成的网络密钥 | 🔴 紧急 |
| Z-Wave S0 密钥提取 | 升级支持 S2 的设备 | 🟠 重要 |
| Sniffing 嗅探 | 所有无线通信必须 AES-128 加密 | 🔴 紧急 |
| Replay 重放攻击 | 使用 nonce/frame counter | 🔴 紧急 |
| Deauth 攻击 | 使用 802.11w 管理帧保护（Wi-Fi） | 🟡 推荐 |

## 三、物联网通信协议安全

### 1. MQTT

```bash
git clone https://github.com/akamai/mqtt-pwn.git && cd mqtt-pwn
pip install -r requirements.txt
python mqtt-pwn.py --host 192.168.1.100 --scan     # 端口、TLS、匿名访问

mosquitto_sub -h 192.168.1.100 -t "#" -v           # 订阅所有主题
mosquitto_sub -h 192.168.1.100 -t "$SYS/#" -v      # 系统主题

git clone https://github.com/akamai/MQTTSA.git && cd MQTTSA
pip install -r requirements.txt
python MQTTSA.py --host 192.168.1.100 --port 1883
```

安全基线：① `allow_anonymous false` ② 启用 TLS（listener 8883）③ 配置 ACL ④ 禁止外部访问 `$SYS` 主题 ⑤ 客户端 ID 白名单 ⑥ 持久会话限制。

```
# mosquitto.acl
user sensor01
topic read sensors/+/temperature
topic write sensors/sensor01/status

user admin
topic readwrite #
topic read $SYS/#

pattern read sensors/%u/#
pattern write sensors/%u/status
```

```
# mosquitto.conf
listener 1883 127.0.0.1
listener 8883
certfile /etc/mosquitto/certs/server.crt
keyfile /etc/mosquitto/certs/server.key
cafile /etc/mosquitto/certs/ca.crt
tls_version tlsv1.2

allow_anonymous false
password_file /etc/mosquitto/passwd
acl_file /etc/mosquitto/acl

max_connections 1000
persistent_client_expiration 14d
```

### 2. CoAP（UDP 5683 明文 / 5684 DTLS）

```bash
pip install aiocoap
aiocoap-client coap://192.168.1.100/.well-known/core
```

```python
import asyncio
from aiocoap import *
async def discover():
    protocol = await Context.create_client_context()
    request = Message(code=GET, uri='coap://192.168.1.100/.well-known/core')
    response = await protocol.request(request).response
    print(f"发现资源: {response.payload.decode()}")
asyncio.run(discover())
```

安全基线：使用 DTLS（coaps://）、启用访问控制、限制资源发现、避免敏感信息出现在 URI、实施速率限制。

### 3. LoRaWAN

两层密钥：NwkSKey（网络层）与 AppSKey（应用层）。检查项：OTAA（推荐，更安全）vs ABP（密钥静态，不推荐）、Join-EUI/Dev-EUI、AppKey 生成方式、帧计数器（Frame Counter）。

基线：✅ OTAA 激活｜✅ 随机生成的 AppKey（≥ 16 字节）｜✅ 启用帧计数器验证｜✅ 使用加密自适应数据速率 ADR｜❌ 避免 ABP｜❌ 避免默认 AppKey。

### 4. 协议安全对比

| 协议 | 传输层 | 加密 | 认证 | 默认端口 | 安全等级 |
|:---|:---:|:---:|:---:|:---:|:---:|
| MQTT 3.1.1 | TCP | TLS | Username/Password, Cert | 1883/8883 | ⭐⭐⭐ |
| MQTT 5.0 | TCP | TLS+ | Enhanced Auth | 1883/8883 | ⭐⭐⭐⭐ |
| CoAP | UDP | DTLS | PSK, Cert | 5683/5684 | ⭐⭐⭐ |
| HTTP/2 | TCP | TLS | OAuth, JWT | 443 | ⭐⭐⭐⭐ |
| AMQP | TCP | TLS | SASL, X.509 | 5671/5672 | ⭐⭐⭐⭐ |
| LoRaWAN | LoRa | AES-128 | AppKey | N/A | ⭐⭐⭐ |
| Zigbee | 802.15.4 | AES-128-CCM | Trust Center | N/A | ⭐⭐⭐ |
| Thread | 6LoWPAN | AES-128-CCM | DTLS | N/A | ⭐⭐⭐⭐ |

### 5. 通信安全基线清单

| # | 检查项 | 严重程度 | 验证方法 |
|:---:|:---|:---:|:---|
| 1 | MQTT 匿名访问是否禁用 | 🔴 严重 | 尝试无密码连接 |
| 2 | TLS 是否启用 | 🔴 严重 | 尝试非加密连接 |
| 3 | 默认凭证是否修改 | 🔴 严重 | 尝试 admin/admin |
| 4 | MQTT ACL 是否配置 | 🟠 高危 | 尝试订阅受限主题 |
| 5 | CoAP 资源发现是否限制 | 🟠 高危 | 请求 .well-known/core |
| 6 | MQTT $SYS 主题是否保护 | 🟠 高危 | 尝试订阅 $SYS |
| 7 | 客户端 ID 是否验证 | 🟡 中危 | 使用伪造 client ID |
| 8 | 帧计数器是否启用 | 🟠 高危 | 发送重放消息 |
| 9 | 会话超时是否配置 | 🟡 中危 | 检查配置 |
| 10 | 速率限制是否启用 | 🟡 中危 | 压力测试 |

## 四、嵌入式设备硬件安全

### 1. 调试接口与引脚

| 接口 | 电压 | 协议 | 用途 |
|:---|:---:|:---|:---|
| JTAG | 3.3V | IEEE 1149.1 | CPU 调试/编程 |
| SWD | 3.3V | ARM Serial Wire | ARM 调试 |
| UART | 3.3V | 串行（115200,8N1） | 控制台/Bootloader |
| SPI | 3.3V | 同步串行 | Flash/传感器 |
| I2C | 3.3V | I2C 总线 | 传感器/EEPROM |
| USB | 5V | USB 2.0/3.0 | 固件更新/数据 |

JTAG 引脚常见色序：1 VREF（红/橙）｜2 GND（黑）｜3 TMS/SWDIO（黄）｜4 TCK/SWCLK（蓝）｜5 TDO/SWO（绿）｜6 TDI（紫）｜7-20 GND（黑）。

### 2. JTAG / SWD 测试

```
screen /dev/ttyUSB0 115200      # 连接 JTAGulator
# 菜单流程：选电压 3.3V → IDCODE 扫描识别 TAP → BYPASS 扫描确认 TCK → Pin 映射
```

```
# openocd.cfg
source [find interface/jlink.cfg]
transport select jtag
source [find target/stm32f4x.cfg]

# JTAG 安全操作：halt CPU → 读 Flash → 读 option bytes → 解除 Flash 读保护
```

```bash
openocd -f openocd.cfg
telnet localhost 4444
# halt
# flash read_bank 0 firmware.bin
# flash protect 0 0 0 off
# flash erase_address 0x08000000 0x10000
```

### 3. UART 串口攻击

用逻辑分析仪（Saleae Logic，采样率 ≥ 1MHz，触发 UART 起始位）识别引脚；或用 Bus Pirate：`m` 选模式 → `3` UART → `115200` 波特率 → `8` 数据位 → `1` 停止位 → `n` 无校验 → `(3)` 接收。

```bash
for baud in 9600 19200 38400 57600 115200 230400 460800 921600; do
    stty -F /dev/ttyUSB0 $baud cs8 -cstopb -parenb
    echo -n "$baud: "
    timeout 1 cat /dev/ttyUSB0 2>/dev/null
    echo
done
```

进入 Bootloader：通常上电时按住某按键，或发送特定 break 信号；随后用 xmodem/ymodem 或 UART console 导出固件。

### 4. 侧信道分析（ChipWhisperer）

```python
import chipwhisperer as cw
scope = cw.scope()
target = cw.target(scope, cw.targets.SimpleSerial)

scope.adc.samples = 10000
scope.clock.clkgen_freq = 7.37e6
scope.trigger.triggers = "tio4"

target.simpleserial_write('k', key)
target.simpleserial_write('p', plaintext)
scope.capture()
trace = scope.adc.read()

# DPA：多次采集
traces = []
for i in range(1000):
    plaintext = random_bytes(16)
    target.simpleserial_write('p', plaintext)
    scope.capture()
    traces.append(scope.adc.read())
```

电磁攻击需电磁探头 + 放大器，配示波器或 ADC 采集。

### 5. 硬件加固基线

| # | 防护措施 | 效果 | 实施难度 |
|:---:|:---|:---:|:---:|
| 1 | JTAG/SWD 熔丝编程（读保护） | ✅ 禁止调试接口读 Flash | 低（烧录时设置） |
| 2 | Flash 加密存储 | ✅ 读出也无法解析 | 中（需 BootROM 支持） |
| 3 | 禁用 UART 控制台 | ✅ 防止串口入侵 | 低（kernel config） |
| 4 | 移除调试焊盘 | ✅ 物理防护 | 高（PCB 改版） |
| 5 | 防篡改检测 | ✅ 开盖即擦除密钥 | 高（硬件设计） |
| 6 | BGA 封装（替代 QFP） | ✅ 增加探测难度 | 高（制造成本） |
| 7 | 环氧树脂封装 | ✅ 保护芯片/走线 | 中（生产工序） |
| 8 | Secure Boot | ✅ 验证启动代码 | 中（需 ROM 支持） |

## 五、物联网平台与云安全

### 1. AWS IoT Core

```bash
aws iot list-ca-certificates
aws iot list-certificates
aws iot list-policies
aws iot list-policies --query 'policies[*].policyName'
aws iot get-policy --policy-name <policy-name>
aws iot get-policy --policy-name <policy-name> --query 'policyDocument'
aws iot get-topic-rule --rule-name <rule-name>
```

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": ["iot:Connect"],
      "Resource": ["arn:aws:iot:us-east-1:123456789:client/${iot:ClientId}"],
      "Condition": { "Bool": { "iot:Connection.Thing.IsAttached": ["true"] } } },
    { "Effect": "Allow", "Action": ["iot:Publish", "iot:Receive"],
      "Resource": ["arn:aws:iot:us-east-1:123456789:topic/${iot:ClientId}/telemetry"] },
    { "Effect": "Allow", "Action": ["iot:Subscribe"],
      "Resource": ["arn:aws:iot:us-east-1:123456789:topicfilter/${iot:ClientId}/commands"] }
  ]
}
```

IoT Core 仅支持 TLS 1.2+，密码套件为 ECDHE 系列（前向保密）。

### 2. Azure IoT Hub

```bash
az iot hub show --name <hub-name> --query "sku"
az iot hub show --name <hub-name> --query "properties.eventHubEndpoints"
az iot hub show --name <hub-name> --query "properties.ipFilterRules"
az iot hub route list --hub-name <hub-name>
az iot hub device-identity list --hub-name <hub-name> --query "[].{deviceId:deviceId, auth:authentication}"
az iot hub device-twin show --device-id <device-id> --hub-name <hub-name>
az network private-endpoint list --query "[?contains(??,'Microsoft.Devices/IotHubs')]"
```

基线：✅ 使用 SAS 令牌（而非连接字符串）｜✅ 启用 TLS 1.2｜✅ 使用设备预配服务 DPS｜✅ 使用 IP 过滤器｜✅ 启用诊断日志｜❌ 避免共享访问策略的完全控制权限。

### 3. X.509 设备身份全流程

```bash
openssl genrsa -out ca-key.pem 2048
openssl req -x509 -new -nodes -key ca-key.pem -sha256 -days 3650 \
  -out ca-cert.pem -subj "/C=CN/CN=MyIoTCA"
aws iot register-ca-certificate \
  --ca-certificate file://ca-cert.pem \
  --verification-certificate file://verification-cert.pem --set-as-active

openssl genrsa -out device-key.pem 2048
openssl req -new -key device-key.pem -out device-csr.pem -subj "/C=CN/CN=device-01"
openssl x509 -req -in device-csr.pem -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out device-cert.pem -days 365 -sha256

aws iot register-certificate-without-ca --certificate-pem file://device-cert.pem --status ACTIVE
aws iot attach-policy --policy-name "IoTDevicePolicy" \
  --target "arn:aws:iot:region:account:cert/<cert-id>"
```

### 4. OTA 更新安全

```bash
openssl dgst -sha256 -sign private-key.pem -out firmware.bin.sig firmware.bin

aws iot create-job \
  --job-id "firmware-v2.0.1" \
  --targets "arn:aws:iot:region:account:thing/device-01" \
  --document file://ota-document.json \
  --description "安全OTA更新 v2.0.1"
```

```json
{
  "url": "https://s3.amazonaws.com/ota-bucket/firmware-v2.0.1.bin",
  "version": "2.0.1",
  "fileSize": 1048576,
  "hash": "sha256:f123...",
  "signature": "base64-encoded-signature",
  "signatureAlgorithm": "SHA256-RSA"
}
```

设备端流程：下载固件 → 验证哈希 → 验证签名 → 写入 Flash。

### 5. IoT 云安全基线

| # | 检查项 | 严重程度 | 建议 |
|:---:|:---|:---:|:---|
| 1 | IoT 策略仅为通配符（iot:*） | 🔴 严重 | 严格遵守最小权限 |
| 2 | 设备证书未激活/过期 | 🟠 高危 | 建立证书吊销机制 |
| 3 | 设备影子允许修改敏感属性 | 🟠 高危 | 限制影子写入权限 |
| 4 | 规则引擎直接访问数据库 | 🔴 严重 | 使用 IAM 角色限制 |
| 5 | MQTT 主题过于宽泛（#） | 🟠 高危 | 按设备 ID 隔离主题 |
| 6 | 无 TLS 1.2+ 强制 | 🔴 严重 | 仅允许 TLS 1.2+ 连接 |
| 7 | 固件未签名 OTA | 🔴 严重 | 实施代码签名验证 |
| 8 | 无设备预置认证 | 🟠 高危 | 使用 DPS + X.509 |

## 六、智能家居与车联网安全

### 1. 智能家居攻击面

```bash
nmap -sn 192.168.1.0/24          # 发现设备
nmap -sV -T4 -A 192.168.1.50-100 # 服务扫描
sudo arp-scan --local
```

```python
import upnpclient
devices = upnpclient.discover()
for dev in devices:
    print(f"Device: {dev.friendly_name}")
    print(f"  Services: {[s.name for s in dev.services]}")
```

```bash
nmap -p 80,443,8000,8080,8443 <smart-speaker-ip>
sudo avahi-browse -all            # mDNS 服务
ssh root@<hub-ip>                 # 集线器常跑嵌入式 Linux，试默认凭证
```

### 2. Matter 协议安全

| 安全层 | 说明 | 机制 |
|:---|:---|:---|
| 设备认证 | 认证设备合法性 | DAC（Device Attestation Certificate） |
| 通信加密 | 数据加密传输 | CASE（Cert Auth Session Establishment） |
| 访问控制 | 细粒度权限控制 | ACL（Access Control List） |
| 固件更新 | 安全 OTA | 代码签名验证 |

检查清单：□ 是否误用 Test-Event 安全证书（非生产）□ Matter DAC 是否过期 □ ACL 配置是否正确（最小权限）□ Thread 网络密钥是否非默认 □ 调试模式是否在生产设备禁用 □ mDNS 服务信息是否过滤。

### 3. CAN 总线测试

```bash
sudo modprobe can
sudo modprobe can-raw
sudo ip link set can0 type can bitrate 500000
sudo ip link set can0 up

candump can0
cansend can0 7DF#02010C0000000000     # OBD-II 请求
candump can0,0x7E8:0xFFF              # 仅收响应
```

```python
import can
bus = can.interface.Bus(channel='can0', bustype='socketcan')
msg = can.Message(arbitration_id=0x7DF,
                  data=[0x02, 0x01, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00],
                  is_extended_id=False)   # RPM 请求
bus.send(msg)
for msg in bus:
    if msg.arbitration_id == 0x7E8:
        print(f"Response: {msg.data.hex()}")
```

```bash
git clone https://github.com/zombieCraig/ICSim.git && cd ICSim && make
./icsim vcan0            # 仪表盘模拟
./controls vcan0         # 控制模拟
cansend vcan0 0x244#032F000000000000    # 伪造车速
cansend vcan0 0x245#0100000000000000    # 伪造检查引擎灯
```

### 4. OBD-II 安全评估

风险点：① OBD-II dongle 蓝牙连接不安全 ② 固定 PIN 码 ③ 经 OBD-II 打通 CAN 总线。

```bash
sudo hcitool scan             # 常见名称: OBDII / ELM327 / Vgate
sudo rfcomm connect 0 <MAC> 1 &    # 成功后出现 /dev/rfcomm0
picocom /dev/rfcomm0 -b 38400
# ATZ 重置 / ATSP0 自动选协议 / 010C 请求 RPM
nmap -p 35000 192.168.0.0/24  # ELM327 WiFi 默认 IP 常为 192.168.0.10
```

常见默认 PIN：1234、0000、6789。

### 5. 车联网与智能家居安全基线

| # | 安全项 | 严重程度 | 修复建议 |
|:---:|:---|:---:|:---:|
| 1 | OBD-II 端口未加锁 | 🔴 严重 | 使用 OBD-II 锁或安全盖 |
| 2 | CAN 总线无认证 | 🔴 严重 | 实施 CAN-FD 安全消息认证 |
| 3 | 蓝牙 OBD-II 默认 PIN | 🟠 高危 | 改为随机 PIN |
| 4 | 远程解锁漏洞 | 🔴 严重 | 端到端加密 + 挑战-响应 |
| 5 | 智能家居设备默认密码 | 🔴 严重 | 强制修改默认密码 |
| 6 | Matter 设备使用测试证书 | 🟠 高危 | 使用生产 PCA 签发的 DAC |
| 7 | UPnP 端口暴露 | 🟡 中危 | 禁用 WAN 侧 UPnP |
| 8 | 本地 API 未授权 | 🔴 严重 | 实施本地认证 |

## 七、常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Binwalk | 固件分析工具 | https://github.com/ReFirmLabs/binwalk |
| Firmadyne | 固件仿真平台 | https://github.com/firmadyne/firmadyne |
| Ghidra | 逆向工程框架 | https://ghidra-sre.org/ |
| QEMU | 全系统仿真器 | https://www.qemu.org/ |
| Firmwalker | 固件扫描脚本 | https://github.com/craigz28/firmwalker |
| JTAGulator | JTAG 引脚识别 | https://www.adafruit.com/product/1554 |
| OpenOCD | JTAG/SWD 调试器 | https://openocd.org/ |
| Saleae Logic | 逻辑分析仪 | https://www.saleae.com/ |
| Bus Pirate | 多协议硬件工具 | https://buspirate.com/ |
| ChipWhisperer | 侧信道分析平台 | https://chipwhisperer.io/ |
| BLEAH | BLE 安全测试框架 | https://github.com/BAH-LE/BLEAH |
| Ubertooth | BLE 嗅探器 | https://github.com/greatscottgadgets/ubertooth |
| Z3sec | Zigbee 安全测试 | https://github.com/attify/z3sec |
| KillerBee | Zigbee 攻击框架 | https://github.com/riverloopsec/killerbee |
| HackRF | SDR 平台 | https://greatscottgadgets.com/hackrf/ |
| BetterCAP | 网络攻击框架 | https://www.bettercap.org/ |
| MQTT PWN | MQTT 安全测试框架 | https://github.com/akamai/mqtt-pwn |
| MQTTSA | MQTT 安全助手 | https://github.com/akamai/MQTTSA |
| aiocoap | CoAP Python 库 | https://github.com/chrysn/aiocoap |
| Mosquitto | MQTT Broker | https://mosquitto.org/ |
| ChirpStack | LoRaWAN 网络服务器 | https://www.chirpstack.io/ |
| ICSim | CAN 总线模拟器 | https://github.com/zombieCraig/ICSim |
| CANtact | CAN 总线工具 | https://cantact.io/ |
| can-utils | CAN 工具集 | https://github.com/linux-can/can-utils |
| Home Assistant | 智能家居平台 | https://www.home-assistant.io/ |
| MQTTX | MQTT 客户端工具 | https://mqttx.app/ |
| OpenSSL | 证书管理 | https://www.openssl.org/ |

## 八、参考资源

- [OWASP IoT Testing Guide](https://owasp.org/www-project-iot-security-testing-guide/)
- [OWASP IoT Top 10](https://owasp.org/www-project-iot-top-10/)
- [NIST IR 8259 — IoT Device Cybersecurity Guidance](https://csrc.nist.gov/publications/detail/ir/8259/final)
- [NIST IR 8259B — IoT Device Security](https://csrc.nist.gov/publications/detail/ir/8259b/final)
- [NIST SP 800-183 — Networks of 'Things'](https://csrc.nist.gov/publications/detail/sp/800-183/final)
- [NIST SP 800-193 — Platform Firmware Resiliency](https://csrc.nist.gov/publications/detail/sp/800-193/final)
- [MQTT Security Best Practices](https://www.hivemq.com/blog/mqtt-security-fundamentals/)
- [CoAP Security (RFC 7252)](https://datatracker.ietf.org/doc/html/rfc7252)
- [LoRaWAN Security](https://lora-alliance.org/about-lorawan/)
- [Matter and Thread Security Fundamentals](https://csa-iot.org/)
- [AWS IoT Security Best Practices](https://docs.aws.amazon.com/iot/latest/developerguide/security-best-practices.html)
- [Azure IoT Hub Security](https://learn.microsoft.com/azure/iot-hub/iot-hub-security-overview)
- [Hardware Hacking Handbook](https://nostarch.com/hardwarehacking)
- [SAE J3061 — Automotive Cybersecurity](https://www.sae.org/standards/content/j3061_201601/)
- [MITRE ATT&CK for ICS / Embedded](https://attack.mitre.org/techniques/ics/)

## 九、上游原文（references/）

| 上游文件 | 本包路径 |
|:---|:---|
| `README.md`（分类导读与技能清单） | `references/README.md` |
| `skills/固件逆向与分析-FirmwareReverseEngineering.md` | `references/固件逆向与分析-FirmwareReverseEngineering.md` |
| `skills/BLE-Zigbee-Z-Wave无线安全测试-WirelessProtocolSecurity.md` | `references/BLE-Zigbee-Z-Wave无线安全测试-WirelessProtocolSecurity.md` |
| `skills/物联网通信协议安全-IoTCommunicationSecurity.md` | `references/物联网通信协议安全-IoTCommunicationSecurity.md` |
| `skills/嵌入式设备硬件安全测试-EmbeddedHardwareSecurity.md` | `references/嵌入式设备硬件安全测试-EmbeddedHardwareSecurity.md` |
| `skills/物联网平台与云安全-IoTPlatformCloudSecurity.md` | `references/物联网平台与云安全-IoTPlatformCloudSecurity.md` |
| `skills/智能家居与车联网安全-SmartHomeConnectedVehicleSecurity.md` | `references/智能家居与车联网安全-SmartHomeConnectedVehicleSecurity.md` |
