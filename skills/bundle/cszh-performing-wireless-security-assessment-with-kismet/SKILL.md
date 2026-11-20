---
name: cszh-performing-wireless-security-assessment-with-kismet
description: 使用 Kismet 通过被动射频监控进行无线网络安全评估，检测流氓接入点（Rogue AP）、隐藏 SSID、弱加密和未授权客户端。
---

> 来源：killvxk/cybersecurity-skills-zh 上游技能 `performing-wireless-security-assessment-with-kismet`，正文为中文原文照录（仅剥离上游 frontmatter）。
> 定位：使用 Kismet 进行无线安全评估。
> 用法：按正文的「工作流程 / 命令清单 / 输出格式」执行；本技能在 dsh 中的名字是 cszh-performing-wireless-security-assessment-with-kismet。

# 使用 Kismet 进行无线安全评估

## 概述

Kismet 是一款开源无线网络探测器、数据包嗅探器和无线入侵检测系统（WIDS），支持 802.11a/b/g/n/ac/ax。与主动扫描器不同，Kismet 以被动监听模式运行，使被评估网络无法检测到它。Kismet 捕获原始 802.11 帧，识别接入点、客户端、探测请求和加密类型，无需发送任何数据包。本技能涵盖部署 Kismet 进行全面无线安全评估、识别流氓接入点、检测弱加密、绘制隐藏网络图以及分析客户端行为。

## 前置条件

- 已安装 Kismet 2023+ 的 Linux 系统（Kali Linux、Ubuntu 22.04+）
- 支持监听模式的无线网卡（如 Alfa AWUS036ACH、TP-Link TL-WN722N v1）
- 无线评估的书面授权（法律要求）
- GPS 接收器（可选，用于地理位置映射）
- 目标环境无线网络文档

## 核心概念

### Kismet 架构

Kismet 采用客户端-服务器架构：

- **kismet** — 捕获和处理数据包的主服务器进程
- **kismet_cap_linux_wifi** — Linux WiFi 接口的捕获源
- **kismet_cap_linux_bluetooth** — 蓝牙捕获源
- **Web UI** — 基于浏览器的界面，位于 http://localhost:2501

### 无线帧类型

| 帧类型 | 用途 | 安全相关性 |
|--------|------|-----------|
| Beacon | AP 宣告其存在 | SSID、加密类型、厂商 |
| Probe Request | 客户端搜索网络 | 揭示首选网络 |
| Probe Response | AP 响应客户端探测 | 隐藏 SSID 泄露 |
| Authentication | 客户端向 AP 认证 | 认证类型识别 |
| Deauthentication | 断开客户端与 AP 的连接 | 潜在攻击指示器 |
| Association | 客户端加入网络 | 客户端-AP 关系 |

### 加密评估

| 加密类型 | 状态 | 风险 |
|---------|------|------|
| 开放（无加密） | 不安全 | 严重 - 所有流量可见 |
| WEP | 已破解 | 严重 - 数分钟内可破解 |
| WPA-TKIP | 已弃用 | 高 - 存在已知漏洞 |
| WPA2-PSK (CCMP) | 可接受 | 中 - 取决于密码短语强度 |
| WPA2-Enterprise (802.1X) | 推荐 | 低 - 基于证书 |
| WPA3-SAE | 最佳实践 | 低 - 可抵御离线攻击 |

## 步骤

### 步骤 1：准备无线网卡

```bash
# 识别无线接口
iwconfig

# 检查网卡能力
iw list | grep -A 10 "Supported interface modes"

# 终止可能干扰的进程
sudo airmon-ng check kill

# 启用监听模式
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# 验证监听模式
iw dev wlan0 info | grep type
```

### 步骤 2：配置并启动 Kismet

编辑 `/etc/kismet/kismet.conf`：

```ini
# 数据源
source=wlan0:name=WiFi-Monitor,channel_hop=true,channel_hoprate=5/sec

# 日志配置
log_types=kismet,pcapng
log_prefix=/opt/kismet/logs/assessment

# 启用所有 802.11 信道（2.4GHz 和 5GHz）
channel_hop_speed=5
channel_list=IEEE80211:1,2,3,4,5,6,7,8,9,10,11,36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,149,153,157,161,165

# GPS 配置（若可用）
gps=gpsd:host=localhost,port=2947

# 告警配置
alert=ADVCRYPTCHANGE,5/min,1/sec
alert=BSSTIMESTAMP,5/min,1/sec
alert=CRYPTODROP,5/min,1/sec
alert=DISASSOCTRAFFIC,10/min,1/sec
alert=DEAUTHFLOOD,10/min,2/sec
alert=PROBENOMFP,5/min,1/sec
```

启动 Kismet：

```bash
# 启动 Kismet 服务器
sudo kismet -c wlan0

# 访问 Web 界面
# 打开浏览器访问 http://localhost:2501
# 默认凭证：kismet / kismet（请立即更改）
```

### 步骤 3：执行评估扫描

**流氓接入点检测：**

```bash
# 通过 Kismet REST API 导出设备列表
curl -u kismet:kismet http://localhost:2501/devices/summary/devices.json | \
    python3 -m json.tool > all_devices.json

# 筛选接入点
curl -u kismet:kismet \
    'http://localhost:2501/devices/summary/devices.json' \
    -d 'json={"fields":["kismet.device.base.macaddr","kismet.device.base.name","kismet.device.base.type","kismet.device.base.crypt","kismet.device.base.channel","kismet.device.base.manuf","dot11.device/dot11.device.advertised_ssid_map/dot11.advertisedssid.ssid"]}' \
    > access_points.json
```

**客户端探测分析：**

探测请求（Probe Request）揭示客户端曾连接过的网络，可能表明：
- 企业设备连接至不安全的家庭网络
- 设备搜索已知恶意 SSID（易受邪恶双胞胎攻击）
- 企业环境中的未授权个人设备

### 步骤 4：分析结果

Kismet 数据库分析 Python 脚本：

```python
#!/usr/bin/env python3
"""分析 Kismet 捕获数据库中的无线安全发现。"""

import sqlite3
import json
import sys
from collections import defaultdict


def analyze_kismet_db(db_path: str):
    """分析 Kismet SQLite 数据库中的安全问题。"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT devmac, type, device FROM devices")
    devices = cursor.fetchall()
    ap_count = 0
    client_count = 0
    open_networks = []
    wep_networks = []
    wpa_tkip_networks = []
    hidden_networks = []
    all_aps = []

    for mac, dev_type, device_json in devices:
        try:
            device = json.loads(device_json)
        except json.JSONDecodeError:
            continue
        base = device.get('kismet.device.base.type', '')
        if 'Wi-Fi AP' in base or 'Wi-Fi Device' in base:
            ap_count += 1
            ssid_map = device.get('dot11.device', {}).get('dot11.device.advertised_ssid_map', [])
            crypt = device.get('kismet.device.base.crypt', '')
            name = device.get('kismet.device.base.name', '未知')
            channel = device.get('kismet.device.base.channel', '')
            manuf = device.get('kismet.device.base.manuf', '未知')
            ap_info = {'mac': mac, 'ssid': name, 'encryption': crypt, 'channel': channel, 'manufacturer': manuf}
            all_aps.append(ap_info)
            if 'None' in crypt or crypt == '':
                open_networks.append(ap_info)
            elif 'WEP' in crypt:
                wep_networks.append(ap_info)
            elif 'WPA+TKIP' in crypt and 'AES' not in crypt:
                wpa_tkip_networks.append(ap_info)
            for ssid_entry in ssid_map:
                if isinstance(ssid_entry, dict):
                    ssid = ssid_entry.get('dot11.advertisedssid.ssid', '')
                    if ssid == '' or ssid is None:
                        hidden_networks.append(ap_info)
        elif 'Wi-Fi Client' in base:
            client_count += 1

    print(f"\n{'='*70}")
    print("无线安全评估报告")
    print(f"{'='*70}")
    print(f"\n检测到的接入点总数：{ap_count}")
    print(f"检测到的客户端总数：{client_count}")
    if open_networks:
        print(f"\n[严重] 开放网络（无加密）：{len(open_networks)}")
        for net in open_networks:
            print(f"  - SSID：{net['ssid']}，MAC：{net['mac']}，信道：{net['channel']}，厂商：{net['manufacturer']}")
    if wep_networks:
        print(f"\n[严重] WEP 加密网络：{len(wep_networks)}")
        for net in wep_networks:
            print(f"  - SSID：{net['ssid']}，MAC：{net['mac']}，信道：{net['channel']}")
    if wpa_tkip_networks:
        print(f"\n[高危] WPA-TKIP 网络（已弃用）：{len(wpa_tkip_networks)}")
        for net in wpa_tkip_networks:
            print(f"  - SSID：{net['ssid']}，MAC：{net['mac']}，信道：{net['channel']}")
    if hidden_networks:
        print(f"\n[中危] 已发现的隐藏 SSID：{len(hidden_networks)}")
        for net in hidden_networks:
            print(f"  - MAC：{net['mac']}，信道：{net['channel']}，厂商：{net['manufacturer']}")
    channel_usage = defaultdict(int)
    for ap in all_aps:
        ch = ap.get('channel', '未知')
        channel_usage[ch] += 1
    print(f"\n[信息] 信道使用情况：")
    for ch, count in sorted(channel_usage.items()):
        print(f"  信道 {ch}：{count} 个 AP")
    conn.close()


if __name__ == '__main__':
    db_path = sys.argv[1] if len(sys.argv) > 1 else 'Kismet-*.kismet'
    analyze_kismet_db(db_path)
```

### 步骤 5：检测流氓接入点

将已发现的 AP 与授权清单进行比对：

```python
#!/usr/bin/env python3
"""通过与授权 AP 列表比对来检测流氓接入点。"""

import json
import sys


def load_authorized_aps(filepath: str) -> set:
    """从文件加载授权 AP MAC 地址。"""
    authorized = set()
    with open(filepath, 'r') as f:
        for line in f:
            mac = line.strip().lower()
            if mac and not mac.startswith('#'):
                authorized.add(mac)
    return authorized


def detect_rogues(kismet_json: str, authorized_file: str):
    """将已发现的 AP 与授权列表进行比对。"""
    authorized = load_authorized_aps(authorized_file)
    with open(kismet_json, 'r') as f:
        devices = json.load(f)
    rogues = []
    for device in devices:
        mac = device.get('kismet.device.base.macaddr', '').lower()
        dev_type = device.get('kismet.device.base.type', '')
        if 'AP' in dev_type and mac not in authorized:
            rogues.append({
                'mac': mac,
                'ssid': device.get('kismet.device.base.name', '未知'),
                'encryption': device.get('kismet.device.base.crypt', ''),
                'channel': device.get('kismet.device.base.channel', ''),
                'manufacturer': device.get('kismet.device.base.manuf', ''),
                'signal': device.get('kismet.device.base.signal', {}).get('kismet.common.signal.last_signal', 0),
            })
    if rogues:
        print(f"\n[告警] 检测到 {len(rogues)} 个流氓接入点\n")
        for rogue in rogues:
            print(f"  MAC：{rogue['mac']}")
            print(f"  SSID：{rogue['ssid']}")
            print(f"  加密：{rogue['encryption']}")
            print(f"  信道：{rogue['channel']}")
            print(f"  厂商：{rogue['manufacturer']}")
            print(f"  信号强度：{rogue['signal']} dBm")
            print()
    else:
        print("未检测到流氓接入点。")


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("用法：python detect_rogues.py <kismet_devices.json> <authorized_aps.txt>")
        sys.exit(1)
    detect_rogues(sys.argv[1], sys.argv[2])
```

## 评估检查清单

- [ ] 所有授权 AP 已识别并验证
- [ ] 已识别并定位流氓/未授权 AP
- [ ] 所有 SSID 的加密类型已记录
- [ ] 已发现并记录隐藏 SSID
- [ ] 已分析客户端探测请求中的敏感模式
- [ ] 已评估邪恶双胞胎攻击易感性
- [ ] 已检查所有 AP 的 WPS 状态
- [ ] 已绘制信号覆盖边界图
- [ ] 已验证访客网络隔离
- [ ] 无线网络上未暴露管理接口

## 最佳实践

- **书面授权** — 进行无线评估前务必获取签署的授权
- **仅被动模式** — 使用 Kismet 被动模式，不发送取消认证帧或探测请求
- **全面信道覆盖** — 扫描 2.4GHz 和 5GHz 频段，包括 DFS 信道
- **多点位置** — 在多个物理位置进行捕获以获得完整覆盖
- **捕获时长** — 捕获至少 30-60 分钟以观测间歇性设备
- **GPS 映射** — 使用 GPS 创建信号边界热力图
- **基线比对** — 维护授权 AP 清单并在每次评估中进行比对

## 参考资料

- Kismet 文档：https://www.kismetwireless.net/docs/
- NIST SP 800-153 无线网络安全：https://csrc.nist.gov/publications/detail/sp/800-153/final
- Kismet GitHub 仓库：https://github.com/kismetwireless/kismet
