# API 参考：WiFi 密码破解 Agent（Aircrack-ng）

## 概述

自动化 WPA/WPA2 无线安全评估：监听模式管理、网络扫描、握手/PMKID 捕获，以及通过 aircrack-ng 和 hashcat 子进程封装进行离线破解。

## 依赖

| 包 | 版本 | 用途 |
|----|------|------|
| subprocess | stdlib | 执行 aircrack-ng 套件和 hashcat |

## 所需外部工具

| 工具 | 用途 |
|------|------|
| airmon-ng | 启用/禁用监听模式 |
| airodump-ng | 无线网络扫描和捕获 |
| aireplay-ng | 取消认证以捕获握手包 |
| aircrack-ng | WPA 字典攻击（CPU） |
| hashcat | GPU 加速 WPA 破解 |
| hcxdumptool | PMKID 捕获（可选） |
| hcxpcapngtool | PMKID 哈希提取（可选） |

## 核心函数

### `enable_monitor_mode(iface)`
终止干扰进程并启用监听模式。
- **返回**：包含 `monitor_interface` 的 `dict`

### `scan_networks(mon_iface, duration, output_prefix)`
扫描附近的无线网络，解析 CSV 输出。
- **返回**：`list[dict]` — BSSID、信道、加密类型、ESSID、信号强度

### `capture_handshake(mon_iface, bssid, channel, output_prefix, timeout)`
使用定向取消认证捕获 WPA 四次握手包。
- **返回**：包含 `capture_file`、`handshake_captured` 的 `dict`

### `try_pmkid_capture(mon_iface, bssid, channel, timeout)`
尝试基于 PMKID 的捕获（无需客户端）。
- **返回**：包含 `pmkid_captured`、`hash_file` 的 `dict`

### `crack_with_aircrack(cap_file, wordlist)`
使用 aircrack-ng 进行基于 CPU 的字典攻击。
- **默认字典**：`/usr/share/wordlists/rockyou.txt`
- **返回**：包含 `cracked`、`key` 的 `dict`

### `crack_with_hashcat(hash_file, wordlist, hash_mode)`
GPU 加速破解。模式 22000 用于 WPA-PBKDF2-PMKID+EAPOL。
- **返回**：包含 `cracked`、`result` 的 `dict`

### `disable_monitor_mode(mon_iface)`
恢复托管模式并重启 NetworkManager。

## Hashcat 模式

| 模式 | 哈希类型 |
|------|---------|
| 22000 | WPA-PBKDF2-PMKID+EAPOL |
| 22001 | WPA-PMK-PMKID+EAPOL |
| 2500 | WPA-EAPOL-PBKDF2（旧版） |

## 要求

- root/sudo 权限
- 支持监听模式的无线网卡
- 目标网络的书面授权

## 用法

```bash
sudo python agent.py wlan0
```
