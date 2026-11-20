# API 参考：使用 Kismet 进行无线安全评估

## Kismet REST API 端点

| 端点 | 方法 | 描述 |
|------|------|------|
| `/session/check_login` | POST | 使用用户名/密码进行认证 |
| `/system/status.json` | GET | 服务器状态和统计信息 |
| `/devices/summary/devices.json` | POST | 按字段选择查询设备 |
| `/devices/by-key/{key}/device.json` | GET | 获取单个设备详情 |
| `/phy/phy80211/ssids/views/ssids.json` | GET | 所有已检测到的 SSID |
| `/alerts/all_alerts.json` | GET | 所有 Kismet 告警 |
| `/datasource/list_interfaces.json` | GET | 可用的捕获接口 |

## 设备字段

| 字段 | 描述 |
|------|------|
| `kismet.device.base.macaddr` | 设备 MAC 地址 |
| `kismet.device.base.name` | SSID 或设备名称 |
| `kismet.device.base.type` | `Wi-Fi AP`、`Wi-Fi Client` 等 |
| `kismet.device.base.manuf` | 厂商（OUI 查找） |
| `kismet.device.base.channel` | 工作信道 |
| `kismet.device.base.crypt` | 加密类型 |
| `kismet.device.base.signal` | 信号强度数据 |
| `kismet.device.base.first_time` | 首次发现时间戳 |
| `kismet.device.base.last_time` | 最近发现时间戳 |

## 认证

| 方法 | 头部/Cookie |
|------|------------|
| API 密钥 | `Cookie: KISMET=<api_key>` |
| 登录 | POST `/session/check_login`，JSON 格式 `{username, password}` |

## Kismet CLI

| 命令 | 描述 |
|------|------|
| `kismet -c wlan0` | 启动带捕获源的 Kismet |
| `kismet --override wardrive` | 使用战地驾驶（Wardriving）配置 |
| `kismet_cap_linux_wifi` | Linux Wi-Fi 捕获助手 |

## Python 库

| 库 | 版本 | 用途 |
|----|------|------|
| `requests` | >=2.28 | Kismet REST API 客户端 |
| `json` | stdlib | 解析 API 响应 |

## 参考资料

- Kismet 文档：https://www.kismetwireless.net/docs/readme/intro/kismet/
- Kismet REST API：https://www.kismetwireless.net/docs/api/rest_api/
- Kismet GitHub：https://github.com/kismetwireless/kismet
