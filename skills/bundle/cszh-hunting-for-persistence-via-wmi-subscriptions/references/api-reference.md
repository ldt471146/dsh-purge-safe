# API 参考——狩猎通过 WMI 事件订阅实现的持久化

## 使用的库
- **subprocess**：执行 WMIC 和 PowerShell 命令进行 WMI 枚举
- **python-evtx**（Evtx）：解析 Sysmon EVTX 中的 WMI 相关事件（ID 19、20、21）
- **re**：对可疑 WMI 消费者载荷进行正则匹配

## CLI 接口

```
python agent.py enumerate                  # 基于 WMIC 的 WMI 订阅枚举
python agent.py powershell                 # PowerShell Get-WMIObject 枚举
python agent.py sysmon --evtx-file <path>  # 扫描 Sysmon EVTX 中的 WMI 事件
```

## 核心函数

### `enumerate_wmi_subscriptions()`
通过 WMIC 查询四个 WMI 订阅类，并标记匹配可疑模式的条目。

**返回值：** dict，包含 `classes`（EventFilter、EventConsumer、ActiveScriptEventConsumer、FilterToConsumerBinding）和 `suspicious` 列表。

### `scan_sysmon_wmi_events(evtx_file)`
解析 Sysmon EVTX 中的事件 ID 19（WmiEventFilter）、20（WmiEventConsumer）、21（WmiEventBinding）。

**参数：**
| 名称 | 类型 | 描述 |
|------|------|------|
| `evtx_file` | str | Sysmon .evtx 文件路径 |

### `query_powershell_wmi()`
使用 PowerShell `Get-WMIObject` 枚举 `root\Subscription` 命名空间中的 WMI 订阅。

## 枚举的 WMI 类

| 类 | 描述 |
|----|------|
| `__EventFilter` | 定义触发订阅的 WQL 查询 |
| `CommandLineEventConsumer` | 过滤器匹配时执行命令 |
| `ActiveScriptEventConsumer` | 过滤器匹配时运行 VBScript/JScript |
| `__FilterToConsumerBinding` | 将过滤器链接到其消费者 |

## Sysmon 事件 ID

| 事件 ID | 描述 |
|---------|------|
| 19 | WmiEvent——检测到过滤器活动 |
| 20 | WmiEvent——检测到消费者活动 |
| 21 | WmiEvent——消费者到过滤器的绑定 |

## 依赖项
```
pip install python-evtx  # 可选，用于 EVTX 解析
```
