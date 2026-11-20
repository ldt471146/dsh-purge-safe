# 标准与参考资料 - WMI 事件订阅持久化狩猎

## MITRE ATT&CK 参考

| 技术编号 | 名称 | 描述 |
|-----------|------|-------------|
| T1546.003 | WMI Event Subscription | 主要持久化技术 |
| T1047 | WMI | WMI 执行用于横向移动 |
| T1059.005 | Visual Basic | ActiveScriptEventConsumer 中的 VBScript |
| T1059.007 | JavaScript | ActiveScriptEventConsumer 中的 JScript |

## WMI 订阅组件

| 组件 | WMI 类 | 用途 |
|-----------|-----------|---------|
| 事件过滤器 | __EventFilter | 定义触发器（WQL 查询） |
| 事件消费者 | __EventConsumer | 定义执行动作 |
| 绑定 | __FilterToConsumerBinding | 将过滤器与消费者关联 |

## 消费者类型及风险

| 消费者类 | 风险级别 | 描述 |
|---------------|-----------|-------------|
| ActiveScriptEventConsumer | 严重 | 执行 VBScript/JScript 代码 |
| CommandLineEventConsumer | 严重 | 执行任意命令 |
| LogFileEventConsumer | 低 | 写入日志文件 |
| NTEventLogEventConsumer | 低 | 写入 Windows 事件日志 |
| SMTPEventConsumer | 中等 | 发送邮件通知 |

## 常见恶意过滤器查询

| 过滤器类型 | WQL 查询 | 用途 |
|-------------|-----------|-------|
| 进程启动 | SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' | 在特定进程启动时执行 |
| 系统启动 | SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' | 系统启动后不久执行 |
| 基于计时器 | SELECT * FROM __TimerEvent WHERE TimerID='MyTimer' | 按间隔执行 |
| 用户登录 | SELECT * FROM __InstanceCreationEvent WHERE TargetInstance ISA 'Win32_LogonSession' | 用户登录时执行 |

## 检测事件

| 来源 | 事件 ID | 描述 |
|--------|----------|-------------|
| Sysmon | 19 | 检测到 WmiEventFilter 活动 |
| Sysmon | 20 | 检测到 WmiEventConsumer 活动 |
| Sysmon | 21 | 检测到 WmiEventConsumerToFilter 活动 |
| WMI-Activity | 5861 | WMI 永久事件订阅已创建 |
| Security | 4688 | 进程创建（mofcomp.exe、WmiPrvSe.exe 子进程） |

## 已知 APT 使用案例

| 组织 | 技术详情 |
|-------|-------------------|
| APT29 | 使用编码 VBScript 后门的 ActiveScriptEventConsumer |
| APT32（OceanLotus） | 定向攻击中使用 WMI 订阅持久化 |
| FIN8 | 使用 CommandLineEventConsumer 执行 PowerShell |
| Turla | WMI 事件订阅与 COM 劫持相结合 |
| HEXANE | 在中东能源行业攻击中使用 WMI 持久化 |
