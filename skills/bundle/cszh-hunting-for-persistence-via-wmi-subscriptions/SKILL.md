---
name: cszh-hunting-for-persistence-via-wmi-subscriptions
description: 通过监控 WMI 消费者、过滤器和绑定创建事件，狩猎攻击者利用 Windows Management Instrumentation 事件订阅实现的持久化，这些订阅在系统事件触发时执行恶意代码。
---

> 来源：killvxk/cybersecurity-skills-zh 上游技能 `hunting-for-persistence-via-wmi-subscriptions`，正文为中文原文照录（仅剥离上游 frontmatter）。
> 定位：狩猎通过 WMI 事件订阅实现的持久化。
> 用法：按正文的「工作流程 / 命令清单 / 输出格式」执行；本技能在 dsh 中的名字是 cszh-hunting-for-persistence-via-wmi-subscriptions。

# 狩猎通过 WMI 事件订阅实现的持久化

## 适用场景

- 主动搜索 Windows 环境中的无文件持久化机制时
- 威胁情报报告显示 APT 组织（APT29、APT32、FIN8）使用基于 WMI 的持久化时
- 调查清除恶意软件后仍能跨重启持久存活的系统时
- 事件响应阶段，标准持久化位置（Run 键、计划任务）未发现异常时
- 观察到 WmiPrvSe.exe 派生出非预期子进程时

## 前置条件

- 启用 Sysmon 事件 ID 19、20、21（WMI 事件过滤器/消费者/绑定）
- 来自 Microsoft-Windows-WMI-Activity 的 Windows 事件 ID 5861（WMI 活动日志）
- 启用 PowerShell 日志（脚本块日志、模块日志）
- 用于枚举的 WMI 存储库访问权限
- 用于事件关联的 SIEM 平台

## 工作流程

1. **枚举现有 WMI 订阅**：查询目标系统上的所有永久 WMI 事件订阅。干净系统通常只有很少或零个永久订阅，因此异常易于发现。
2. **监控 WMI 事件创建（Sysmon 19/20/21）**：Sysmon 事件 19 捕获 WmiEventFilter 活动，事件 20 捕获 WmiEventConsumer 活动，事件 21 捕获 WmiEventConsumerToFilter 绑定。
3. **分析消费者类型**：重点关注 ActiveScriptEventConsumer（运行 VBScript/JScript）和 CommandLineEventConsumer（执行命令）——这两种类型是用于持久化的危险类型。
4. **检查事件过滤器触发条件**：检查触发订阅的条件。常见恶意触发条件包括系统启动（Win32_ProcessStartTrace）、用户登录或基于定时器的执行间隔。
5. **调查 WmiPrvSe.exe 的子进程**：WMI 订阅触发时，操作由 WmiPrvSe.exe 执行。狩猎 WmiPrvSe.exe 的异常子进程。
6. **关联 MOF 编译**：检测 `mofcomp.exe` 的使用——它用于编译 MOF 文件以编程方式创建 WMI 订阅。
7. **验证并响应**：确认恶意订阅，将其清除，并追溯到初始感染入口。

## 核心概念

| 概念 | 描述 |
|------|------|
| T1546.003 | 事件触发执行：WMI 事件订阅 |
| __EventFilter | 定义触发条件的 WMI 类 |
| __EventConsumer | 定义执行操作的 WMI 类 |
| __FilterToConsumerBinding | 将过滤器链接到消费者 |
| ActiveScriptEventConsumer | 运行 VBScript 或 JScript 的消费者 |
| CommandLineEventConsumer | 执行命令行的消费者 |
| WmiPrvSe.exe | 执行订阅操作的 WMI 提供程序主机 |
| MOF 文件 | 用于定义 WMI 对象的托管对象格式 |

## 检测查询

### Splunk——通过 Sysmon 检测 WMI 订阅创建
```spl
index=sysmon (EventCode=19 OR EventCode=20 OR EventCode=21)
| eval event_type=case(EventCode=19, "EventFilter", EventCode=20, "EventConsumer", EventCode=21, "FilterToConsumerBinding")
| table _time Computer User event_type EventNamespace Name Query Destination Operation
```

### Splunk——通过 Windows 事件 5861 检测 WMI 订阅
```spl
index=wineventlog source="Microsoft-Windows-WMI-Activity/Operational" EventCode=5861
| table _time Computer NamespaceName Operation PossibleCause
```

### PowerShell——枚举 WMI 订阅
```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class __EventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

### KQL——WmiPrvSe.exe 派生可疑子进程
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "wmiprvse.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

### Sigma 规则
```yaml
title: WMI Event Subscription Persistence
status: stable
logsource:
    product: windows
    category: wmi_event
detection:
    selection_consumer:
        EventID: 20
        Destination|contains:
            - 'ActiveScriptEventConsumer'
            - 'CommandLineEventConsumer'
    condition: selection_consumer
level: high
tags:
    - attack.persistence
    - attack.t1546.003
```

## 常见场景

1. **APT29 WMI 持久化**：创建一个 ActiveScriptEventConsumer，在系统启动时执行 VBScript 后门，即使重启或重置凭据后仍能存活。
2. **Turla WMI 后门**：使用 Win32_ProcessStartTrace 过滤器结合 CommandLineEventConsumer 进行隐蔽命令执行。
3. **FIN8 WMI 定时器**：基于间隔的 __IntervalTimerEvent 每 30 分钟触发一次编码的 PowerShell 下载。
4. **基于 MOF 的安装**：攻击者投放 .mof 文件并使用 `mofcomp.exe` 编译，静默创建持久化订阅。

## 输出格式

```
狩猎 ID：TH-WMI-[日期]-[序号]
主机：[主机名]
订阅名称：[过滤器/消费者名称]
过滤器查询：[WQL 触发条件]
消费者类型：[ActiveScript/CommandLine]
消费者操作：[脚本内容或命令]
绑定：[过滤器到消费者的链接]
创建时间：[时间戳]
用户上下文：[SYSTEM/用户]
风险等级：[严重/高/中/低]
```
