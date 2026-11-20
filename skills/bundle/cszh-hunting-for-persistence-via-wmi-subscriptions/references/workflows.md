# 详细狩猎工作流程 - WMI 订阅持久化（WMI Subscription Persistence）

## 阶段 1：枚举现有订阅

### 步骤 1.1 - PowerShell 枚举
```powershell
# 列出所有事件过滤器
Get-WMIObject -Namespace root\Subscription -Class __EventFilter | Select-Object Name, Query, QueryLanguage

# 列出所有事件消费者
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer | Select-Object Name, __CLASS

# 列出所有绑定关系
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding | Select-Object Filter, Consumer

# 详细检查 ActiveScriptEventConsumer
Get-WMIObject -Namespace root\Subscription -Class ActiveScriptEventConsumer | Select-Object Name, ScriptingEngine, ScriptText

# 详细检查 CommandLineEventConsumer
Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer | Select-Object Name, ExecutablePath, CommandLineTemplate
```

### 步骤 1.2 - WMIC 枚举
```cmd
wmic /namespace:\\root\subscription path __EventFilter get Name, Query
wmic /namespace:\\root\subscription path __EventConsumer get Name, __CLASS
wmic /namespace:\\root\subscription path __FilterToConsumerBinding get Filter, Consumer
```

## 阶段 2：监控创建事件

### 步骤 2.1 - Sysmon WMI 事件检测
```spl
index=sysmon (EventCode=19 OR EventCode=20 OR EventCode=21)
| eval event_type=case(
    EventCode=19, "EventFilter Created",
    EventCode=20, "EventConsumer Created",
    EventCode=21, "Binding Created"
)
| table _time Computer User event_type Name Query Consumer Destination
```

### 步骤 2.2 - Windows WMI 活动日志
```spl
index=wineventlog source="Microsoft-Windows-WMI-Activity/Operational"
| where EventCode IN (5857, 5858, 5859, 5860, 5861)
| table _time Computer EventCode NamespaceName Query Operation PossibleCause
```

## 阶段 3：狩猎 WmiPrvSe.exe 的可疑子进程

### 步骤 3.1 - 进程树分析
```spl
index=sysmon EventCode=1
| where match(ParentImage, "(?i)WmiPrvSe\.exe$")
| where match(Image, "(?i)(cmd|powershell|wscript|cscript|mshta|rundll32|regsvr32)\.exe$")
| table _time Computer Image CommandLine User ParentImage
```

### 步骤 3.2 - MOF 编译检测
```spl
index=sysmon EventCode=1 Image="*\\mofcomp.exe"
| table _time Computer User CommandLine ParentImage
```

## 阶段 4：清除与处置

### 步骤 4.1 - 删除恶意订阅
```powershell
# 删除特定订阅组件
Get-WMIObject -Namespace root\Subscription -Class __EventFilter -Filter "Name='MaliciousFilter'" | Remove-WmiObject
Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer -Filter "Name='MaliciousConsumer'" | Remove-WmiObject
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding -Filter "Filter=""__EventFilter.Name='MaliciousFilter'""" | Remove-WmiObject
```

## 阶段 5：响应
1. 记录所有发现的订阅及完整细节
2. 从所有受影响主机中删除恶意订阅
3. 在可行的情况下通过组策略阻止 WMI 订阅创建
4. 通过 Sysmon 事件 19/20/21 部署持续监控
5. 调查创建订阅的初始感染向量
