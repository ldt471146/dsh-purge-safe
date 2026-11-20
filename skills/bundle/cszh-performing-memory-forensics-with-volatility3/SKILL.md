---
name: cszh-performing-memory-forensics-with-volatility3
description: 使用 Volatility 3 分析易失性内存转储，以提取运行中的进程、网络连接、加载的模块以及恶意活动的证据。
---

> 本技能源自中文网络安全技能库 killvxk/cybersecurity-skills-zh（上游目录 performing-memory-forensics-with-volatility3），正文按中文原文照录。

**这个技能干什么**：使用 Volatility 3 分析易失性内存转储，以提取运行中的进程、网络连接、加载的模块以及恶意活动的证据。

**什么时候用**：需要按上游中文方法论执行「performing-memory-forensics-with-volatility3」对应任务时加载本技能。

**关键工具**：见正文各章节列出的命令与工具清单。

# 使用 Volatility 3 执行内存取证

## 适用场景
- 分析来自被入侵或可疑系统的 RAM 转储时
- 事件响应期间识别运行中的恶意软件、注入代码或 rootkit 时
- 需要从内存中提取凭据、加密密钥或网络连接时
- 检测进程空洞化（process hollowing）、DLL 注入或隐藏进程时
- 单纯的磁盘取证不足以解决问题且易失性数据至关重要时

## 前置条件
- 已安装 Python 3.7+
- 已安装 Volatility 3 框架（`pip install volatility3`）
- 原始格式、ELF 或崩溃转储格式的内存转储
- 目标操作系统版本的适当符号表（ISF 文件）
- 充足的磁盘空间用于分析输出（内存转储大小的 2-3 倍）
- 可选：YARA 规则用于内存中的恶意软件扫描

## 工作流程

### 步骤 1：获取内存转储并安装 Volatility 3

```bash
# 安装 Volatility 3
pip install volatility3

# 或从源代码安装以获取最新功能
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip install -e .

# 下载 Windows 符号表（ISF 包）
# 放置在 volatility3/symbols/ 目录中
wget https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
unzip windows.zip -d /opt/volatility3/volatility3/symbols/

# 下载 Linux 和 Mac 符号包
wget https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip
wget https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip

# 内存获取工具（用于活动系统）：
# Windows：winpmem、DumpIt、FTK Imager
# Linux：LiME（Linux Memory Extractor）
sudo insmod lime-$(uname -r).ko "path=/cases/memory/linux_mem.lime format=lime"

# 验证内存转储
file /cases/case-2024-001/memory/memory.raw
ls -lh /cases/case-2024-001/memory/memory.raw
```

### 步骤 2：识别操作系统 Profile

```bash
# 运行 banners 插件识别操作系统
vol -f /cases/case-2024-001/memory/memory.raw banners

# 对于 Windows，识别操作系统版本
vol -f /cases/case-2024-001/memory/memory.raw windows.info

# 输出示例：
# Variable        Value
# Kernel Base     0xf8047e200000
# DTB             0x1ad000
# Symbols         ntkrnlmp.pdb/GUID
# Is64Bit         True
# IsPAE           False
# primary layer   Intel32e
# KdVersionBlock  0xf8047ee232c0
# Major/Minor     15.19041
# Machine Type    34404
# KeNumberProcessors 4
# SystemTime      2024-01-18 14:32:15 UTC
# NtBuildLab      19041.1.amd64fre.vb_release.191206-1406
# NtProductType   NtProductWinNt
# NtSystemRoot    C:\WINDOWS
# PE MajorOperatingSystemVersion 10
# PE MinorOperatingSystemVersion 0

# 对于 Linux 内存转储
vol -f /cases/case-2024-001/memory/linux_mem.lime linux.info
```

### 步骤 3：枚举进程并检测异常

```bash
# 列出所有运行中的进程
vol -f /cases/case-2024-001/memory/memory.raw windows.pslist | tee /cases/case-2024-001/analysis/pslist.txt

# 显示进程树（父子关系）
vol -f /cases/case-2024-001/memory/memory.raw windows.pstree | tee /cases/case-2024-001/analysis/pstree.txt

# 使用交叉视图分析检测隐藏进程
vol -f /cases/case-2024-001/memory/memory.raw windows.psscan | tee /cases/case-2024-001/analysis/psscan.txt

# 比较 pslist 与 psscan 以查找隐藏进程
diff <(vol -f memory.raw windows.pslist | awk '{print $1}' | sort) \
     <(vol -f memory.raw windows.psscan | awk '{print $1}' | sort)

# 列出可疑进程加载的 DLL（PID 4532）
vol -f /cases/case-2024-001/memory/memory.raw windows.dlllist --pid 4532

# 检查进程空洞化和注入
vol -f /cases/case-2024-001/memory/memory.raw windows.malfind | tee /cases/case-2024-001/analysis/malfind.txt

# 转储可疑进程内存以进一步分析
vol -f /cases/case-2024-001/memory/memory.raw windows.memmap --pid 4532 --dump \
   -o /cases/case-2024-001/analysis/dumps/
```

### 步骤 4：分析网络连接和注册表

```bash
# 列出活动网络连接
vol -f /cases/case-2024-001/memory/memory.raw windows.netscan | tee /cases/case-2024-001/analysis/netscan.txt

# 过滤已建立的连接
vol -f /cases/case-2024-001/memory/memory.raw windows.netscan | grep ESTABLISHED

# 过滤监听端口
vol -f /cases/case-2024-001/memory/memory.raw windows.netscan | grep LISTENING

# 提取带进程映射的网络连接
vol -f /cases/case-2024-001/memory/memory.raw windows.netstat | tee /cases/case-2024-001/analysis/netstat.txt

# 从内存中转储注册表 hive
vol -f /cases/case-2024-001/memory/memory.raw windows.registry.hivelist

# 提取特定注册表键
vol -f /cases/case-2024-001/memory/memory.raw windows.registry.printkey \
   --key "Software\Microsoft\Windows\CurrentVersion\Run"

# 检查服务
vol -f /cases/case-2024-001/memory/memory.raw windows.svcscan | tee /cases/case-2024-001/analysis/services.txt
```

### 步骤 5：提取凭据和敏感数据

```bash
# 转储缓存凭据（hashdump）
vol -f /cases/case-2024-001/memory/memory.raw windows.hashdump | tee /cases/case-2024-001/analysis/hashes.txt

# 提取 LSA 机密
vol -f /cases/case-2024-001/memory/memory.raw windows.lsadump

# 转储缓存的域凭据
vol -f /cases/case-2024-001/memory/memory.raw windows.cachedump

# 在进程内存中搜索明文字符串
vol -f /cases/case-2024-001/memory/memory.raw windows.strings --pid 4532 \
   | grep -iE '(password|credential|token|api.key)'

# 从 cmd.exe/powershell 提取命令历史
vol -f /cases/case-2024-001/memory/memory.raw windows.cmdline | tee /cases/case-2024-001/analysis/cmdline.txt

# 提取环境变量
vol -f /cases/case-2024-001/memory/memory.raw windows.envars --pid 4532
```

### 步骤 6：使用 YARA 规则扫描恶意软件

```bash
# 使用 YARA 规则扫描内存
vol -f /cases/case-2024-001/memory/memory.raw yarascan \
   --yara-file /opt/yara-rules/malware_index.yar | tee /cases/case-2024-001/analysis/yara_hits.txt

# 扫描特定进程内存
vol -f /cases/case-2024-001/memory/memory.raw yarascan \
   --yara-file /opt/yara-rules/apt_rules.yar --pid 4532

# 检查已加载的内核模块是否存在 rootkit
vol -f /cases/case-2024-001/memory/memory.raw windows.modules | tee /cases/case-2024-001/analysis/modules.txt

# 检测未链接/隐藏的模块
vol -f /cases/case-2024-001/memory/memory.raw windows.modscan | tee /cases/case-2024-001/analysis/modscan.txt

# 检查 SSDT 钩子（系统服务描述符表）
vol -f /cases/case-2024-001/memory/memory.raw windows.ssdt | grep -v "ntoskrnl\|win32k"

# 从内存中转储可疑可执行文件
vol -f /cases/case-2024-001/memory/memory.raw windows.dumpfiles --pid 4532 \
   -o /cases/case-2024-001/analysis/extracted/
```

### 步骤 7：将调查结果汇编为报告

```bash
# 生成综合分析摘要
echo "=== 内存取证报告 ===" > /cases/case-2024-001/analysis/memory_report.txt
echo "镜像：memory.raw" >> /cases/case-2024-001/analysis/memory_report.txt
echo "操作系统：Windows 10 Build 19041" >> /cases/case-2024-001/analysis/memory_report.txt
echo "" >> /cases/case-2024-001/analysis/memory_report.txt

echo "--- 可疑进程 ---" >> /cases/case-2024-001/analysis/memory_report.txt
cat /cases/case-2024-001/analysis/malfind.txt >> /cases/case-2024-001/analysis/memory_report.txt

echo "--- 网络连接 ---" >> /cases/case-2024-001/analysis/memory_report.txt
cat /cases/case-2024-001/analysis/netscan.txt >> /cases/case-2024-001/analysis/memory_report.txt

echo "--- YARA 匹配 ---" >> /cases/case-2024-001/analysis/memory_report.txt
cat /cases/case-2024-001/analysis/yara_hits.txt >> /cases/case-2024-001/analysis/memory_report.txt

# 计算内存转储的哈希以验证完整性
sha256sum /cases/case-2024-001/memory/memory.raw >> /cases/case-2024-001/analysis/memory_report.txt
```

## 关键概念

| 概念 | 描述 |
|------|------|
| 易失性数据（Volatile data） | 仅存在于 RAM 中、断电后丢失的信息 |
| 进程空洞化（Process hollowing） | 恶意软件将合法进程内存替换为恶意代码的技术 |
| DLL 注入（DLL injection） | 向运行中的进程地址空间加载未授权 DLL |
| EPROCESS | 表示进程的 Windows 内核结构；进程列表的基础 |
| 池扫描（Pool scanning） | 在内存中搜索内核对象签名以查找隐藏制品 |
| VAD（虚拟地址描述符） | 跟踪进程虚拟内存区域的内存管理结构 |
| ISF（中间符号格式） | 用于操作系统特定结构定义的 Volatility 3 符号表格式 |
| Malfind | 通过检查 VAD 权限和内容检测注入代码的插件 |

## 工具与系统

| 工具 | 用途 |
|------|------|
| Volatility 3 | 主要的开源内存取证框架 |
| LiME | 用于获取 Linux RAM 转储的 Linux Memory Extractor |
| WinPmem | Windows 物理内存获取驱动程序 |
| DumpIt | Comae 一键式 Windows 内存转储工具 |
| YARA | 用于恶意软件签名扫描的模式匹配引擎 |
| Rekall | 替代内存取证框架（Google） |
| MemProcFS | 用于内存分析的内存进程文件系统 |
| strings | 从二进制内存转储中提取可打印字符串 |

## 常见场景

**场景 1：活跃恶意软件调查**
使用 DumpIt 获取内存，运行 pslist/pstree 识别可疑进程，使用 malfind 检测 svchost.exe 中的注入代码，转储注入的内存段，使用 YARA 规则识别 Cobalt Strike beacon，从 netscan 中提取 C2 IP，与网络日志关联。

**场景 2：数据泄露后的凭据盗取**
运行 hashdump 和 lsadump 提取缓存凭据，在 cmdline 输出中识别 mimikatz 执行，检查文件系统制品中的 lsass.exe 内存转储，与网络连接中的横向移动证据关联。

**场景 3：Rootkit 检测**
比较 pslist（使用 EPROCESS 链表）与 psscan（池扫描）以查找未链接进程，检查 modules 与 modscan 是否存在隐藏内核驱动，检查 SSDT 是否有重定向系统调用的钩子，转储可疑模块进行静态分析。

**场景 4：勒索软件事件恢复**
在系统关机前从勒索软件进程内存中提取加密密钥，使用 YARA 识别勒索软件变种，通过命令行制品找到初始执行点，通过网络连接绘制横向移动路线。

## 输出格式

```
内存取证分析：
  镜像：            memory.raw（16 GB）
  识别操作系统：    Windows 10 x64 Build 19041
  捕获时间：        2024-01-18 14:32:15 UTC

  进程分析：
    进程总数：      87
    隐藏进程：      2（PID：4532, 6128）
    注入进程：      3（malfind 检测到）
    可疑：          svchost.exe（PID 4532）- 0x7FFE0000 处有注入代码

  网络连接：
    总数：        45
    已建立：      12
    可疑：        3（C2 连接至 185.xx.xx.xx:443）

  发现的凭据：
    NTLM 哈希：   4 个账户
    缓存凭据：    2 个域账户

  YARA 匹配：
    CobaltStrike_Beacon：PID 4532（3 次命中）
    Mimikatz_Memory：    PID 6128（1 次命中）

  提取的制品：  15 个文件已转储至 /analysis/extracted/
```
