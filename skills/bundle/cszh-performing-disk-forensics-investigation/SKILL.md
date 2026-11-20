---
name: cszh-performing-disk-forensics-investigation
description: 使用取证镜像、文件系统分析、产物恢复和时间线重建进行磁盘取证调查，以支持事件响应案例。 使用 FTK Imager、Autopsy 和 The Sleuth Kit 等工具进行证据采集、已删除文件恢复和产物检查。 适用于磁盘取证、硬盘分析、取证镜像、文件恢复、证据采集或数字取证调查等请求场景。
---

> 来源：killvxk/cybersecurity-skills-zh 上游技能 `performing-disk-forensics-investigation`，正文为中文原文照录（仅剥离上游 frontmatter）。
> 定位：执行磁盘取证调查（Performing Disk Forensics Investigation）。
> 用法：按正文的「工作流程 / 命令清单 / 输出格式」执行；本技能在 dsh 中的名字是 cszh-performing-disk-forensics-investigation。

# 执行磁盘取证调查（Performing Disk Forensics Investigation）

## 适用场景

- 安全事件需要对系统持久存储进行取证分析
- 潜在法律程序或 HR 调查需要保全证据
- 需要恢复已删除文件、浏览器历史或应用产物
- 需要从文件系统元数据重建用户或攻击者的活动时间线
- 需要识别和记录存储在磁盘上的恶意软件持久化机制

**不适用场景**：易失性证据（运行中的进程、网络连接）；此类情况应改用 Volatility 进行内存取证。

## 前置条件

- 配备硬件或软件写保护设备的取证工作站（Tableau T35u、Arsenal Image Mounter）
- 取证镜像软件：FTK Imager、Guymager 或带 dcfldd 的 dd
- 分析平台：Autopsy、FTK（Forensic Toolkit）或 X-Ways Forensics
- 充足存储空间（目标磁盘大小的 2-3 倍，用于镜像及工作副本）
- 物理介质的证据链记录表和证据袋
- 证据完整性哈希验证工具（SHA-256）

## 工作流程

### 步骤 1：保全并记录证据

触碰任何存储介质前，建立证据链监管：

- 对系统进行拍照，记录序列号、标签和线缆连接
- 记录证据来源：设备类型、品牌、型号、序列号、容量
- 填写包含日期、时间、操作人姓名和采集原因的证据链表
- 将证据磁盘连接到取证工作站时使用硬件写保护设备

```
证据链记录：
━━━━━━━━━━━━━━━━━━━━━━━
案例 ID：          INC-2025-1547
证据 ID：          EVD-001
描述：             三星 870 EVO 500GB SSD
序列号：           S5XXNJ0R912345
来源主机：         WKSTN-042
采集人：           [分析员姓名]
日期/时间：        2025-11-15T16:30:00Z
写保护设备：       Tableau T35u（序列号：T35U-12345）
```

### 步骤 2：创建取证镜像

对证据磁盘进行逐位复制：

**使用 FTK Imager（Windows）：**
1. 通过写保护设备连接证据磁盘
2. 文件 > 创建磁盘镜像 > 选择源磁盘
3. 选择 E01（Expert Witness Format）格式，支持压缩和元数据
4. 设置目标路径和证据项目信息
5. 启用"创建后验证镜像"
6. 记录源磁盘和镜像的哈希值

**使用 dcfldd（Linux）：**
```bash
# 创建带哈希验证的原始镜像
dcfldd if=/dev/sdb of=/evidence/WKSTN-042.dd \
  hash=sha256 hashlog=/evidence/WKSTN-042.sha256 \
  bs=4096 conv=noerror,sync

# 验证镜像完整性
sha256sum /evidence/WKSTN-042.dd
```

```
镜像摘要：
源磁盘：    /dev/sdb（三星 870 EVO 500GB）
镜像文件：  WKSTN-042.E01
镜像格式：  E01（Expert Witness）
源哈希：    SHA-256: a1b2c3d4e5f6...
镜像哈希：  SHA-256: a1b2c3d4e5f6...  （匹配）
读取扇区：  976,773,168
错误：       0
持续时间：  47 分钟
```

### 步骤 3：分析文件系统结构

在 Autopsy 或 FTK 中打开取证镜像并检查文件系统：

- 识别分区布局（MBR/GPT，NTFS/ext4/APFS 分区）
- 检查 NTFS 的主文件表（Master File Table，MFT）或 ext4 的 inode 表
- 识别已删除文件和目录（标记为未分配但尚未覆写）
- 使用文件雕刻（File Carving）从未分配空间恢复文件
- 检查 NTFS 替代数据流（Alternate Data Streams，ADS）中的隐藏数据

**需要检查的关键 Windows 产物：**
```
用户活动：
- NTUSER.DAT（每用户注册表蜂巢）
- UsrClass.dat（Shellbags、文件访问历史）
- 最近文件：%AppData%\Microsoft\Windows\Recent\
- 跳转列表：%AppData%\Microsoft\Windows\Recent\AutomaticDestinations\

程序执行：
- Prefetch：C:\Windows\Prefetch\*.pf
- Amcache：C:\Windows\appcompat\Programs\Amcache.hve
- SRUM：C:\Windows\System32\SRU\SRUDB.dat
- ShimCache：SYSTEM 注册表蜂巢

持久化：
- 计划任务：C:\Windows\System32\Tasks\
- 启动文件夹：%AppData%\Microsoft\Windows\Start Menu\Programs\Startup\
- 服务：SYSTEM 注册表蜂巢

网络：
- WLAN 配置文件：C:\ProgramData\Microsoft\Wlansvc\Profiles\
- 浏览器历史：Chrome、Firefox、Edge 配置目录
```

### 步骤 4：重建时间线

构建文件系统活动的综合时间线：

**使用 Autopsy 时间线模块：**
1. 从所有可用来源（MFT、事件日志、浏览器历史、Prefetch）生成时间线
2. 筛选到调查时间范围
3. 识别与事件相关的活动簇
4. 基于文件创建、修改和访问时间戳记录攻击者行动序列

**使用 The Sleuth Kit（命令行）：**
```bash
# 从 NTFS 镜像生成 body 文件
fls -r -m / WKSTN-042.dd > bodyfile.txt

# 从 body 文件创建时间线
mactime -b bodyfile.txt -d > timeline.csv

# 筛选时间线到调查时间段
grep "2025-11-15" timeline.csv | sort > incident_timeline.csv
```

### 步骤 5：恢复并分析产物

提取和分析特定取证产物：

- **Prefetch 文件**：使用 PECmd 解析以确定程序执行时间和加载的 DLL
- **事件日志**：使用 EvtxECmd 解析 Windows XML 事件日志
- **注册表**：使用 RegRipper 或 Registry Explorer 解析用户活动和系统配置
- **浏览器产物**：使用 Hindsight（Chrome）、KAPE 或 DB Browser 处理 SQLite 数据库
- **USB 设备历史**：从 SYSTEM\CurrentControlSet\Enum\USBSTOR 注册表键提取
- **$MFT 分析**：使用 MFTECmd 解析，包含 $SI 和 $FN 时间戳的详细文件元数据

### 步骤 6：记录发现

编写适合法律程序的取证分析报告：

- 维护证据完整性文档（哈希链）
- 记录使用的每个工具及其版本
- 以可重现的方式记录所有分析步骤
- 客观地呈现发现，不作推测
- 明确区分事实（观察到的数据）和解释（分析员结论）

## 核心概念

| 术语 | 定义 |
|------|------|
| **取证镜像（Forensic Image）** | 存储介质的逐位副本，保留所有数据，包括已删除文件和未分配空间 |
| **写保护设备（Write Blocker）** | 防止在采集过程中对证据介质进行任何修改的硬件或软件设备 |
| **E01 格式** | EnCase 和 FTK 使用的 Expert Witness Format；支持压缩、元数据和内置哈希验证 |
| **文件雕刻（File Carving）** | 在未分配磁盘空间中搜索文件头和尾部以重建已删除文件的恢复技术 |
| **MFT（主文件表）** | NTFS 元数据结构，包含每个文件和目录的条目，包括已删除条目 |
| **MAC 时间戳** | 文件的修改（Modified）、访问（Accessed）、创建（Created）时间戳，用于时间线重建（NTFS 还有条目修改时间） |
| **Prefetch** | 记录程序执行元数据的 Windows 产物；包含执行次数、时间戳和加载的 DLL |
| **未分配空间（Unallocated Space）** | 未分配给任何文件的磁盘扇区；可能包含通过雕刻恢复的已删除文件残留 |

## 工具与系统

- **FTK Imager**：免费取证镜像工具，支持 E01、AFF 和原始格式，内置哈希验证
- **Autopsy**：基于 The Sleuth Kit 构建的开源数字取证平台，用于全面磁盘分析
- **KAPE（Kroll Artifact Parser and Extractor）**：用于快速产物提取的分类采集和解析工具
- **X-Ways Forensics**：商业取证分析工具，以大型数据集的速度和效率著称
- **Eric Zimmerman 工具套件**：免费 Windows 产物解析器套件（PECmd、MFTECmd、EvtxECmd、RegRipper）

## 常见场景

### 场景：员工数据盗窃调查

**背景**：员工已提交辞职，怀疑在离职前将专有文件复制到 USB 驱动器。HR 要求对员工工作站进行取证调查。

**方法**：
1. 使用写保护设备通过 FTK Imager 对工作站磁盘进行镜像
2. 从 SYSTEM 注册表解析 USB 设备历史，识别已连接设备
3. 检查 Shellbags 和跳转列表，查找文件浏览和复制到可移动介质的证据
4. 解析"最近"文件夹中的 LNK 文件，识别最近访问的文档
5. 分析浏览器历史，查找个人云存储上传（Google Drive、Dropbox）
6. 构建时间线，将 USB 连接事件与文件访问事件关联

**注意事项**：
- IT 部门重新分配工作站前未能及时镜像磁盘
- 未将云存储浏览历史与 USB 证据一并检查
- 忽视了可能包含已删除文件早期版本的卷影副本
- 将分析结论作为事实呈现而缺乏支撑证据文档

## 输出格式

```
磁盘取证调查报告
=====================================
案例 ID：          INC-2025-1547
证据：             EVD-001（三星 870 EVO 500GB SSD）
检查人：           [姓名]
分析日期：         2025-11-16

证据完整性
源哈希：      SHA-256: a1b2c3d4e5f6...
镜像哈希：    SHA-256: a1b2c3d4e5f6... （验证匹配）
写保护设备：  Tableau T35u

分区布局
分区 1：  NTFS  100 MB   （系统保留）
分区 2：  NTFS  465 GB   （C: - 操作系统和数据）
分区 3：  NTFS  500 MB   （恢复分区）

关键发现
1. [时间戳] - 恶意软件投放器在 %TEMP% 创建（update.exe）
2. [时间戳] - 创建计划任务 "WindowsUpdate" 以实现持久化
3. [时间戳] - Prefetch 显示 update.exe 执行 14 次
4. [时间戳] - USB 设备 "Kingston DataTraveler" 已连接
5. [时间戳] - 847 个文件复制到 E:\ 驱动器（Shellbag 证据）

已恢复产物
- 从未分配空间恢复 3 个已删除恶意软件样本
- 浏览器历史显示访问过 C2 控制面板
- 注册表证据显示安全软件被禁用

时间线
[按时间顺序列出事件，包含时间戳和证据来源]

使用工具
- FTK Imager 4.7.1（镜像）
- Autopsy 4.21.0（分析）
- PECmd 1.5.0（Prefetch 解析）
- MFTECmd 1.2.2（MFT 分析）
```
