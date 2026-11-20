---
name: analyzing-bootkit-and-rootkit-samples
description: >
  分析感染主引导记录（MBR）、卷引导记录（VBR）或 UEFI 固件以在操作系统底层获取持久化的 bootkit 和高级 rootkit 恶意软件。
  涵盖引导扇区分析、UEFI 模块检查和反 rootkit 检测技术。
  适用于 bootkit 分析、MBR 恶意软件调查、UEFI 持久化分析或 OS 前恶意软件检测相关请求。
domain: cybersecurity
subdomain: malware-analysis
tags: [malware, bootkit, rootkit, UEFI, MBR-analysis]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# 分析 Bootkit 和 Rootkit 样本

## 适用场景

- 系统在操作系统重装后仍存在持续性被攻陷迹象
- 尽管有明确的被攻陷证据，但杀毒软件和 EDR 均无法检测到恶意软件
- UEFI Secure Boot 已被禁用或显示完整性违规
- 内存取证（Memory Forensics）揭示 rootkit 行为（隐藏进程、系统调用挂钩）
- 调查已知部署 bootkit 的国家级威胁（APT28、APT41、方程式组织）

**不适用于**标准用户态恶意软件；bootkit 和 rootkit 运行在完全不同的层级，需要专门的分析技术。

## 前置条件

- 磁盘镜像工具（dd、FTK Imager）用于获取 MBR/VBR 扇区
- UEFITool 用于 UEFI 固件卷分析和模块提取
- chipsec 用于硬件级固件安全评估
- Ghidra，支持 x86 实模式和 16 位模式用于 MBR 代码分析
- Volatility 3 用于内核级 rootkit 工件检测
- 可引导的 Linux Live USB 用于离线系统分析

## 工作流程

### 步骤 1：获取引导扇区和固件

提取 MBR、VBR 和 UEFI 固件用于离线分析：

```bash
# 获取 MBR（磁盘前 512 字节）
dd if=/dev/sda of=mbr.bin bs=512 count=1

# 获取第一磁道（通常包含 MBR 之外的 bootkit 代码）
dd if=/dev/sda of=first_track.bin bs=512 count=63

# 获取 VBR（卷引导记录 - 分区的第一个扇区）
dd if=/dev/sda1 of=vbr.bin bs=512 count=1

# 获取 UEFI 系统分区
mkdir /mnt/efi
mount /dev/sda1 /mnt/efi
cp -r /mnt/efi/EFI /analysis/efi_backup/

# 转储 UEFI 固件（需要 chipsec 或 flashrom）
# 使用 chipsec：
python chipsec_util.py spi dump firmware.rom

# 使用 flashrom：
flashrom -p internal -r firmware.rom

# 验证固件转储完整性
sha256sum firmware.rom
```

### 步骤 2：分析 MBR/VBR 中的 Bootkit 代码

检查引导扇区代码中的恶意修改：

```bash
# 反汇编 MBR 代码（16 位实模式）
ndisasm -b16 mbr.bin > mbr_disasm.txt

# 与已知正常的 Windows MBR 对比
# 标准 Windows MBR 以 EB 5A 90（JMP 0x5C, NOP）开头
# 标准 Windows 10 MBR：33 C0 8E D0 BC 00 7C（XOR AX,AX; MOV SS,AX; MOV SP,7C00h）

python3 << 'PYEOF'
with open("mbr.bin", "rb") as f:
    mbr = f.read()

# 检查 MBR 签名（510-511 字节应为 0x55AA）
if mbr[510:512] == b'\x55\xAA':
    print("[*] 有效的 MBR 签名 (0x55AA)")
else:
    print("[!] 无效的 MBR 签名")

# 检查已知 bootkit 签名
bootkit_sigs = {
    b'\xE8\x00\x00\x5E\x81\xEE': "TDL4/Alureon bootkit",
    b'\xFA\x33\xC0\x8E\xD0\xBC\x00\x7C\x8B\xF4\x50\x07': "标准 Windows MBR（干净）",
    b'\xEB\x5A\x90\x4E\x54\x46\x53': "标准 NTFS VBR（干净）",
}

for sig, name in bootkit_sigs.items():
    if sig in mbr:
        print(f"[{'!' if '干净' not in name else '*'}] 签名匹配：{name}")

# 检查分区表条目
print("\n分区表：")
for i in range(4):
    offset = 446 + (i * 16)
    entry = mbr[offset:offset+16]
    if entry != b'\x00' * 16:
        boot_flag = "活动" if entry[0] == 0x80 else "非活动"
        part_type = entry[4]
        start_lba = int.from_bytes(entry[8:12], 'little')
        size_lba = int.from_bytes(entry[12:16], 'little')
        print(f"  分区 {i+1}: 类型=0x{part_type:02X} {boot_flag} 起始=LBA {start_lba} 大小={size_lba} 扇区")
PYEOF
```

### 步骤 3：分析 UEFI 固件中的植入物

检查 UEFI 固件卷中的未授权模块：

```bash
# 使用 UEFITool 提取 UEFI 固件组件
# GUI：打开 firmware.rom -> 检查固件卷
# CLI：
UEFIExtract firmware.rom all

# 列出所有 DXE 驱动（UEFI 植入物最常见的目标）
find firmware.rom.dump -name "*.efi" -exec file {} \;

# 与已知正常的固件模块列表对比
# 每个 UEFI 模块都有一个 GUID - 与厂商基线对比

# 验证 Secure Boot 配置
python chipsec_main.py -m common.secureboot.variables

# 检查 SPI 闪存写保护
python chipsec_main.py -m common.bios_wp

# 检查已知 UEFI 恶意软件模式
yara -r uefi_malware.yar firmware.rom
```

```
已知 UEFI Bootkit 检测点：
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
LoJax（APT28）：
  - 修改 SPI 闪存
  - 添加 DXE 驱动，在 Windows 启动时植入 agent
  - 持久化于操作系统重装和磁盘更换之后

BlackLotus：
  - 利用 CVE-2022-21894 绕过 Secure Boot
  - 修改 EFI 系统分区引导程序
  - 在启动时安装内核驱动

CosmicStrand：
  - 修改 CORE_DXE 固件模块
  - 在启动期间挂钩内核初始化
  - 将 shellcode 植入 Windows 内核内存

MoonBounce：
  - SPI 闪存植入于 CORE_DXE 模块
  - 修改 GetVariable() 函数
  - 通过启动链部署用户态植入物

ESPecter：
  - 修改 ESP 上的 Windows Boot Manager
  - 修补 winload.efi 以禁用 DSE
  - 加载未签名的内核驱动
```

### 步骤 4：检测内核级 Rootkit 行为

分析运行中系统的 rootkit 工件：

```bash
# 用于 rootkit 检测的内存取证
# SSDT 挂钩检测
vol3 -f memory.dmp windows.ssdt | grep -v "ntoskrnl\|win32k"

# 隐藏进程（DKOM）
vol3 -f memory.dmp windows.psscan > psscan.txt
vol3 -f memory.dmp windows.pslist > pslist.txt
# 对比以发现隐藏进程

# 内核回调注册（rootkit 注册回调用于过滤）
vol3 -f memory.dmp windows.callbacks

# 驱动分析
vol3 -f memory.dmp windows.driverscan
vol3 -f memory.dmp windows.modules

# 检查未签名驱动
vol3 -f memory.dmp windows.driverscan | while read line; do
    driver_path=$(echo "$line" | awk '{print $NF}')
    if [ -f "$driver_path" ]; then
        sigcheck -nobanner "$driver_path" 2>/dev/null | grep "Unsigned"
    fi
done

# IDT 挂钩检测
vol3 -f memory.dmp windows.idt
```

### 步骤 5：引导流程完整性验证

验证整个引导链的完整性：

```bash
# 验证 Windows Boot Manager 签名
sigcheck -a C:\Windows\Boot\EFI\bootmgfw.efi

# 验证 winload.efi
sigcheck -a C:\Windows\System32\winload.efi

# 验证 ntoskrnl.exe
sigcheck -a C:\Windows\System32\ntoskrnl.exe

# 检查测量启动日志（如有 TPM）
# Windows：BCDEdit /enum firmware
bcdedit /enum firmware

# 验证 Secure Boot 状态
Confirm-SecureBootUEFI  # PowerShell 命令

# 检查引导配置是否被篡改
bcdedit /v

# 查找引导配置更改
# testsigning：应为 No
# nointegritychecks：应为 No
# debug：应为 No
bcdedit | findstr /i "testsigning nointegritychecks debug"
```

### 步骤 6：记录 Bootkit/Rootkit 分析结果

整理综合分析发现：

```
分析应记录：
- 引导扇区（MBR/VBR）完整性状态（含十六进制对比）
- UEFI 固件模块清单及完整性验证
- Secure Boot 状态及检测到的任何绕过机制
- 识别的内核级挂钩（SSDT、IDT、IRP、内联）
- 发现的隐藏进程、驱动和文件
- 持久化机制（SPI 闪存、ESP、MBR、内核驱动）
- 引导链完整性验证结果
- 与已知 bootkit 家族的溯源归因（如可能）
- 修复步骤（重刷固件、重建 MBR、更换硬件）
```

## 核心概念

| 术语 | 定义 |
|------|------------|
| **Bootkit（引导工具包）** | 感染引导流程（MBR、VBR、UEFI）的恶意软件，在操作系统加载之前执行，获取持久化的低级控制权 |
| **MBR（主引导记录）** | 磁盘的前 512 字节，包含引导代码和分区表；MBR bootkit 将此代码替换为恶意加载器 |
| **UEFI（统一可扩展固件接口）** | 取代 BIOS 的现代固件接口；UEFI bootkit 将恶意模块植入固件卷或修改 ESP |
| **Secure Boot（安全启动）** | 验证引导组件数字签名的 UEFI 安全功能；BlackLotus 等 bootkit 利用漏洞绕过它 |
| **SPI Flash（SPI 闪存）** | 存储 UEFI 固件的闪存芯片；LoJax 和 MoonBounce 等高级 bootkit 修改 SPI 闪存以实现固件级持久化 |
| **DKOM（直接内核对象操作）** | Rootkit 技术，通过修改内核结构隐藏进程、文件和网络连接，而无需挂钩函数 |
| **DSE（驱动签名强制）** | 要求内核驱动经过数字签名的 Windows 安全功能；bootkit 在启动时禁用 DSE 以加载未签名的 rootkit 驱动 |

## 工具与系统

- **UEFITool**：开源 UEFI 固件镜像编辑器和解析器，用于检查固件卷、驱动和模块
- **chipsec**：英特尔硬件安全评估框架，用于验证 SPI 闪存保护、Secure Boot 和 UEFI 配置
- **Volatility**：内存取证框架，具有 SSDT、IDT、回调和驱动分析插件用于内核 rootkit 检测
- **GMER**：Windows rootkit 检测工具，扫描 SSDT 挂钩、IDT 挂钩、隐藏进程和修改过的内核模块
- **Bootkits Analyzer**：专用工具，用于分析 MBR/VBR 代码，包括反汇编和与已知正常基线对比

## 常见场景

### 场景：调查在操作系统重装后仍存在的持续性入侵

**场景背景**：某组织对一台被攻陷的工作站重新镜像，但同样的 C2 信标在几小时内恢复。标准磁盘取证未发现恶意软件。怀疑存在 UEFI bootkit。

**方法**：
1. 从 Linux Live USB 启动，避免执行任何被攻陷的操作系统组件
2. 使用 chipsec 或 flashrom 转储 SPI 闪存固件用于离线分析
3. 用 dd 转储 MBR 和 VBR 扇区用于引导扇区分析
4. 复制 EFI 系统分区用于引导程序完整性验证
5. 在 UEFITool 中打开 SPI 转储，将模块 GUID 与厂商提供的固件对比
6. 查找不应存在的额外或修改过的 DXE 驱动
7. 使用 Ghidra 分析任何可疑模块（x86_64 UEFI 模块格式）
8. 验证 Secure Boot 配置，检查基于漏洞利用的绕过

**常见陷阱**：
- 在被攻陷的操作系统运行时分析系统（rootkit 可能对实时分析隐藏自身）
- 不检查 SPI 闪存（仅分析磁盘引导组件会遗漏固件级植入物）
- 假设 Secure Boot 能阻止所有 bootkit（已知绕过方法存在，如 CVE-2022-21894）
- 重刷前未保留原始固件转储（溯源归因的关键证据）

## 输出格式

```
BOOTKIT / ROOTKIT 分析报告
====================================
系统：           Dell OptiPlex 7090（UEFI，TPM 2.0）
固件版本：       1.15.0（Dell）
Secure Boot：    已启用（但已被绕过）
获取方式：       Linux Live USB + chipsec SPI 转储

MBR/VBR 分析
MBR 签名：       有效（0x55AA）
MBR 代码：       与标准 Windows 10 MBR 匹配（干净）
VBR 代码：       与标准 NTFS VBR 匹配（干净）

UEFI 固件分析
总模块数：       287
厂商预期：       285
额外模块：       2 个未授权
  [!] DXE 驱动 GUID：{ABCD1234-...} "SmmAccessDxe_mod"（已修改）
      原始大小：12,288 字节
      当前大小：45,056 字节（新增 32KB）
      熵值：7.82（高 - 加密载荷）

  [!] DXE 驱动 GUID：{EFGH5678-...} "UefiPayloadDxe"（新增 - 厂商固件中不存在）
      大小：28,672 字节
      功能：在启动时植入持久化 agent

引导链完整性
bootmgfw.efi：   已修改（哈希不匹配，通过 CVE-2022-21894 绕过 Secure Boot）
winload.efi：    已修改（加载时禁用 DSE）
ntoskrnl.exe：   干净（但启动后加载了未签名驱动）

内核 Rootkit 组件
驱动：           C:\Windows\System32\drivers\null_mod.sys（未签名，已隐藏）
SSDT 挂钩：      3 处（NtQuerySystemInformation、NtQueryDirectoryFile、NtDeviceIoControlFile）
隐藏进程：       2 个（PID 6784：beacon.exe，PID 6812：keylog.exe）
隐藏文件：       C:\Windows\System32\drivers\null_mod.sys

溯源归因
家族：           BlackLotus 变种
可信度：         高（CVE-2022-21894 漏洞利用，ESP 修改模式匹配）

修复措施
1. 通过硬件编程器用干净的厂商镜像重刷 SPI 固件
2. 从干净的 Windows 安装介质重建 EFI 系统分区
3. 从已验证的介质重装操作系统
4. 启用所有固件写保护
5. 将固件更新至最新版本（修复 CVE-2022-21894）
```
