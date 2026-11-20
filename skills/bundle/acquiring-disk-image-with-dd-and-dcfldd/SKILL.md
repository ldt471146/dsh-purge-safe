---
name: acquiring-disk-image-with-dd-and-dcfldd
description: 使用 dd 和 dcfldd 创建取证级逐位磁盘镜像，通过哈希验证保持证据完整性。
domain: cybersecurity
subdomain: digital-forensics
tags: [forensics, disk-imaging, evidence-acquisition, dd, dcfldd, hash-verification]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# 使用 dd 和 dcfldd 获取磁盘镜像

## 适用场景
- 需要为调查创建嫌疑驱动器的取证副本时
- 事件响应（Incident Response）期间，在分析前需要保全易失性磁盘证据时
- 法律执行或法律程序要求经过验证的逐位副本时
- 在对存储设备执行任何破坏性分析之前
- 从物理驱动器、USB 设备或存储卡获取镜像时

## 前置条件
- 基于 Linux 的取证工作站（SIFT、Kali 或任意 Linux 发行版）
- `dd`（预装于所有 Linux 系统）或 `dcfldd`（增强版取证工具）
- 已配置硬件写保护器或软件写保护
- 目标驱动器有足够存储空间（大于源设备）
- 取证工作站上的 root/sudo 权限
- SHA-256 或 MD5 哈希工具（`sha256sum`、`md5sum`）

## 工作流程

### 步骤 1：识别目标设备并启用写保护

```bash
# 列出所有已连接的块设备以识别目标
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,MODEL

# 验证设备详情
fdisk -l /dev/sdb

# 启用软件写保护（如果没有硬件写保护器）
blockdev --setro /dev/sdb

# 验证只读状态
blockdev --getro /dev/sdb
# 输出: 1（表示已启用只读）

# 或者，使用 udev 规则实现持久写保护
echo 'SUBSYSTEM=="block", ATTRS{serial}=="WD-WCAV5H861234", ATTR{ro}="1"' > /etc/udev/rules.d/99-writeblock.rules
udevadm control --reload-rules
```

### 步骤 2：准备目标位置并记录来源信息

```bash
# 创建案件目录结构
mkdir -p /cases/case-2024-001/{images,hashes,logs,notes}

# 记录源驱动器信息
hdparm -I /dev/sdb > /cases/case-2024-001/notes/source_drive_info.txt

# 记录序列号和型号
smartctl -i /dev/sdb >> /cases/case-2024-001/notes/source_drive_info.txt

# 预先对源设备进行哈希计算
sha256sum /dev/sdb | tee /cases/case-2024-001/hashes/source_hash_before.txt
```

### 步骤 3：使用 dd 获取镜像

```bash
# 带进度显示和错误处理的基本 dd 获取
dd if=/dev/sdb of=/cases/case-2024-001/images/evidence.dd \
   bs=4096 \
   conv=noerror,sync \
   status=progress 2>&1 | tee /cases/case-2024-001/logs/dd_acquisition.log

# 压缩镜像以节省空间
dd if=/dev/sdb bs=4096 conv=noerror,sync status=progress | \
   gzip -c > /cases/case-2024-001/images/evidence.dd.gz

# 使用 dd 进行部分获取（指定数量）
dd if=/dev/sdb of=/cases/case-2024-001/images/first_1gb.dd \
   bs=1M count=1024 status=progress
```

### 步骤 4：使用 dcfldd 获取（推荐的取证方法）

```bash
# 如果未安装则安装 dcfldd
apt-get install dcfldd

# 带内置哈希和分割输出的镜像获取
dcfldd if=/dev/sdb \
   of=/cases/case-2024-001/images/evidence.dd \
   hash=sha256,md5 \
   hashwindow=1G \
   hashlog=/cases/case-2024-001/hashes/acquisition_hashes.txt \
   bs=4096 \
   conv=noerror,sync \
   errlog=/cases/case-2024-001/logs/dcfldd_errors.log

# 将大型镜像分割成可管理的段
dcfldd if=/dev/sdb \
   of=/cases/case-2024-001/images/evidence.dd \
   hash=sha256 \
   hashlog=/cases/case-2024-001/hashes/split_hashes.txt \
   bs=4096 \
   split=2G \
   splitformat=aa

# 带验证的获取
dcfldd if=/dev/sdb \
   of=/cases/case-2024-001/images/evidence.dd \
   hash=sha256 \
   hashlog=/cases/case-2024-001/hashes/verification.txt \
   vf=/cases/case-2024-001/images/evidence.dd \
   verifylog=/cases/case-2024-001/logs/verify.log
```

### 步骤 5：验证镜像完整性

```bash
# 对获取的镜像进行哈希计算
sha256sum /cases/case-2024-001/images/evidence.dd | \
   tee /cases/case-2024-001/hashes/image_hash.txt

# 比较源和镜像的哈希值
diff <(sha256sum /dev/sdb | awk '{print $1}') \
     <(sha256sum /cases/case-2024-001/images/evidence.dd | awk '{print $1}')

# 如果使用分割镜像，验证每个段
sha256sum /cases/case-2024-001/images/evidence.dd.* | \
   tee /cases/case-2024-001/hashes/split_image_hashes.txt

# 重新对源进行哈希以确认未发生变化
sha256sum /dev/sdb | tee /cases/case-2024-001/hashes/source_hash_after.txt
diff /cases/case-2024-001/hashes/source_hash_before.txt \
     /cases/case-2024-001/hashes/source_hash_after.txt
```

### 步骤 6：记录获取过程

```bash
# 生成获取报告
cat << 'EOF' > /cases/case-2024-001/notes/acquisition_report.txt
DISK IMAGE ACQUISITION REPORT
==============================
Case Number: 2024-001
Date/Time: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Examiner: [Name]

Source Device: /dev/sdb
Model: [from hdparm output]
Serial: [from hdparm output]
Size: [from fdisk output]

Acquisition Tool: dcfldd v1.9.1
Block Size: 4096
Write Blocker: [Hardware/Software model]

Image File: evidence.dd
Image Hash (SHA-256): [from hash file]
Source Hash (SHA-256): [from hash file]
Hash Match: YES/NO

Errors During Acquisition: [from error log]
EOF

# 压缩日志以归档
tar -czf /cases/case-2024-001/acquisition_package.tar.gz \
   /cases/case-2024-001/hashes/ \
   /cases/case-2024-001/logs/ \
   /cases/case-2024-001/notes/
```

## 核心概念

| 概念 | 定义 |
|------|------|
| 逐位副本（Bit-for-bit copy） | 包括未分配空间和松弛空间在内的源完整副本 |
| 写保护器（Write blocker） | 防止向证据介质写入的硬件或软件机制 |
| 哈希验证（Hash verification） | 通过比较源和镜像的加密哈希来证明完整性 |
| 块大小（Block size，bs） | 影响速度的传输块大小；取证通常使用 4096 或 64K |
| conv=noerror,sync | 读取错误时继续，并用零填充以保持偏移对齐 |
| 证据监管链（Chain of custody） | 证明证据未被篡改的文档记录链 |
| 分割镜像（Split imaging） | 将大型镜像分割成较小文件以便存储和传输 |
| 原始/dd 格式（Raw/dd format） | 不含元数据容器开销的逐位镜像格式 |

## 工具与系统

| 工具 | 用途 |
|------|------|
| dd | 用于原始镜像的标准 Unix 磁盘复制工具 |
| dcfldd | 美国国防部计算机取证实验室（DoD）增强版 dd，带哈希功能 |
| dc3dd | 来自 DoD 网络犯罪中心的另一个取证 dd 变体 |
| sha256sum | 用于完整性验证的 SHA-256 哈希计算工具 |
| blockdev | 将块设备设为只读模式的 Linux 命令 |
| hdparm | 驱动器识别和参数报告工具 |
| smartctl | 用于驱动器健康和识别的 S.M.A.R.T. 数据获取工具 |
| lsblk | 块设备枚举和识别工具 |

## 常见场景

**场景：获取嫌疑笔记本电脑硬盘**
通过 Tableau T35u 硬件写保护器连接驱动器，识别为 `/dev/sdb`，使用带 SHA-256 哈希的 dcfldd，分割为 4GB 段用于 DVD 归档，验证哈希匹配，在案件记录中记录文档。

**场景：对受损工作站的 USB 闪存驱动器进行镜像**
使用 `blockdev --setro` 进行软件写保护，使用包含 MD5 和 SHA-256 双重哈希的 dcfldd 获取，镜像足够小可存为单个文件，验证后存储在加密的案件驱动器上。

**场景：通过网络进行远程获取**
使用 dd 通过 netcat 或 ssh 管道进行远程获取：`ssh root@remote "dd if=/dev/sda bs=4096" | dd of=remote_image.dd bs=4096`，在两端独立计算哈希以验证传输完整性。

**场景：从故障驱动器获取**
首先使用 `ddrescue` 恢复可读扇区，然后使用带 `conv=noerror,sync` 的 dd 用零填充空缺，在错误日志中记录哪些扇区不可读。

## 输出格式

```
获取摘要:
  源:       /dev/sdb (500GB Western Digital WD5000AAKX)
  目标:     /cases/case-2024-001/images/evidence.dd
  工具:     dcfldd 1.9.1
  块大小:   4096 bytes
  耗时:     2h 15m 32s
  已复制:   500,107,862,016 字节
  错误:     0 个坏扇区
  源 SHA-256:  a3f2b8c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
  镜像 SHA-256: a3f2b8c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
  验证结果: 通过 - 哈希匹配
```
