---
name: cszh-analyzing-linux-kernel-rootkits
description: 使用 Volatility3 Linux 插件（check_syscall、lsmod、hidden_modules）分析 Linux 内存转储，结合 rkhunter 系统扫描和 /proc 与 /sys 差异分析，检测 hooked syscall、隐藏内核模块和被篡改的系统结构，以识别内核级 rootkit。
---

> 本技能源自中文网络安全技能库 killvxk/cybersecurity-skills-zh（上游目录 analyzing-linux-kernel-rootkits），正文按中文原文照录。

**这个技能干什么**：使用 Volatility3 Linux 插件（check_syscall、lsmod、hidden_modules）分析 Linux 内存转储，结合 rkhunter 系统扫描和 /proc 与 /sys 差异分析，检测 hooked syscall、隐藏内核模块和被篡改的系统结构，以识别内核级 rootkit。

**什么时候用**：需要按上游中文方法论执行「analyzing-linux-kernel-rootkits」对应任务时加载本技能。

**关键工具**：见正文各章节列出的命令与工具清单。

# 分析 Linux 内核 Rootkit

## 概述

Linux 内核 rootkit 在 ring 0 层级运行，通过修改内核数据结构来对用户态工具隐藏进程、文件、网络连接和内核模块。检测方法需要使用内存取证（使用 Volatility3 分析物理内存转储）或交叉视图分析（比对 /proc、/sys 和内核数据结构的不一致性）。本 skill 涵盖使用 Volatility3 Linux 插件检测 syscall 表 hook、隐藏内核模块和被修改的函数指针，以及使用 rkhunter 和 chkrootkit 进行实时系统扫描。

## 前置条件

- 已安装 Volatility3（pip install volatility3）
- Linux 内存转储（通过 LiME、AVML 或 /proc/kcore 获取）
- 与目标内核版本匹配的 Volatility3 Linux 符号表（ISF）
- 用于实时系统扫描的 rkhunter 和 chkrootkit
- 用于比对的已知良好内核镜像

## 步骤

### 步骤 1：获取内存转储
使用 LiME 内核模块或针对云实例的 AVML 捕获 Linux 物理内存。

### 步骤 2：使用 Volatility3 分析
运行 linux.check_syscall、linux.lsmod、linux.hidden_modules 和 linux.check_idt 插件以检测 rootkit 痕迹。

### 步骤 3：交叉视图分析
比较来自 /proc/modules、lsmod 和 /sys/module 的模块列表，识别在某一视图中隐藏但在另一视图中存在的模块。

### 步骤 4：实时系统扫描
运行 rkhunter 和 chkrootkit，检测已知 rootkit 特征、可疑文件和被修改的系统二进制文件。

## 预期输出

JSON 报告，包含检测到的 syscall hook、隐藏内核模块、被修改的 IDT 条目、可疑的 /proc 差异以及 rkhunter 发现。
