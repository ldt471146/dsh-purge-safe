---
name: cszh-hunting-for-lateral-movement-via-wmi
description: 通过分析 Windows 事件 ID 4688 进程创建和 Sysmon 事件 ID 1 中的 WmiPrvSE.exe 子进程模式、远程进程执行以及 WMI 事件订阅持久化，检测基于 WMI 的横向移动。
---

> 本技能源自中文网络安全技能库 killvxk/cybersecurity-skills-zh（上游目录 hunting-for-lateral-movement-via-wmi），正文按中文原文照录。

**这个技能干什么**：通过分析 Windows 事件 ID 4688 进程创建和 Sysmon 事件 ID 1 中的 WmiPrvSE.exe 子进程模式、远程进程执行以及 WMI 事件订阅持久化，检测基于 WMI 的横向移动。

**什么时候用**：需要按上游中文方法论执行「hunting-for-lateral-movement-via-wmi」对应任务时加载本技能。

**关键工具**：见正文各章节列出的命令与工具清单。

# 狩猎通过 WMI 进行的横向移动

## 概述

Windows Management Instrumentation（WMI）常被滥用于横向移动，方式包括 `wmic process call create` 或 Win32_Process.Create() 在远程主机执行命令。检测重点在于：识别 WmiPrvSE.exe 在 Windows 安全事件 ID 4688 和 Sysmon 事件 ID 1 日志中派生子进程（cmd.exe、powershell.exe），以及 WMI-Activity/Operational 事件（5857、5860、5861）中的事件订阅持久化行为。

## 前置条件

- 启用了进程创建审计的 Windows 安全事件日志（事件 4688，含命令行）
- 安装了 Sysmon 并配置了事件 ID 1（进程创建）
- Python 3.9+ 及 `python-evtx`、`lxml` 库
- 了解 WMI 架构和 WmiPrvSE.exe 行为

## 步骤

### 步骤 1：解析进程创建事件
从 EVTX 文件中提取事件 ID 4688 和 Sysmon 事件 1 条目。

### 步骤 2：检测 WmiPrvSE 子进程
标记 ParentImage/ParentProcessName 为 WmiPrvSE.exe 的进程，表示存在远程 WMI 执行。

### 步骤 3：分析命令行模式
识别匹配 WMI 横向移动模式的可疑命令行（cmd.exe /q /c、输出重定向到 admin$ 共享）。

### 步骤 4：检查 WMI 事件订阅
解析 WMI-Activity/Operational 日志，查找表明持久化的事件消费者创建事件。

## 预期输出

JSON 报告，包含 WMI 派生的进程、可疑命令行、WMI 事件订阅告警以及横向移动活动的时间线。
