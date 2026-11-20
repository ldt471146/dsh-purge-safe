---
name: cszh-performing-privilege-escalation-on-linux
description: Linux 权限提升是指在已控制的系统上从低权限用户账户提升至 root 访问权限。红队通过利用错误配置、存在漏洞的服务、内核漏洞利用和弱权限来实现 root 访问。
---

> 本技能源自中文网络安全技能库 killvxk/cybersecurity-skills-zh（上游目录 performing-privilege-escalation-on-linux），正文按中文原文照录。

**这个技能干什么**：Linux 权限提升是指在已控制的系统上从低权限用户账户提升至 root 访问权限。红队通过利用错误配置、存在漏洞的服务、内核漏洞利用和弱权限来实现 root 访问。

**什么时候用**：需要按上游中文方法论执行「performing-privilege-escalation-on-linux」对应任务时加载本技能。

**关键工具**：见正文各章节列出的命令与工具清单。

# 在 Linux 上执行权限提升

## 概述

Linux 权限提升是指在已控制的系统上从低权限用户账户提升至 root 访问权限。红队通过利用错误配置、存在漏洞的服务、内核漏洞利用和弱权限来实现 root。本技能涵盖手动枚举技术和用于识别及利用权限提升向量的自动化工具。

## MITRE ATT&CK 映射

- **T1548.001** - 滥用权限提升控制机制：Setuid 和 Setgid
- **T1548.003** - 滥用权限提升控制机制：Sudo 和 Sudo 缓存
- **T1068** - 利用漏洞进行权限提升
- **T1574.006** - 劫持执行流：动态链接器劫持
- **T1053.003** - 计划任务/作业：Cron
- **T1543.002** - 创建或修改系统进程：Systemd 服务

## 主要提升向量

### SUID/SGID 二进制文件
- 查找 SUID 二进制文件：`find / -perm -4000 -type f 2>/dev/null`
- 查看 GTFOBins 获取利用方法
- 自定义 SUID 二进制文件可能存在漏洞

### Sudo 错误配置
- `sudo -l` 列出允许的命令
- sudo 规则中的通配符允许注入
- 危险命令的 NOPASSWD 条目
- sudo 版本易受 CVE-2021-3156（Baron Samedit）攻击

### 内核漏洞利用
- Dirty Cow（CVE-2016-5195）适用于较旧内核
- Dirty Pipe（CVE-2022-0847）适用于内核 5.8+
- PwnKit（CVE-2021-4034）针对 pkexec
- GameOver(lay)（CVE-2023-2640、CVE-2023-32629）针对 Ubuntu

### Cron 作业滥用
- 全局可写的 cron 脚本
- cron 作业中的 PATH 劫持
- cron 命令中的通配符注入

### Capabilities（能力）
- `getcap -r / 2>/dev/null` 查找具有 capabilities 的二进制文件
- cap_setuid 允许 UID 操控
- cap_dac_override 绕过文件权限

### 可写服务文件
- 权限较弱的 Systemd 单元文件
- 非 root 用户可写的 Init 脚本
- 可访问位置的 Socket 文件

## 工具与资源

| 工具 | 用途 |
|------|---------|
| LinPEAS | 自动化权限提升枚举 |
| LinEnum | Linux 枚举脚本 |
| linux-exploit-suggester | 内核漏洞匹配 |
| pspy | 无需 root 的进程监控 |
| GTFOBins | SUID/sudo 二进制文件利用参考 |
| PEASS-ng | 权限提升工具套件 |

## 验证标准

- [ ] 已使用自动化工具执行枚举
- [ ] 已识别权限提升向量
- [ ] 已通过识别的向量获取 root 访问权限
- [ ] 已记录证据（截图、命令输出）
- [ ] 已识别替代提升路径
