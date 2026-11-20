---
name: hfh-privilege-escalation
description: 网络安全知识库「权限提升」分类技能包，源自 Hi-FullHouse/CyberSecurity-Skills 上游 04-权限提升-PrivilegeEscalation。覆盖 Linux 提权（SUID/SGID、sudo 配置、Cron、环境变量、内核漏洞）、Windows 提权（服务与令牌、注册表、UAC、命名管道）、内核漏洞与服务配置错误提权（含常见提权漏洞速查）以及凭证窃取与利用（LSASS、SAM、DPAPI、浏览器、密钥文件）的中文方法论、枚举清单与工具用法，含 5 份中文原文 references。
---

# 权限提升（Privilege Escalation）

> 上游来源：<https://github.com/Hi-FullHouse/CyberSecurity-Skills> → `04-权限提升-PrivilegeEscalation`
> 本技能包由上游 5 个 Markdown 文件转存，正文是导航与一句话要点，**中文原文完整保留在 `references/`**。

## 使用方式

1. 拿到低权限 Shell 后的**第一件事是信息收集与枚举**，再按平台（Linux / Windows）挑路线。
2. 提权成果要落「服务器主机权限」档位得分（普通权限与管理员/root 是不同档位，同一系统只按最高权限计一次）。
3. 提权成功后立刻做两件事：**该提权的容器/主机再枚举一次关键信息**，并**把凭证交给横向移动角色**。

## 知识清单（逐文件要点）

### 1. Linux 提权（Linux Privilege Escalation）
- **一句话要点**：用内核漏洞、配置错误、SUID/SGID 与特权滥用，**把普通用户变成 root**。
- **覆盖**：信息收集与枚举（用户/组、内核与发行版、SUID/SGID 文件、可写文件与服务、Cron、环境变量、PATH 劫持、NFS、Docker 组、capabilities）、常见提权手法、权限提升检查清单、自动化枚举工具（linpeas 一类）与手工验证路径。
- **原文**：`references/Linux-LinuxPrivEsc.md`

### 2. Windows 提权（Windows Privilege Escalation）
- **一句话要点**：用内核漏洞、服务漏洞、令牌窃取与注册表配置错误，**从普通用户升到 SYSTEM/管理员**。
- **覆盖**：信息收集与枚举（系统补丁、服务与权限、注册表可写项、计划任务、AlwaysInstallElevated、未加引号服务路径、域信息）、令牌窃取与模拟、UAC 绕过、命名管道与服务滥用、权限提升检查清单与工具链。
- **原文**：`references/Windows-WindowsPrivEsc.md`

### 3. 内核漏洞与服务配置错误提权（Kernel & Service Misconfiguration）
- **一句话要点**：**内核漏洞 + 服务配置错误**是最高性价比的提权杠杆，命中即可直接落地 SYSTEM/root。
- **覆盖**：Linux 内核漏洞提权（版本指纹、公开 EXP 匹配与编译）、服务与 sudo 配置错误、Windows 内核与服务提权、常见提权漏洞速查表、EXP 落地与稳定性注意事项。
- **原文**：`references/KernelServicePrivEsc.md`

### 4. 凭证窃取与利用（Credential Theft）
- **一句话要点**：窃取系统里存的密码、哈希与令牌，**既用于提权也用于横向移动与持久化**。
- **覆盖**：Windows 凭证窃取（LSASS 内存、SAM/SECURITY 注册表、DPAPI、计划任务与 IIS 配置、凭据管理器、浏览器保存口令）、Linux 凭证位置（shadow、历史命令、配置文件、密钥文件、SSH known_hosts 与私钥）、常用凭证收集位置清单、mimikatz/其他工具用法。
- **原文**：`references/CredentialTheft.md`

### 5. 分类导读（README）
- **一句话要点**：上游该分类的官方目录说明（阶段目标：从低权限提升至管理员/root）。
- **原文**：`references/README.md`

## 提权作业纪律

- **枚举优先于尝试**：先把枚举结果落库（系统版本、补丁号、可写服务、SUID/GID 清单），再挑 EXP；盲目跑 EXP 容易挂服务、暴露行踪。
- **凭证要登记**：拿到的密码/哈希/密钥写进凭据库（含明文 secret_value 与 privilege 级别），供后续横向复用。
- **同一系统只计最高权限**：先记普通档再提到管理员档时，用高档 `points` 再记一条，系统会自动顶掉旧档。
- **失败要留痕**：提权失败的原因（补丁已打、缺编译环境、服务不可写）写进资产测试记录的 `test` 字段，避免后来者重复踩坑。
