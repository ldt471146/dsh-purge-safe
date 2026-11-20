---
name: hfh-persistence
description: 网络安全知识库「持久化」分类技能包，源自 Hi-FullHouse/CyberSecurity-Skills 上游 07-持久化-Persistence。覆盖 Windows 与跨平台持久化总览（注册表与服务、计划任务、WMI 事件订阅，含持久化技术对比）、启动项与登录自动执行（Run 键、启动文件夹、服务、计划任务、跨平台启动脚本）、账户与凭证持久化（本地/域账户、SSH 密钥、云访问密钥）、Office 应用持久化（COM 加载项、VBA、Outlook 规则与表单）以及 Bootkit 与固件级持久化（MBR/VBR、UEFI）的中文方法论与命令清单，含 6 份中文原文 references。
---

# 持久化（Persistence）

> 上游来源：<https://github.com/Hi-FullHouse/CyberSecurity-Skills> → `07-持久化-Persistence`
> 本技能包由上游 6 个 Markdown 文件转存，正文是导航与一句话要点，**中文原文完整保留在 `references/`**。

## 使用方式

1. 目标：**系统重启、口令变更后仍能访问**——即把「一次拿下的会话」变成「稳定的控制权」。
2. 保守优先：先用**合法机制**（服务、计划任务、账户、SSH 密钥），再考虑高侵入手段（驱动/Bootkit）。
3. 每条持久化机制都要**记攻击链步骤**（怎么建的、命令是什么、怎么验证生效），并在复盘时说明**怎么检测**。

## 知识清单（逐文件要点）

### 1. 持久化总览（Persistence）
- **一句话要点**：在目标系统建立后门，**确保重启与凭证变更后仍保持访问**；含技术对比表。
- **覆盖**：Windows 启动项持久化、注册表与服务持久化、计划任务、WMI 事件订阅、Linux 侧对应机制、**持久化技术对比**（权限要求、隐蔽性、稳定性）、常用工具。
- **原文**：`references/Persistence.md`

### 2. 启动项与登录自动执行（Boot / Logon Autostart）
- **一句话要点**：利用操作系统**自带的自动执行机制**（合法功能）实现开机或登录即执行。
- **覆盖**：Windows 注册表 Run 键（HKCU/HKLM 多位置）、启动文件夹、系统服务、计划任务、Winlogon Shell/Userinit；Linux 侧 systemd、rc.local、crontab、shell profile；跨平台启动脚本与验证方法。
- **原文**：`references/BootLogonAutostart.md`

### 3. 账户持久化（Account Persistence）
- **一句话要点**：**建账户、改权限、埋凭证**，在网络里留一个稳定入口（域环境/Linux/云都适用）。
- **覆盖**：Windows 本地账户创建与提权、域账户与 ACL 后门、Linux 用户与 sudoers、SSH 公钥植入（authorized_keys）、Web 应用账户后门、云平台访问密钥（AK/SK）与 IAM 后门、检测与清理要点。
- **原文**：`references/AccountPersistence.md`

### 4. Office 应用程序持久化（Office Persistence）
- **一句话要点**：借 Office 的扩展机制（加载项/宏/规则）**随办公软件启动而执行**，在企业环境极隐蔽。
- **覆盖**：Office COM/VSTO 加载项、Excel/Word 模板与启动目录（STARTUP 路径）、VBA 宏与宏存储位置、Outlook VBA 与规则/表单、注册表加载项键值。
- **原文**：`references/Office-OfficePersistence.md`

### 5. Bootkit 与固件持久化（Bootkit & Firmware Persistence）
- **一句话要点**：把代码埋进**引导过程（MBR/VBR）、UEFI 固件或设备固件**，在操作系统加载前或独立于操作系统执行——最高级也最高风险。
- **覆盖**：MBR/VBR Bootkit、UEFI 固件与 SPI Flash 写入、Bootkit 技术对比（存活层级、检测难度、持久性）、适用与限制条件、常用工具。
- **原文**：`references/Bootkit-BootkitFirmwarePersistence.md`

### 6. 分类导读（README）
- **一句话要点**：上游该分类的官方目录说明（阶段目标：建立重启与改密后仍可用的后门）。
- **原文**：`references/README.md`

## 持久化纪律

- **权限要求先确认**：写系统目录、装服务、改 MBR 都需要管理员/root；没到该权限就先提权。
- **隐蔽性与可恢复性权衡**：高侵入（Bootkit、驱动）难以清除，演练环境里慎用；优先可回滚的机制。
- **每个后门都要能被检出**：记录落地路径、注册表键、服务名与账号名，便于防守方复盘与本方清理。
- **凭证类后门进凭据库**：SSH 私钥、云 AK/SK、账户口令都要登记（含明文 secret_value），以便复用与回收。
