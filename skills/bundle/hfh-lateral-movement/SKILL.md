---
name: hfh-lateral-movement
description: 网络安全知识库「横向移动」分类技能包，源自 Hi-FullHouse/CyberSecurity-Skills 上游 06-横向移动-LateralMovement。覆盖以已控机器为跳板横向扩展（Pass-the-Hash、票据传递、域内移动、技术对比）、Windows 远程执行（PsExec/WMI/WinRM/SCM/计划任务，含隐蔽性对比）以及内网代理与隧道（SSH 隧道、端口转发、代理链、穿透网络隔离，含隧道技术对比）的中文方法论、命令清单与工具选型，含 4 份中文原文 references。
---

# 横向移动（Lateral Movement）

> 上游来源：<https://github.com/Hi-FullHouse/CyberSecurity-Skills> → `06-横向移动-LateralMovement`
> 本技能包由上游 4 个 Markdown 文件转存，正文是导航与一句话要点，**中文原文完整保留在 `references/`**。

## 使用方式

1. **先有隧道，再做横向**：没有稳定的代理/隧道，内网只能看到一台跳板。
2. 顺序：`内网代理与隧道`（打通可达性）→ `横向移动`（选认证路径）→ `PsExec/WMI`（选执行方式）。
3. 每拿下一台主机就要落库：访问会话（`redteam_access_add`）、凭据（如有）、攻击链步骤（含实际命令与回显）。

## 知识清单（逐文件要点）

### 1. 横向移动（Lateral Movement 总览）
- **一句话要点**：从一台已控主机移动到另一台，**逐步逼近目标系统（如域控）**。
- **覆盖**：Pass-the-Hash（PtH）、票据传递、WinRM 与远程执行、凭据复用与爆破组合、域内信息枚举与路径规划、**横向移动技术对比**（成功率/隐蔽性/所需权限）、常用工具（Impacket 套件等）。
- **原文**：`references/LateralMovement.md`

### 2. PsExec 与 WMI 远程执行（PsExec & WMI）
- **一句话要点**：用 Windows **内置管理机制**在远程主机执行命令，是最直接的横向执行方式。
- **覆盖**：PsExec 基础用法与替代实现（Impacket psexec/smbexec 一类）、WMI 远程调用（wmic/win32_process）、SCM 服务创建、计划任务与 WinRM、命令回显与文件投递、**横向移动技术隐蔽性对比**（是否落地文件、是否留服务、日志痕迹）、常用工具。
- **原文**：`references/PsExecWMI-PsExecWMI.md`

### 3. 内网代理与隧道（Internal Proxy & Tunnel）
- **一句话要点**：在内网搭代理或隧道**穿透网络隔离**，让攻击机访问原本到不了的内网资源。
- **覆盖**：SSH 隧道（本地/远程/动态转发）、端口转发与流量中转、HTTP/SOCKS 代理（WebShell 通道型工具如 suo5/Neo-ReGeorg）、frp/chisel 一类反向隧道、多级代理链与内网可达性探测、**隧道技术对比**（出网要求、稳定性、隐蔽性）、常用工具。
- **原文**：`references/InternalProxyTunnel.md`

### 4. 分类导读（README）
- **一句话要点**：上游该分类的官方目录说明（阶段目标：以内网已控机器为跳板扩大控制范围）。
- **原文**：`references/README.md`

## 横向移动纪律

- **隧道必须说明目标侧那一端**：经 WebShell/HTTP（target-http）、目标反弹到我的 VPS（target-outbound）、或经目标已控进程转发（target-agent）；**只在自建服务器上开的代理不算突破**。
- **凭据优先于爆破**：能复用已拿到的哈希/票据就先复用，爆破是最后手段（噪声大、易锁账号）。
- **横向成果要落访问会话**：记录 host / method / privilege / session_ref，报告里才能证明「这台是怎么进去的」。
- **内网扫描交给专用工具与角色**：内网铺面用 gogo/fscan 一类引擎走隧道扫，不要拿外网手法一台台 nmap。
- **每发现一个新网段就再跑一轮**，直到没有新网段、没有新存活为止。
