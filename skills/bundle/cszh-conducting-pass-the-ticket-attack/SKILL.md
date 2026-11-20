---
name: cszh-conducting-pass-the-ticket-attack
description: 票据传递（Pass-the-Ticket，PtT）是一种横向移动技术，使用窃取的 Kerberos 票据（TGT 或 TGS）在不知道用户密码的情况下向服务进行认证。通过从已控制的主机内存中提取 Kerberos 票据，攻击者可以将这些票据注入自己的会话以模拟票据所有者。
---

> 来源：killvxk/cybersecurity-skills-zh 上游技能 `conducting-pass-the-ticket-attack`，正文为中文原文照录（仅剥离上游 frontmatter）。
> 定位：执行票据传递攻击。
> 用法：按正文的「工作流程 / 命令清单 / 输出格式」执行；本技能在 dsh 中的名字是 cszh-conducting-pass-the-ticket-attack。

# 执行票据传递攻击

## 概述

票据传递（PtT）是一种横向移动技术，使用窃取的 Kerberos 票据（TGT 或 TGS）在不知道用户密码的情况下向服务进行认证。通过从已控制主机的内存（LSASS）中提取 Kerberos 票据，攻击者可以将这些票据注入自己的会话，以模拟票据所有者身份并以该用户身份访问资源。

## MITRE ATT&CK 映射

- **T1550.003** - 使用替代认证材料：票据传递
- **T1003.001** - 操作系统凭据转储：LSASS 内存
- **T1558** - 窃取或伪造 Kerberos 票据
- **T1021.002** - 远程服务：SMB/Windows 管理共享

## 实施步骤

### 阶段一：票据提取
1. 获取目标工作站的本地管理员访问权限
2. 使用 Mimikatz 或 Rubeus 从 LSASS 内存中转储 Kerberos 票据
3. 以 .kirbi 格式（Mimikatz）或 base64（Rubeus）导出票据
4. 识别高价值票据（域管理员 TGT、关键系统的服务票据）

### 阶段二：票据注入
1. 清除攻击者会话中的现有 Kerberos 票据
2. 将窃取的票据导入/注入当前会话
3. 验证票据已加载且有效
4. 使用注入的票据访问目标资源

### 阶段三：横向移动
1. 使用窃取的票据身份访问远程系统
2. 以被模拟用户的身份执行操作
3. 从被访问系统收集额外凭据
4. 记录成功横向移动的证据

## 工具与资源

| 工具 | 用途 | 命令 |
|------|---------|---------|
| Mimikatz | 票据导出/导入 | sekurlsa::tickets /export, kerberos::ptt |
| Rubeus | 票据转储和注入 | dump, ptt, tgtdeleg |
| Impacket ticketConverter | 格式转换 | ticketConverter.py ticket.kirbi ticket.ccache |
| Impacket psexec/smbexec | 使用票据远程执行 | KRB5CCNAME=ticket.ccache psexec.py |

## 检测指标

- 来自异常客户端地址的事件 ID 4768
- 来自意外主机的事件 ID 4769 服务票据请求
- 从与 TGT 签发时不同的 IP 使用 TGT
- 同一票据在不同工作站上的多次认证

## 验证标准

- [ ] 已从被控主机提取 Kerberos 票据
- [ ] 票据已注入攻击者会话
- [ ] 使用窃取的票据已演示横向移动
- [ ] 已捕获证据用于报告
