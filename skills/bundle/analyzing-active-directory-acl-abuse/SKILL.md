---
name: analyzing-active-directory-acl-abuse
description: 使用 ldap3 检测 Active Directory 中危险的 ACL 配置错误，识别 GenericAll、WriteDACL 和 WriteOwner 等滥用路径
domain: cybersecurity
subdomain: identity-security
tags: [active-directory, acl-abuse, ldap, privilege-escalation]
version: "1.0"
author: mahipal
license: Apache-2.0
---

## 概述

活动目录（Active Directory）访问控制列表（ACL）通过包含访问控制条目（ACE）的自主访问控制列表（DACL）来定义 AD 对象的权限。配置错误的 ACE 可能赋予非特权用户对敏感对象（如 Domain Admins 组、域控制器或 GPO）的危险权限，包括 GenericAll（完全控制）、WriteDACL（修改权限）、WriteOwner（获取所有权）和 GenericWrite（修改属性）。

本技能使用 ldap3 Python 库连接到域控制器，查询包含 nTSecurityDescriptor 属性的对象，将二进制安全描述符解析为 SDDL（安全描述符定义语言）格式，并识别向非管理员主体授予危险权限的 ACE。这些配置错误正是 BloodHound 等工具发现的基于 ACL 的攻击路径的基础。

## 前置条件

- Python 3.9 或更高版本，并安装 ldap3 库（`pip install ldap3`）
- 具有 AD 对象读取权限的域用户凭据
- 域控制器端口 389（LDAP）或 636（LDAPS）的网络连接
- 了解 Active Directory 安全模型和 SDDL 格式

## 步骤

1. **连接域控制器**：使用 ldap3 通过 NTLM 或简单身份验证建立 LDAP 连接。在生产环境中使用 LDAPS（端口 636）进行加密连接。

2. **查询目标对象**：搜索目标 OU 或整个域，获取包括用户、组、计算机和 OU 在内的对象。请求 `nTSecurityDescriptor`、`distinguishedName`、`objectClass` 和 `sAMAccountName` 属性。

3. **解析安全描述符**：将二进制 nTSecurityDescriptor 转换为 SDDL 字符串表示。解析 DACL 中的每个 ACE，提取受托人 SID、访问掩码和 ACE 类型（允许/拒绝）。

4. **将 SID 解析为主体**：通过对域的 LDAP 查询，将安全标识符（SID）映射为可读的账户名。识别内置组的已知 SID。

5. **检查危险权限**：将每个 ACE 的访问掩码与危险权限位掩码进行比较：GenericAll（0x10000000）、WriteDACL（0x00040000）、WriteOwner（0x00080000）、GenericWrite（0x40000000），以及针对特定扩展权限的 WriteProperty。

6. **过滤非管理员受托人**：排除预期的管理员受托人（Domain Admins、Enterprise Admins、SYSTEM、Administrators），并标记非特权用户或组持有危险权限的 ACE。

7. **映射攻击路径**：对于每个发现，记录潜在的攻击链（例如，对用户的 GenericAll 允许重置密码，对组的 WriteDACL 允许将自身添加到组中）。

8. **生成修复报告**：输出包含所有危险 ACE、受影响对象、非管理员受托人及建议修复步骤的 JSON 报告。

## 预期输出

```json
{
  "domain": "corp.example.com",
  "objects_scanned": 1247,
  "dangerous_aces_found": 8,
  "findings": [
    {
      "severity": "critical",
      "target_object": "CN=Domain Admins,CN=Users,DC=corp,DC=example,DC=com",
      "target_type": "group",
      "trustee": "CORP\\helpdesk-team",
      "permission": "GenericAll",
      "access_mask": "0x10000000",
      "ace_type": "ACCESS_ALLOWED",
      "attack_path": "GenericAll on Domain Admins group allows adding arbitrary members",
      "remediation": "Remove GenericAll ACE for helpdesk-team on Domain Admins"
    }
  ]
}
```
