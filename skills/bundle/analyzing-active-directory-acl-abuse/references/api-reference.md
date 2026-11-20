# Active Directory ACL 滥用 API 参考

## ldap3 Python 连接

```python
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE

server = Server("192.168.1.10", get_info=ALL, use_ssl=False)
conn = Connection(server, user="DOMAIN\\user", password="pass",
                  authentication=NTLM, auto_bind=True)

# 使用 nTSecurityDescriptor 进行搜索
conn.search(
    "DC=corp,DC=example,DC=com",
    "(objectClass=group)",
    search_scope=SUBTREE,
    attributes=["distinguishedName", "sAMAccountName",
                "objectClass", "nTSecurityDescriptor"],
)
```

## SDDL ACE 格式

```
ACE 字符串: (ace_type;ace_flags;rights;object_guid;inherit_guid;trustee_sid)
示例:       (A;;GA;;;S-1-5-21-xxx-512)
```

| 组件 | 说明 |
|-----------|-------------|
| `A` | 访问允许 |
| `D` | 访问拒绝 |
| `OA` | 对象访问允许 |
| `GA` | Generic All（完全控制） |
| `GW` | Generic Write（通用写入） |
| `WD` | Write DACL（写入 DACL） |
| `WO` | Write Owner（写入所有者） |

## 危险权限位掩码

| 权限 | 十六进制掩码 | 风险 |
|-----------|----------|------|
| GenericAll | `0x10000000` | 对对象的完全控制 |
| GenericWrite | `0x40000000` | 修改所有可写属性 |
| WriteDACL | `0x00040000` | 修改对象权限 |
| WriteOwner | `0x00080000` | 获取对象所有权 |
| WriteProperty | `0x00000020` | 写入特定属性 |
| ExtendedRight | `0x00000100` | 扩展权限（密码重置等） |
| Self | `0x00000008` | 自身成员关系修改 |
| Delete | `0x00010000` | 删除对象 |

## BloodHound ACL 路径 Cypher 查询

```cypher
-- 查找对 Domain Admins 具有 GenericAll 权限的所有用户
MATCH p=(n:User)-[r:GenericAll]->(g:Group {name:"DOMAIN ADMINS@CORP.COM"})
RETURN p

-- 从非管理员到高价值目标查找 WriteDACL 路径
MATCH (n:User {admincount:false})
MATCH p=allShortestPaths((n)-[r:WriteDacl|WriteOwner|GenericAll*1..]->(m:Group))
WHERE m.highvalue = true
RETURN p

-- 查找计算机上用于 RBCD 攻击的 GenericWrite
MATCH p=(n:User)-[r:GenericWrite]->(c:Computer)
WHERE NOT n.admincount
RETURN n.name, c.name

-- 枚举主体的所有出站 ACL 边
MATCH p=(n {name:"HELPDESK@CORP.COM"})-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(m)
RETURN type(r), m.name, labels(m)

-- 查找到 Domain Admin 的最短 ACL 滥用路径
MATCH (n:User {name:"JSMITH@CORP.COM"})
MATCH (da:Group {name:"DOMAIN ADMINS@CORP.COM"})
MATCH p=shortestPath((n)-[r:MemberOf|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns|ForceChangePassword*1..]->(da))
RETURN p
```

## PowerView ACL 枚举命令

```powershell
# 获取 Domain Admins 组的 ACL
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs

# 查找非管理员用户的高危 ACE
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner"
}

# 获取特定 OU 的 ACL
Get-DomainObjectAcl -SearchBase "OU=Servers,DC=corp,DC=com" -ResolveGUIDs
```
