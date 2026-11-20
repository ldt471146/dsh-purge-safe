---
name: cszh-extracting-credentials-from-memory-dump
description: 使用 Volatility 和 Mimikatz 从内存转储中提取缓存的凭据、密码哈希、Kerberos 票据和身份验证令牌，用于取证调查。
---

> 本技能源自中文网络安全技能库 killvxk/cybersecurity-skills-zh（上游目录 extracting-credentials-from-memory-dump），正文按中文原文照录。

**这个技能干什么**：使用 Volatility 和 Mimikatz 从内存转储中提取缓存的凭据、密码哈希、Kerberos 票据和身份验证令牌，用于取证调查。

**什么时候用**：需要按上游中文方法论执行「extracting-credentials-from-memory-dump」对应任务时加载本技能。

**关键工具**：见正文各章节列出的命令与工具清单。

# 从内存转储中提取凭据

## 适用场景
- 在事件响应中确定攻击者可以访问哪些凭据时
- 评估违规后凭据泄露的范围时
- 识别需要立即重置密码的账户时
- 调查横向移动及哈希传递（Pass-the-Hash）/票据传递（Pass-the-Ticket）攻击时
- 从进程内存中恢复加密密钥或身份验证令牌时

## 前置条件
- raw、ELF 或崩溃转储格式的内存转储文件
- 带有 Windows 符号表的 Volatility 3
- Mimikatz（用于对提取的 LSASS 转储进行离线分析）
- pypykatz（Mimikatz 的 Python 实现，用于基于 Linux 的分析）
- 了解 Windows 身份验证（NTLM、Kerberos、DPAPI）
- 凭据提取的适当法律授权

## 工作流程

### 步骤 1：准备工具并验证内存转储

```bash
# 安装分析工具
pip install volatility3 pypykatz

# 验证内存转储完整性
sha256sum /cases/case-2024-001/memory/memory.raw

# 识别操作系统版本
vol -f /cases/case-2024-001/memory/memory.raw windows.info

# 验证 LSASS 进程是否存在于内存中
vol -f /cases/case-2024-001/memory/memory.raw windows.pslist | grep -i lsass

# 输出示例：
# PID    PPID   ImageFileName   Offset(V)        Threads  Handles  SessionId
# 684    564    lsass.exe       0xffffe00123456   35       1234     0
```

### 步骤 2：使用 Volatility 提取凭据哈希

```bash
# 从内存转储 SAM 数据库哈希
vol -f /cases/case-2024-001/memory/memory.raw windows.hashdump \
   | tee /cases/case-2024-001/analysis/hashdump.txt

# 提取 LSA 机密
vol -f /cases/case-2024-001/memory/memory.raw windows.lsadump \
   | tee /cases/case-2024-001/analysis/lsadump.txt

# 提取已缓存的域凭据
vol -f /cases/case-2024-001/memory/memory.raw windows.cachedump \
   | tee /cases/case-2024-001/analysis/cachedump.txt
```

### 步骤 3：转储 LSASS 进程内存进行详细分析

```bash
# 转储 LSASS 进程内存（PID 来自步骤 1）
vol -f /cases/case-2024-001/memory/memory.raw windows.memmap --pid 684 --dump \
   -o /cases/case-2024-001/analysis/lsass_dump/

# 重命名转储文件供 pypykatz/mimikatz 使用
mv /cases/case-2024-001/analysis/lsass_dump/pid.684.dmp \
   /cases/case-2024-001/analysis/lsass.dmp
```

### 步骤 4：使用 pypykatz 提取凭据

```bash
# 对完整内存转储运行 pypykatz
pypykatz lsa minidump /cases/case-2024-001/analysis/lsass.dmp \
   > /cases/case-2024-001/analysis/pypykatz_results.txt 2>&1

# 解析 pypykatz 输出进行结构化分析
python3 << 'PYEOF'
import json, subprocess

result = subprocess.run(
    ['pypykatz', 'lsa', 'minidump', '/cases/case-2024-001/analysis/lsass.dmp', '-j'],
    capture_output=True, text=True
)

if result.stdout:
    data = json.loads(result.stdout)
    print("=== 提取的凭据 ===\n")
    for session_key, session in data.get('logon_sessions', {}).items():
        username = session.get('username', 'Unknown')
        domain = session.get('domainname', '')
        if username and username != '(null)':
            print(f"会话：{domain}\\{username}")
            print(f"  SID：{session.get('sid', '')}")
            for cred in session.get('msv_creds', []):
                if cred.get('NThash'):
                    print(f"  NTLM 哈希：{cred['NThash']}")
            for cred in session.get('wdigest_creds', []):
                if cred.get('password'):
                    print(f"  WDigest 明文密码：{cred['password']}")
PYEOF
```

### 步骤 5：提取 Kerberos 票据和令牌

```bash
# 在内存中搜索身份验证令牌和 API 密钥
vol -f /cases/case-2024-001/memory/memory.raw windows.strings --pid 684 | \
   grep -iE '(bearer |authorization:|api[_-]key|token=|password=|secret=)' \
   > /cases/case-2024-001/analysis/auth_strings.txt

# 在内存中搜索云凭据
vol -f /cases/case-2024-001/memory/memory.raw windows.strings | \
   grep -iE '(AKIA[A-Z0-9]{16}|aws_secret_access_key)' \
   > /cases/case-2024-001/analysis/aws_credentials.txt
```

## 关键概念

| 概念 | 描述 |
|------|------|
| LSASS（本地安全认证子系统服务） | 管理身份验证并在内存中存储凭据的 Windows 进程 |
| NTLM 哈希 | 用于身份验证的用户密码 NT LAN Manager 哈希 |
| Kerberos TGT | 允许请求服务票据的票据授予票据 |
| WDigest | 在内存中以明文存储密码的遗留身份验证协议（Win8.1 之前） |
| DPAPI | 使用从用户凭据派生的主密钥的数据保护 API |
| DCC2（域缓存凭据） | 用于离线登录的已缓存域密码哈希 |
| LSA 机密 | 由 LSA 存储的加密服务账户密码和其他机密 |
| 哈希传递 | 使用提取的 NTLM 哈希而无需知道明文密码的攻击技术 |

## 工具与系统

| 工具 | 用途 |
|------|------|
| Volatility 3 | 带有 hashdump、lsadump、cachedump 插件的内存取证框架 |
| pypykatz | 用于跨平台 LSASS 分析的 Mimikatz Python 实现 |
| Mimikatz | Windows 凭据提取工具（用于对转储进行离线分析） |
| secretsdump.py | 从 SAM/SYSTEM/SECURITY 提取机密的 Impacket 工具 |
| hashcat | 恢复的 NTLM 和 DCC2 哈希密码破解工具 |
| Impacket | 用于 Windows 网络协议和凭据的 Python 工具包 |

## 常见场景

**场景 1：违规后凭据评估**
从 LSASS 内存中提取所有已缓存的凭据以确定哪些账户已暴露，根据权限级别优先重置密码，检查黄金票据材料（krbtgt 哈希），评估云凭据是否可被访问。

**场景 2：横向移动调查**
提取 NTLM 哈希和 Kerberos 票据以了解攻击者如何在系统间移动，识别哈希传递/票据传递制品，将提取的凭据与事件日志中的网络登录事件相关联。

**场景 3：勒索软件操作者凭据窃取**
分析加密前的内存转储以获取 Mimikatz 执行证据，提取所有可用的凭据类型，确定是否获取了域管理员凭据，评估 krbtgt 是否已泄露（黄金票据），制定凭据轮换策略。

**场景 4：端点云凭据窃取**
在端点内存中搜索 AWS 访问密钥、Azure 令牌和 CLI 工具及浏览器存储的 GCP 服务账户密钥，识别暴露的云权限，立即轮换发现的凭据，审计云审计日志中的未授权访问。
