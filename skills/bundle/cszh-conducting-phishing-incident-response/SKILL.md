---
name: cszh-conducting-phishing-incident-response
description: 通过分析举报的邮件、提取指标、评估凭据受攻陷情况、在全组织范围隔离恶意邮件并修复受影响账号来响应网络钓鱼事件。涵盖邮件头分析、URL/附件沙箱检测和邮箱范围清除操作。适用于网络钓鱼响应、邮件事件、凭据钓鱼、鱼叉式网络钓鱼调查或钓鱼修复相关请求。
---

> 来源：killvxk/cybersecurity-skills-zh 上游技能 `conducting-phishing-incident-response`，正文为中文原文照录（仅剥离上游 frontmatter）。
> 定位：网络钓鱼事件响应（Phishing Incident Response）。
> 用法：按正文的「工作流程 / 命令清单 / 输出格式」执行；本技能在 dsh 中的名字是 cszh-conducting-phishing-incident-response。

# 网络钓鱼事件响应（Phishing Incident Response）

## 适用场景

- 用户通过钓鱼举报按钮或滥用邮箱举报收到可疑邮件
- 邮件网关检测到绕过初始过滤的恶意邮件
- 威胁情报显示针对该组织的活跃钓鱼活动
- 用户确认点击了可疑邮件中的链接或打开了附件
- 凭据已在疑似钓鱼页面上输入

**不适用于**涉及内部账号受攻陷的商业邮件欺诈（BEC）；此类情况请使用专注于账号接管调查的 BEC 响应流程。

## 前置条件

- 具有邮件追踪和隔离能力的邮件安全网关（Microsoft Defender for Office 365、Proofpoint、Mimecast）
- Microsoft 365 管理员访问权限或 Google Workspace 管理员权限（用于邮箱搜索和清除）
- 用于附件和 URL 分析的恶意软件沙箱（ANY.RUN、Joe Sandbox、Hybrid Analysis）
- 邮件头分析工具（MXToolbox Header Analyzer、Google Admin Toolbox）
- 用于账号修复的身份提供商访问权限（Azure AD、Okta、Duo）
- 钓鱼举报接收流程（专用邮箱或集成举报按钮）

## 工作流程

### 步骤 1：接收并分类钓鱼举报

评估举报的邮件以确定其是否为恶意邮件：

- 将邮件提取为 .EML 或 .MSG 文件（保留邮件头）
- 分析邮件头以确定真实发件人、中继路径和认证结果

```
邮件头分析清单：
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Return-Path:     billing@spoofed-domain[.]com
From:            "IT Support" <support@corp-lookalike[.]com>
Reply-To:        attacker@gmail[.]com（与 From 不同）
SPF:             FAIL（发件人 IP 未被授权用于该域名）
DKIM:            FAIL（签名无效）
DMARC:           FAIL（策略：none - 无执行）
Received:        from mail.attacker-infra[.]net [45.33.x.x]
X-Originating-IP: 45.33.x.x
Message-ID:      <random@attacker-infra.net>
```

分类标准：
- **确认为钓鱼**：恶意 URL/附件、伪造发件人、凭据收割页面
- **可疑**：异常邮件头但无确认的恶意内容
- **垃圾邮件/营销邮件**：不受欢迎但非恶意
- **合法邮件**：非钓鱼邮件（误报）

### 步骤 2：分析恶意内容

在安全环境中检查 URL 和附件：

**URL 分析：**
- 通过 VirusTotal、URLscan.io 和 Google Safe Browsing 检查 URL
- 在沙箱浏览器中打开 URL 以捕获着陆页
- 检查 URL 是否重定向到凭据收割页面
- 识别钓鱼套件类型（Microsoft 365 登录克隆、Okta 克隆、通用类型）
- 确定钓鱼页面是否仍处于活跃状态

**附件分析：**
- 计算文件哈希（SHA-256）并在 VirusTotal 中查询
- 在沙箱中引爆（ANY.RUN、Joe Sandbox）
- 分析文档中的宏（Office 文件使用 olevba）
- 检查嵌入的漏洞利用（文档解析器中的 CVE 利用）

### 步骤 3：确定影响范围

识别所有收件人并评估谁与钓鱼邮件发生了交互：

```
范围评估：
━━━━━━━━━━
总收件人：        47 名用户
投递到收件箱：    38 名用户（9 名被邮件网关拦截）
已打开邮件：      24 名用户（邮件追踪像素数据）
已点击链接：      8 名用户（代理/防火墙日志）
已输入凭据：      3 名用户（钓鱼页面已提交表单数据）
已打开附件：      2 名用户（EDR 进程执行遥测）
```

搜索方法：
- Microsoft 365：使用威胁资源管理器或内容搜索查找邮件的所有实例
- Google Workspace：使用管理控制台 > 调查工具进行邮件搜索
- 代理日志：搜索来自内部 IP 对钓鱼 URL 的连接
- EDR：在所有端点中搜索附件文件哈希的执行

### 步骤 4：遏制威胁

根据影响评估执行遏制措施：

**邮件遏制：**
- 使用 Microsoft 365 内容搜索和清除或 Google Workspace 管理员删除，从所有邮箱清除钓鱼邮件
- 在邮件网关阻断发件人域名
- 将钓鱼 URL 添加到 Web 代理阻断列表
- 将附件哈希添加到邮件网关和 EDR 阻断列表

**账号遏制（针对输入过凭据的用户）：**
- 立即强制重置密码
- 撤销所有活跃会话和 OAuth 令牌
- 启用或重新验证 MFA 注册
- 检查邮箱规则是否存在攻击者创建的转发规则
- 检查未授权的 OAuth 应用程序授权
- 检查近期登录活动是否存在可疑位置

```powershell
# Microsoft 365：撤销会话并重置密码
Connect-AzureAD
Revoke-AzureADUserAllRefreshToken -ObjectId "user@corp.com"
Set-AzureADUserPassword -ObjectId "user@corp.com" -ForceChangePasswordNextLogin $true

# 检查邮箱转发规则
Get-InboxRule -Mailbox "user@corp.com" | Where-Object {$_.ForwardTo -or $_.RedirectTo}

# 移除可疑转发规则
Remove-InboxRule -Mailbox "user@corp.com" -Identity "Rule Name"
```

### 步骤 5：根除并恢复

清除钓鱼攻击的所有痕迹：

- 确认邮件清除已成功完成（所有邮箱）
- 验证受攻陷账号已得到保护（密码已更改、会话已撤销、MFA 已验证）
- 从受影响端点清除通过钓鱼附件安装的任何恶意软件
- 监控受攻陷账号 72 小时以观察是否有持续未授权访问的迹象
- 在暴露窗口期内检查受攻陷账号的数据外泄情况

### 步骤 6：事件后行动

加强针对类似钓鱼攻击的防御：

- 向 Google Safe Browsing 和 Microsoft SmartScreen 举报钓鱼 URL
- 通过域名注册商滥用联系方式提交钓鱼域名下线申请
- 根据观察到的规避技术更新邮件网关过滤规则
- 向受影响用户发送有针对性的安全意识通知
- 更新钓鱼模拟程序以涵盖观察到的攻击技术

## 核心概念

| 术语 | 定义 |
|------|------|
| **鱼叉式网络钓鱼（Spear Phishing）** | 使用个性化内容针对特定个人或组织精心制作的定向钓鱼攻击 |
| **凭据收割（Credential Harvesting）** | 通过模仿合法登录页面捕获用户名和密码的钓鱼技术 |
| **SPF（Sender Policy Framework，发件人策略框架）** | 指定哪些邮件服务器被授权为某域名发送邮件的电子邮件认证协议 |
| **DKIM（DomainKeys Identified Mail，域名密钥识别邮件）** | 使用加密签名验证邮件在传输过程中未被篡改的电子邮件认证方法 |
| **DMARC** | 使用 SPF 和 DKIM 确定邮件真实性并指示接收方如何处理失败情况的策略框架 |
| **OAuth 同意钓鱼（OAuth Consent Phishing）** | 诱骗用户授予恶意 OAuth 应用程序访问其邮件和数据权限的攻击 |
| **邮件头（Email Header）** | 每封邮件中嵌入的元数据，包含用于取证分析的路由、认证和发件人信息 |

## 工具与系统

- **Microsoft Defender for Office 365**：具有威胁资源管理器的邮件威胁防护平台，支持调查和自动清除
- **Proofpoint TAP（Targeted Attack Protection）**：具有 URL 重写和附件沙箱的邮件安全平台
- **URLscan.io**：扫描 URL 并捕获钓鱼页面截图作为证据的在线服务
- **PhishTool**：自动化邮件头分析、URL 检查和 IOC 提取的钓鱼分析平台
- **GoPhish**：用于安全意识测试的开源钓鱼模拟平台

## 常见场景

### 场景：通过二维码进行 Microsoft 365 凭据钓鱼

**背景**：用户举报一封声称来自 IT 部门的邮件，要求重新注册 MFA。邮件包含一个二维码，链接到托管在受攻陷 WordPress 网站上的逼真 Microsoft 365 登录页面克隆。

**处理方法**：
1. 在沙箱中扫描二维码提取 URL
2. 分析钓鱼页面：可捕获凭据和 MFA 令牌（中间人攻击）
3. 以邮件主题和发件人为搜索条件，在邮件网关中搜索所有收件人
4. 与代理日志交叉引用以识别访问了钓鱼 URL 的用户
5. 对所有访问该 URL 的用户强制重置密码并撤销会话
6. 从所有邮箱清除邮件并阻断发件人域名
7. 向所有 47 名收件人发送包含钓鱼邮件视觉示例的具体通知

**常见陷阱**：
- 未检查可以捕获会话令牌的中间人（AiTM）能力（即使开启 MFA）
- 仅重置密码而不撤销活跃会话（攻击者通过窃取的会话 Cookie 保持访问）
- 未搜索攻击者在攻陷账号后创建的邮箱转发规则
- 遗漏二维码钓鱼（Quishing），因为 URL 扫描工具无法解码二维码图像

## 输出格式

```
网络钓鱼事件响应报告
===================================
事件：           INC-2025-1602
举报日期：       2025-11-16T09:15:00Z
举报人：         jdoe@corp.example.com
分类：           凭据钓鱼（AiTM）

邮件分析
主题：      "需要操作：MFA 重新注册"
发件人：    it-support@corp-security[.]com（伪造）
SPF：       FAIL | DKIM：FAIL | DMARC：FAIL
钓鱼 URL：  hxxps://compromised-site[.]com/ms365/login
钓鱼类型：  Microsoft 365 AiTM 凭据收割器

影响评估
收件人：         47 人
点击链接：       8 人
输入凭据：       3 人（通过代理 POST 数据确认）

遏制措施
[x] 邮件已从全部 47 个邮箱清除
[x] 钓鱼域名已在 Web 代理处阻断
[x] 发件人域名已在邮件网关处阻断
[x] 3 个受攻陷账号：密码已重置，会话已撤销
[x] 邮箱转发规则已检查（已移除 1 条恶意规则）
[x] OAuth 应用程序授权已检查（未发现未授权授权）

提取的 IOC
域名：   corp-security[.]com
URL：    hxxps://compromised-site[.]com/ms365/login
IP：     104.21.x.x（Cloudflare 托管）
发件人： it-support@corp-security[.]com

建议
1. 为企业域名实施 DMARC 执行（p=reject）
2. 在邮件网关部署二维码扫描
3. 向全部 47 名收件人发送有针对性的意识通知
4. 通过注册商滥用联系方式申请域名下线
```
