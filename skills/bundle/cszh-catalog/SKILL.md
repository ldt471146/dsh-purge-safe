---
name: cszh-catalog
description: 中文网络安全技能库索引（734+ 技能），按主题检索并给出上游取用路径；当需要中文视角的渗透/取证/检测/云安全/威胁情报方法论时使用
---

# 中文网络安全技能库索引

来源：https://github.com/killvxk/cybersecurity-skills-zh （上游许可见仓库）
规模：735 个技能，完整清单见 references/all-skills.md

## 怎么用
1. 先在本技能包内检索：`references/all-skills.md`（一次拿到全部 735 个目录名与体量）。
2. 命中后按上游 raw 路径现取正文：
   https://raw.githubusercontent.com/killvxk/cybersecurity-skills-zh/master/skills/<目录名>/SKILL.md
   同目录下可能还有 scripts/ 与 references/，需要时先用 GitHub contents API 列目录再取：
   https://api.github.com/repos/killvxk/cybersecurity-skills-zh/contents/skills/<目录名>
3. 若某个主题已被本机技能覆盖（见下方「本机已收」），优先用本机包，避免重复下载。
4. 取回正文后按上游原文执行；本索引只做路由，不复制上游内容。

## 主题导航（每类给代表条目）

### Web与API安全（27 条）
- implementing-api-abuse-detection-with-rate-limiting
- implementing-api-gateway-security-controls
- implementing-api-key-security-controls
- implementing-api-rate-limiting-and-throttling
- implementing-api-schema-validation-security
- implementing-api-security-posture-management
- implementing-api-security-testing-with-42crunch
- implementing-api-threat-protection-with-apigee
- testing-api-authentication-weaknesses
- testing-api-for-broken-object-level-authorization

### 云与容器K8s（90 条）
- analyzing-azure-activity-logs-for-threats
- analyzing-cloud-storage-access-patterns
- analyzing-docker-container-forensics
- analyzing-kubernetes-audit-logs
- auditing-aws-s3-bucket-permissions
- auditing-azure-active-directory-configuration
- auditing-cloud-with-cis-benchmarks
- auditing-gcp-iam-permissions
- auditing-kubernetes-cluster-rbac
- auditing-kubernetes-rbac-permissions

### 渗透与利用（131 条）
- analyzing-ethereum-smart-contract-vulnerabilities
- analyzing-heap-spray-exploitation
- analyzing-ios-app-security-with-objection
- building-c2-infrastructure-with-sliver-framework
- building-red-team-c2-infrastructure-with-havoc
- bypassing-authentication-with-forced-browsing
- conducting-api-security-testing
- conducting-cloud-infrastructure-penetration-test
- conducting-cloud-penetration-testing
- conducting-external-reconnaissance-with-osint

### 合规治理与供应链（87 条）
- auditing-terraform-infrastructure-for-security
- building-devsecops-pipeline-with-gitlab-ci
- building-patch-tuesday-response-process
- building-phishing-reporting-button-workflow
- building-vulnerability-aging-and-sla-tracking
- building-vulnerability-dashboard-with-defectdojo
- building-vulnerability-exception-tracking-system
- building-vulnerability-scanning-workflow
- hardening-linux-endpoint-with-cis-benchmark
- hardening-windows-endpoint-with-cis-benchmark

### 身份与零信任（60 条）
- building-identity-governance-lifecycle-process
- building-role-mining-for-rbac-optimization
- configuring-active-directory-tiered-model
- configuring-certificate-authority-with-openssl
- configuring-hsm-for-key-storage
- configuring-identity-aware-proxy-with-google-iap
- configuring-ldap-security-hardening
- configuring-microsegmentation-for-zero-trust
- configuring-multi-factor-authentication-with-duo
- configuring-oauth2-authorization-flow

### 检测工程与威胁狩猎（131 条）
- analyzing-api-gateway-access-logs
- analyzing-linux-audit-logs-for-intrusion
- analyzing-network-flow-data-with-netflow
- analyzing-network-packets-with-scapy
- analyzing-network-traffic-for-incidents
- analyzing-network-traffic-with-wireshark
- analyzing-office365-audit-logs-for-compromise
- analyzing-powershell-empire-artifacts
- analyzing-powershell-script-block-logging
- analyzing-security-logs-with-splunk

### 后渗透与内网AD（46 条）
- analyzing-active-directory-acl-abuse
- analyzing-persistence-mechanisms-in-linux
- conducting-domain-persistence-with-dcsync
- conducting-internal-reconnaissance-with-bloodhound-ce
- conducting-pass-the-ticket-attack
- detecting-credential-dumping-techniques
- detecting-credential-dumping-with-edr
- detecting-dcsync-attack-in-active-directory
- detecting-dll-sideloading-attacks
- detecting-golden-ticket-attacks

### 威胁情报与OSINT（60 条）
- analyzing-apt-group-with-mitre-navigator
- analyzing-campaign-attribution-evidence
- analyzing-certificate-transparency-for-phishing
- analyzing-cobalt-strike-beacon-configuration
- analyzing-cobaltstrike-malleable-c2-profiles
- analyzing-cobalt-strike-malleable-profiles
- analyzing-command-and-control-communication
- analyzing-cyber-kill-chain
- analyzing-dns-logs-for-exfiltration
- analyzing-indicators-of-compromise

### 数字取证与应急响应（64 条）
- acquiring-disk-image-with-dd-and-dcfldd
- analyzing-browser-forensics-with-hindsight
- analyzing-disk-image-with-autopsy
- analyzing-email-headers-for-phishing-investigation
- analyzing-linux-kernel-rootkits
- analyzing-linux-system-artifacts
- analyzing-lnk-file-and-jump-list-artifacts
- analyzing-memory-dumps-with-volatility
- analyzing-memory-forensics-with-lime-and-volatility
- analyzing-mft-for-deleted-file-recovery

### 逆向与恶意样本（39 条）
- analyzing-android-malware-with-apktool
- analyzing-bootkit-and-rootkit-samples
- analyzing-golang-malware-with-ghidra
- analyzing-linux-elf-malware
- analyzing-macro-malware-in-office-documents
- analyzing-malicious-pdf-with-peepdf
- analyzing-malware-behavior-with-cuckoo-sandbox
- analyzing-malware-family-relationships-with-malpedia
- analyzing-malware-persistence-with-autoruns
- analyzing-malware-sandbox-evasion-techniques

## 本机已收（避免重复）

### 同源中文技能包（`C:\Users\Administrator\.dsh\skills` 下 `cszh-*`）

| 目录 | 说明 |
| --- | --- |
| `copilot-agent-owasp-compliance` | Check any AI agent codebase against the OWASP Agentic Security Initiative (ASI) Top 10 risks. Use this skill when：- Evaluating an agent syst… |
| `copilot-agent-supply-chain` | Verify supply chain integrity for AI agent plugins, tools, and dependencies. Use this skill when：- Generating SHA-256 integrity manifests fo… |
| `copilot-audit-integrity` | "Enforce output quality, evidence verification, and quality gates across security audits. Use this skill when you perform SAST, SCA, threat … |
| `copilot-aws-cloudwatch-investigation` | Reusable investigation patterns for AWS CloudWatch：Logs Insights query templates, alarm-to-deployment correlation, blast-radius narrowing de… |
| `copilot-github-actions-hardening` | Security hardening reviewer for GitHub Actions workflow files (.github/workflows/*.yml). Reasons about the Actions threat model that pattern… |
| `copilot-incident-postmortem` | 'Use when an outage, production incident, or significant service degradation has occurred and the team needs to write a structured blameless… |
| `copilot-mcp-implementation-security-review` | Review the implementation source code of MCP (Model Context Protocol) servers, clients, and tool handlers against a security baseline — auth… |
| `copilot-mcp-security-audit` | Audit MCP (Model Context Protocol) server configurations for security issues. Use this skill when：- Reviewing .mcp.json files for security r… |
| `copilot-secret-scanning` | 'Guide for configuring and managing GitHub secret scanning, push protection, custom patterns, and secret alert remediation. For pre-commit s… |
| `copilot-threat-model-analyst` | 'Full STRIDE-A threat model analysis and incremental update skill for repositories and systems. Supports two modes：(1) Single analysis — ful… |
| `copilot-tm7-threat-model` | 'Creates valid Microsoft Threat Modeling Tool (.tm7) files compatible with the Microsoft Threat Modeling Tool v7.3+. Use this skill whenever… |
| `cszh-analyzing-cobalt-strike-beacon-configuration` | 从 PE 文件和内存转储中提取并分析 Cobalt Strike beacon 配置，以识别 C2 基础设施、Malleable C2 配置文件和攻击者操作惯例。 |
| `cszh-analyzing-linux-kernel-rootkits` | 使用 Volatility3 Linux 插件（check_syscall、lsmod、hidden_modules）分析 Linux 内存转储，结合 rkhunter 系统扫描和 /proc 与 /sys 差异分析，检测 hooked syscall、隐藏内核模块和被篡改的系统… |
| `cszh-analyzing-macro-malware-in-office-documents` | 分析嵌入在 Microsoft Office 文档（Word、Excel、PowerPoint）中的恶意 VBA 宏， 识别下载摇篮、载荷执行、持久化机制和反分析技术。 |
| `cszh-analyzing-memory-dumps-with-volatility` | 使用 Volatility 框架分析被攻陷系统的 RAM 内存转储，以识别恶意进程、注入代码、 网络连接、加载模块和提取凭据。 |
| `cszh-analyzing-packed-malware-with-upx-unpacker` | 识别并解包 UPX 加壳及其他加壳恶意软件样本，以暴露原始可执行代码供静态分析使用。 |
| `cszh-bypassing-authentication-with-forced-browsing` | 在授权安全评估中，通过枚举 URL 并绕过身份验证控制，发现和访问未受保护的页面、API 及管理界面。 |
| `cszh-catalog` | 中文网络安全技能库索引（734+ 技能），按主题检索并给出上游取用路径；当需要中文视角的渗透/取证/检测/云安全/威胁情报方法论时使用 |
| `cszh-conducting-cloud-infrastructure-penetration-test` | 针对 AWS、Azure 和 GCP 执行云基础设施渗透测试，使用 Pacu、ScoutSuite 和 Prowler 识别 IAM 错误配置、暴露的存储桶、不安全的无服务器函数和云原生攻击路径。 |
| `cszh-conducting-cloud-penetration-testing` | 本 skill 概述了对 AWS、Azure 和 GCP 云环境进行授权渗透测试的方法论。 |
| `cszh-conducting-domain-persistence-with-dcsync` | 执行 DCSync 攻击以复制活动目录（Active Directory）凭据，通过提取 KRBTGT、域管理员和服务账户哈希来建立域持久化，并用于创建黄金票据（Golden Ticket）。 |
| `cszh-conducting-internal-network-penetration-test` | 执行内部网络渗透测试，模拟内部威胁或后渗透攻击者，以识别企业网络内的横向移动路径、权限提升向量和敏感数据暴露情况。 |
| `cszh-conducting-network-penetration-test` | 对授权目标环境执行全面网络渗透测试，通过主机发现、端口扫描、服务枚举、漏洞识别和受控漏洞利用，评估网络基础设施的安全态势。 |
| `cszh-deobfuscating-powershell-obfuscated-malware` | 使用 AST 分析、动态追踪以及 PSDecode 和 PowerDecode 等工具，系统地对多层 PowerShell 恶意软件进行去混淆，以揭示隐藏的载荷和 C2 基础设施。 |
| `cszh-detecting-fileless-malware-techniques` | 检测和分析完全在内存中运行的无文件恶意软件，这类恶意软件利用 PowerShell、 WMI、.NET 反射、注册表存储载荷和离地攻击二进制文件（LOLBins）， 不在磁盘上写入传统可执行文件。 |
| `cszh-exploiting-active-directory-with-bloodhound` | BloodHound 是基于图论的活动目录侦察工具，使用图论揭示 AD 环境中隐藏的和意外的关系。红队使用 BloodHound 识别从已控制账户到域管理员等高价值目标的攻击路径。 |
| `cszh-exploiting-http-request-smuggling` | 检测并利用由前端和后端服务器之间 Content-Length 与 Transfer-Encoding 解析差异引起的 HTTP 请求走私漏洞。 |
| `cszh-exploiting-insecure-deserialization` | 在授权渗透测试中识别并利用 Java、PHP、Python 和 .NET 应用程序中的不安全反序列化漏洞以实现远程代码执行。 |
| `cszh-exploiting-jwt-algorithm-confusion-attack` | 利用 JWT 算法混淆漏洞，该漏洞存在于服务器令牌验证库接受 JWT 头中指定的算法而非强制使用固定算法的场景。 |
| `cszh-exploiting-kerberoasting-with-impacket` | 使用 Impacket 的 GetUserSPNs 执行 Kerberoasting 攻击，提取并破解活动目录服务账户的 Kerberos TGS 票据。 |
| `cszh-exploiting-ms17-010-eternalblue-vulnerability` | MS17-010（EternalBlue）是微软 SMBv1 实现中的一个严重漏洞，允许远程代码执行。最初由 NSA 发现，2017 年被 Shadow Brokers 泄露，曾被用于 WannaCry 和 NotPetya 勒索软件攻击活动。 |
| `cszh-exploiting-nopac-cve-2021-42278-42287` | 利用 noPac 漏洞链（CVE-2021-42278 sAMAccountName 欺骗和 CVE-2021-42287 KDC PAC 混淆），在活动目录环境中从普通域用户提升至域管理员权限。 |
| `cszh-exploiting-sql-injection-vulnerabilities` | 在授权渗透测试中，使用手动技术和 sqlmap 等自动化工具识别并利用 Web 应用程序中的 SQL 注入漏洞。 |
| `cszh-exploiting-sql-injection-with-sqlmap` | 在授权渗透测试中使用 sqlmap 检测并利用 SQL 注入漏洞以提取数据库内容。 |
| `cszh-exploiting-template-injection-vulnerabilities` | 检测并利用 Jinja2、Twig、Freemarker 等模板引擎中的服务器端模板注入（SSTI）漏洞，实现远程代码执行。 |
| `cszh-exploiting-zerologon-vulnerability-cve-2020-1472` | 利用 Netlogon 远程协议中的 Zerologon 漏洞（CVE-2020-1472），通过将机器账户密码重置为空来实现域控制器入侵。 |
| `cszh-extracting-credentials-from-memory-dump` | 使用 Volatility 和 Mimikatz 从内存转储中提取缓存的凭据、密码哈希、Kerberos 票据和身份验证令牌，用于取证调查。 |
| `cszh-extracting-iocs-from-malware-samples` | 从恶意软件样本中提取攻陷指标（IoC），包括文件哈希、网络指标（IP、域名、URL）、 主机痕迹（文件路径、注册表键、互斥锁）以及行为模式，用于威胁情报共享和检测规则创建。 |
| `cszh-hunting-for-defense-evasion-via-timestomping` | 通过比较 MFT 中的 $STANDARD_INFORMATION 与 $FILE_NAME 时间戳， 检测 NTFS 时间戳篡改（MITRE T1070.006）。 |
| `cszh-hunting-for-lateral-movement-via-wmi` | 通过分析 Windows 事件 ID 4688 进程创建和 Sysmon 事件 ID 1 中的 WmiPrvSE.exe 子进程模式、远程进程执行以及 WMI 事件订阅持久化，检测基于 WMI 的横向移动。 |
| `cszh-performing-aws-privilege-escalation-assessment` | 在 AWS 环境中执行已授权的权限提升（Privilege Escalation）评估，使用 Pacu、CloudFox、Principal Mapper 和手动 IAM 策略分析技术，识别允许用户或角色提升权限的 IAM 配置错误。 |
| `cszh-performing-cloud-penetration-testing` | 对 AWS、Azure 和 GCP 云环境执行授权渗透测试，识别 IAM 错误配置、暴露的存储桶、过度宽松的安全组、 无服务器函数漏洞以及从初始访问到账户沦陷的云特定攻击路径。 |
| `cszh-performing-cloud-penetration-testing-with-pacu` | 使用开源 AWS 利用框架 Pacu 执行已授权的 AWS 渗透测试，枚举 IAM 配置、发现权限提升路径、测试凭据收集，并通过系统化的攻击模拟验证安全控制。 |
| `cszh-performing-credential-access-with-lazagne` | 在授权红队行动中，使用 LaZagne 后渗透工具从已控制的终端提取存储的凭据，从浏览器、数据库、系统密钥库和应用程序中恢复密码。 |
| `cszh-performing-firmware-malware-analysis` | 分析固件镜像中嵌入的恶意软件、后门和未授权修改，目标包括路由器、IoT 设备、UEFI/BIOS 和嵌入式系统。 |
| `cszh-performing-gcp-penetration-testing-with-gcpbucketbrute` | 使用 GCPBucketBrute 执行 GCP 安全测试，进行存储桶（Storage Bucket）枚举、gcloud IAM 权限提升路径分析和服务账号权限审计。 |
| `cszh-performing-hash-cracking-with-hashcat` | 哈希破解（Hash Cracking）是渗透测试人员和安全审计员评估密码强度的重要技能。Hashcat 是全球最快的密码恢复工具，支持 GPU 加速下的超过 300 种哈希类型。本技能涵盖在授权许可下使用 Hashcat 进行密码审计、理解攻击模式、创建有效规则集以及生成哈希分析… |
| `cszh-performing-kubernetes-penetration-testing` | Kubernetes 渗透测试（Penetration Testing）通过对 API server、kubelet、etcd、Pod、RBAC、网络策略和密钥模拟攻击者技术，系统性评估集群安全性。使用 kube-hunter、Kubescape、peirates 等工具识别可能… |
| `cszh-performing-lateral-movement-with-wmiexec` | 在红队演练中，使用基于 WMI 的远程执行技术（包括 Impacket wmiexec.py、CrackMapExec 和原生 WMI 命令）在 Windows 网络中执行横向移动，实现隐蔽的后渗透操作。 |
| `cszh-performing-malware-triage-with-yara` | 使用 YARA 规则对文件模式、字符串、字节序列和结构特征进行匹配，快速分级和分类恶意软件样本， 识别已知恶意软件家族及可疑指标。 |
| `cszh-performing-memory-forensics-with-volatility3` | 使用 Volatility 3 分析易失性内存转储，以提取运行中的进程、网络连接、加载的模块以及恶意活动的证据。 |
| `cszh-performing-privilege-escalation-on-linux` | Linux 权限提升是指在已控制的系统上从低权限用户账户提升至 root 访问权限。红队通过利用错误配置、存在漏洞的服务、内核漏洞利用和弱权限来实现 root 访问。 |
| `cszh-performing-static-malware-analysis-with-pe-studio` | 使用 PEStudio 对 Windows PE（可移植可执行文件）恶意软件样本进行静态分析， 检查文件头、导入表、字符串、资源和指标，无需执行二进制文件。 |
| `cszh-performing-web-application-firewall-bypass` | 使用编码技术、HTTP 方法操控、参数污染和载荷混淆绕过 Web 应用防火墙保护，将 SQL 注入、XSS 及其他攻击载荷穿透 WAF 检测规则。 |
| `cszh-reverse-engineering-android-malware-with-jadx` | 使用 JADX 反编译器对恶意 Android APK 文件进行逆向工程，分析 Java/Kotlin 源代码，识别包括数据窃取、C2 通信、权限提升和覆盖攻击在内的恶意功能。 |
| `cszh-reverse-engineering-malware-with-ghidra` | 使用 NSA 的 Ghidra 反汇编器和反编译器对恶意软件二进制文件进行逆向工程，在汇编和伪 C 代码层面理解其内部逻辑、密码学例程、C2 协议和规避技术。 |
| `cszh-reverse-engineering-ransomware-encryption-routine` | 对勒索软件加密例程进行逆向工程，以识别密码学算法、密钥生成缺陷，以及通过静态和动态分析挖掘潜在的解密机会。 |
| `cybersecurity-review` | Ultimate AI-powered cybersecurity code review skill. Performs comprehensive security audit across 8 dimensions：vulnerability detection (OWAS… |
| `cyberskills-ai-risk-management` | Apply the NIST AI Risk Management Framework (AI RMF 1.0) and adjacent guidance to AI / ML systems — model lifecycle governance, fairness and… |
| `cyberskills-api-audit` | Audit REST, GraphQL, and RPC APIs against the OWASP API Security Top 10 (2023). Use when the user mentions 'API security,' 'API audit,' 'BOL… |
| `cyberskills-breach-patterns` | Learn from public breach disclosures — extract the audit question each one implies and check your own stack. Capital One IMDS abuse, LastPas… |
| `cyberskills-cloud-audit` | Audit cloud infrastructure (AWS, GCP, Azure) for misconfigurations, excessive permissions, and security gaps. Use when the user mentions 'cl… |
| `cyberskills-container-audit` | Audit container images, Dockerfiles, and Kubernetes manifests for misconfigurations, excessive privileges, exposed secrets, and runtime risk… |
| `cyberskills-crypto-audit` | Audit cryptography implementation — algorithm choice, key sizes, KDF parameters, IV/nonce handling, signature verification, randomness, TLS … |
| `cyberskills-csf-mapping` | Map your security posture against the NIST Cybersecurity Framework 2.0 (Govern, Identify, Protect, Detect, Respond, Recover). Produce a gap … |
| `cyberskills-dependency-audit` | Audit project dependencies, frameworks, languages, and dev tools for known vulnerabilities, CVEs, and security anti-patterns. Use when the u… |
| `cyberskills-disk-forensics` | Analyze disk images, file systems, and memory captures for digital evidence recovery in forensic investigations and CTF challenges. Use when… |
| `cyberskills-finding-triage` | Triage a single security finding — from a scanner, audit, advisory, or report — to a defensible disposition with a mitigation plan, false-po… |
| `cyberskills-hipaa-audit` | Audit applications and infrastructure handling Protected Health Information against HIPAA — Security Rule (administrative, physical, technic… |
| `cyberskills-iam-audit` | Audit, design, and migrate Identity and Access Management — cloud provider IAM (AWS, GCP, Azure), identity providers (Okta, Entra ID / Azure… |
| `cyberskills-incident-triage` | Guide rapid triage and initial response to security incidents following NIST SP 800-61 methodology. Use when the user mentions 'incident res… |
| `cyberskills-mobile-audit` | Audit iOS and Android mobile applications against OWASP MASVS / MASTG — insecure storage, weak crypto, certificate pinning, deeplinks, IPC, … |
| `cyberskills-osint-recon` | Gather and correlate open source intelligence from public sources for authorized investigations, threat intelligence, and attack surface ass… |
| `cyberskills-owasp-audit` | Audit application source code against the OWASP Top 10 (2021) vulnerability categories — broken access control, cryptographic failures, inje… |
| `cyberskills-pci-audit` | Audit applications and infrastructure handling payment card data against PCI DSS v4.0. Heavy emphasis on scope determination (the single mos… |
| `cyberskills-privacy-engineering` | Implement and audit privacy controls in product and infrastructure — GDPR, CCPA / CPRA, LGPD, PIPEDA. Covers data minimization, lawful basis… |
| `cyberskills-prompt-injection` | Audit applications for AI prompt injection, agent security, and LLM permission boundary vulnerabilities. Use when the user mentions 'prompt … |
| `cyberskills-recon` | Perform structured reconnaissance and attack surface enumeration for authorized penetration tests, CTF challenges, and bug bounty programs. … |
| `cyberskills-red-team-engagement` | Plan, scope, and execute an authorized red-team engagement — distinct from a penetration test. Covers engagement methodology, assumed-breach… |
| `cyberskills-secrets-audit` | Find leaked secrets in source code, Git history, build artifacts, and infrastructure — and audit the secrets-management posture preventing f… |
| `cyberskills-security-comms` | Translate technical security work into the language of non-security audiences — board, executives, engineering, customer success, customers,… |
| `cyberskills-siem-detection` | Engineer and audit SIEM detection rules — log source coverage, Sigma / KQL / SPL / Elastic query authoring, MITRE ATT&CK mapping, false-posi… |
| `cyberskills-soc-operations` | Build, run, and improve a Security Operations Center — alert prioritization, runbook authoring, escalation criteria, on-call structure, aler… |
| `cyberskills-threat-hunting` | Conduct proactive, hypothesis-driven threat hunts — search SIEM / EDR / logs for adversaries who haven't tripped an alert yet. ATT&CK-driven… |
| `cyberskills-threat-modeling` | Run a structured threat-modeling session for a new feature, system, or architecture — STRIDE, attack trees, data flow diagrams, abuse cases.… |
| `cyberskills-vuln-research` | Research a specific CVE or vulnerability disclosure end-to-end — what version is affected, is your code reachable, is there a public PoC, is… |
| `cyberskills-web-pentest` | Perform black-box / grey-box web application penetration testing on an authorized target — auth bypass, IDOR, session handling, business-log… |
| `hfh-code-audit` | 网络安全知识库「代码审计」分类技能包，源自 Hi-FullHouse/CyberSecurity-Skills 上游 12-代码审计-CodeAudit。按语言给出白盒/灰盒审计方法论与危险函数速查：PHP（注入、文件操作、反序列化）、Java（Spring/Struts2、反序… |
| `hfh-exploitation` | 网络安全知识库「漏洞利用」分类技能包，源自 Hi-FullHouse/CyberSecurity-Skills 上游 03-漏洞利用-Exploitation。覆盖 Metasploit 框架利用、SQL 注入、XSS 跨站脚本、SSRF 服务端请求伪造（含防御绕过速查）、命令注… |
| `hfh-incident-response` |  |
| `hfh-lateral-movement` | 网络安全知识库「横向移动」分类技能包，源自 Hi-FullHouse/CyberSecurity-Skills 上游 06-横向移动-LateralMovement。覆盖以已控机器为跳板横向扩展（Pass-the-Hash、票据传递、域内移动、技术对比）、Windows 远程执行… |
| `hfh-llm-security` |  |
| `hfh-persistence` | 网络安全知识库「持久化」分类技能包，源自 Hi-FullHouse/CyberSecurity-Skills 上游 07-持久化-Persistence。覆盖 Windows 与跨平台持久化总览（注册表与服务、计划任务、WMI 事件订阅，含持久化技术对比）、启动项与登录自动执行（… |
| `hfh-post-exploitation` | 网络安全知识库「后渗透」分类技能包，源自 Hi-FullHouse/CyberSecurity-Skills 上游 05-后渗透-PostExploitation。覆盖被控系统上的信息收集与数据窃取（系统/用户/网络拓扑/文件、数据优先级分级与外传）、凭证转储与哈希传递（Mimi… |
| `hfh-privilege-escalation` | 网络安全知识库「权限提升」分类技能包，源自 Hi-FullHouse/CyberSecurity-Skills 上游 04-权限提升-PrivilegeEscalation。覆盖 Linux 提权（SUID/SGID、sudo 配置、Cron、环境变量、内核漏洞）、Windows… |
| `hfh-reconnaissance` | 网络安全知识库「信息搜集」分类技能包，源自 Hi-FullHouse/CyberSecurity-Skills 上游 01-信息搜集-Reconnaissance。覆盖被动信息搜集（OSINT/Google Dork/证书透明）、主动信息搜集（Nmap 端口与服务探测）、DNS … |
| `hfh-reverse-engineering` | 网络安全知识库「逆向工程」分类技能包，源自 Hi-FullHouse/CyberSecurity-Skills 上游 13-逆向工程-ReverseEngineering。覆盖静态逆向分析（文件格式与 PE/ELF 结构、反汇编反编译、加壳识别、字符串与算法还原）、动态调试试分析… |
| `hfh-social-engineering` |  |
| `hfh-vulnerability-scanning` | 网络安全知识库「漏洞扫描」分类技能包，源自 Hi-FullHouse/CyberSecurity-Skills 上游 02-漏洞扫描-VulnerabilityScanning。覆盖网络与主机漏洞扫描（OpenVAS/GVM、Nessus、Nmap NSE）、Web 漏洞扫描（N… |
| `secskills-ai-llm-security` | LLM and AI application security testing — prompt injection, jailbreak resistance, OWASP LLM Top 10 (2025), RAG and agent/tool-use security, … |
| `secskills-blue-team-defense` | System hardening, detection engineering, security baseline monitoring, patch management, defense-in-depth architecture, and security posture… |
| `secskills-cloud-security` | AWS/Azure/GCP security auditing, container and Kubernetes hardening, Infrastructure as Code scanning, and cloud compliance assessment |
| `secskills-crypto-analysis` | SSL/TLS auditing, cipher suite analysis, hash algorithm identification, encryption implementation review, and cryptographic weakness detecti… |
| `secskills-csoc-automation` | SOC alert triage, incident playbook automation, escalation workflows, shift reporting, and SOC KPI tracking |
| `secskills-exploit-development` | Proof-of-concept development, payload crafting, shellcode analysis, and exploitation technique research for authorized security testing |
| `secskills-grc-compliance` | Governance, risk, and compliance — risk assessment and scoring, control mapping across NIST CSF 2.0 / ISO 27001:2022 / SOC 2 / CIS Controls … |
| `secskills-hub` | Masriyan Claude-Code-CyberSecurity-Skill 技能库总索引：22 个网络安全技能的完整清单（名字 + 一句话职责 + 所属大类，覆盖进攻/防守/逆向/威胁情报/紫队/CSOC/AI 安全/移动/OT-ICS/GRC/供应链）、触发词路由、共享证… |
| `secskills-incident-response` | IR playbook execution, evidence collection, forensic timeline analysis, memory forensics, and post-incident reporting following NIST SP 800-… |
| `secskills-log-analysis` | Security log parsing, anomaly detection, SIEM query building, Sigma rule creation, and correlation rule development across Splunk, Elastic, … |
| `secskills-malware-analysis` | Static and dynamic malware analysis, YARA rule generation, sandbox configuration, behavioral profiling, and malware family classification |
| `secskills-mobile-security` | Android and iOS application security testing — static and dynamic analysis, APK/IPA inspection, OWASP MASVS/MASTG verification, secure-stora… |
| `secskills-network-security` | Network traffic analysis, PCAP parsing, IDS/IPS rule creation, firewall configuration auditing, and network anomaly detection |
| `secskills-ot-ics-security` | Operational Technology and industrial control system security — Purdue model segmentation, industrial protocol analysis (Modbus, DNP3, S7, E… |
| `secskills-purple-team` | Collaborative purple-team operations — threat-informed adversary emulation planning (ATT&CK, CTID, Atomic Red Team, CALDERA), the detect-tun… |
| `secskills-recon-osint` | Passive and active reconnaissance, subdomain enumeration, DNS analysis, technology fingerprinting, and OSINT data correlation for authorized… |
| `secskills-red-team-ops` | Authorized red team engagement planning, C2 architecture design, attack methodology, lateral movement strategy, OPSEC, and professional repo… |
| `secskills-reverse-engineering` | Binary analysis, assembly interpretation, disassembly, decompilation, firmware RE, and protocol reverse engineering |
| `secskills-supply-chain-security` | Software supply chain security — SBOM generation and analysis, dependency confusion and typosquatting detection, malicious package indicator… |
| `secskills-threat-hunting` | IOC extraction, threat intelligence correlation, MITRE ATT&CK mapping, hunt hypothesis generation, and detection rule creation |
| `secskills-threat-intelligence` | Cyber threat intelligence production — the intelligence cycle, IOC extraction/normalization/enrichment, STIX/TAXII and MISP, structured anal… |
| `secskills-vulnerability-scanner` | Dependency auditing, CVE detection, configuration security review, CVSS scoring, and prioritized vulnerability reporting |
| `secskills-web-security` | OWASP Top 10 testing, injection vulnerability detection, API security assessment, authentication testing, and web vulnerability reporting fo… |
| `security-audit` | Security guidance and vulnerability review for codebases, APIs, services, CLI tools, libraries, and daemons. Use for security questions, foc… |
| `security-review` | AI-powered codebase security scanner that reasons about code like a security researcher： tracing data flows, understanding component interac… |

### 本机红队技能（`C:\Users\Administrator\.dsh\redteam\skills\`）

命中以下主题时优先用本机红队技能（环境与工具路径已配好），再到上游取中文方法论补充：

- active-scan, asset-correlation, browser-automation, chisel-tunnel, cn-proxy-pool, credential-attack, dir-bruteforce, fofa-recon, frp-tunnel, fscan-intranet, gogo-intranet, kimi-webbridge, lateral-movement, nuclei-scan, passive-recon, recon-pipeline, redteam-setup, shell-handler, suo5-tunnel, unauth-exploit, vps-reverse-shell, web-fingerprint, webshell-toolkit

## 维护

- 刷新索引（上游更新后）：重跑仓库 tree API 取 `skills/<名>/SKILL.md` 的 `<名>` 与 size，重建 `references/all-skills.md`。
- 本包只存索引，不存上游正文；正文永远现取，保证与上游一致。
