---
name: secskills-hub
description: Masriyan Claude-Code-CyberSecurity-Skill 技能库总索引：22 个网络安全技能的完整清单（名字 + 一句话职责 + 所属大类，覆盖进攻/防守/逆向/威胁情报/紫队/CSOC/AI 安全/移动/OT-ICS/GRC/供应链）、触发词路由、共享证据契约与上游 README、schema、工具脚本、MITRE 与 OWASP 对齐方式。当需要挑选该技能库中合适的技能、了解其目录结构或遵守其证据规范时使用。
---

> **来源仓库**：https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill （上游 `skills/` 下的 22 个技能本体由另一条线转换，本包只做**地图/索引**，不重复收录）。
> **用途**：先读本包确定该用哪个技能，再去 `C:\Users\Administrator\.dsh\skills\secskills-*` 里调用对应技能；同时承载该库的共享证据契约、schema、工具与 MITRE/OWASP 对齐说明。
> **本包结构**：`references/upstream-readme.md`（上游 README 原文，302 行）、`references/USAGE.md`、`references/schemas/`、`references/cyberskill/`、`references/tools/`、`references/docs/`、`references/.claude-plugin/`、`references/tests/`。

## 一句话导航

本技能库 = **22 个编号技能**（`skills/01-…` ~ `skills/22-…`，每个含 `SKILL.md` + `scripts/` + `examples/`，部分含 `resources/`）＋ **一套共享证据契约**（`cyberskill/`、`schemas/evidence.schema.json`、`docs/QUALITY.md`）＋ **标准化工具**（`tools/`）。
技能编号不是执行顺序，而是"领域分区"；同一编号技能内部自带 `Purpose / Activation Triggers / Prerequisites / Core Capabilities / Output Template / Script Reference / Skill Integration / References` 结构。

## 22 个技能总清单（名字 + 一句话职责 + 所属大类）

### 进攻 / 侦察 / 利用（进攻（红队向））

- **01-recon-osint**（`skills/01-recon-osint/`，进攻 / 侦察）— 被动与主动侦察、子域枚举、DNS 分析、技术指纹与 OSINT 关联
  - 上游英文描述（原文）：Passive and active reconnaissance, subdomain enumeration, DNS analysis, technology fingerprinting, and OSINT data correlation for authorized security assessments
- **02-vulnerability-scanner**（`skills/02-vulnerability-scanner/`，进攻 / 漏洞发现）— 依赖审计、CVE 检出、配置安全复核、CVSS 评分与漏洞优先级报告
  - 上游英文描述（原文）：Dependency auditing, CVE detection, configuration security review, CVSS scoring, and prioritized vulnerability reporting
- **03-exploit-development**（`skills/03-exploit-development/`，进攻 / 利用）— POC 开发、payload 构造、shellcode 分析与利用技术研究
  - 上游英文描述（原文）：Proof-of-concept development, payload crafting, shellcode analysis, and exploitation technique research for authorized security testing
- **09-web-security**（`skills/09-web-security/`，进攻 / Web 安全）— OWASP Top 10 测试、注入检测、API 安全评估与认证测试（含 JWT）
  - 上游英文描述（原文）：OWASP Top 10 testing, injection vulnerability detection, API security assessment, authentication testing, and web vulnerability reporting for authorized assessments
- **14-red-team-ops**（`skills/14-red-team-ops/`，进攻 / 红队）— 授权红队行动规划、C2 架构设计、横向移动策略、OPSEC 与专业报告
  - 上游英文描述（原文）：Authorized red team engagement planning, C2 architecture design, attack methodology, lateral movement strategy, OPSEC, and professional reporting

### 逆向工程 / 样本分析（逆向）

- **04-reverse-engineering**（`skills/04-reverse-engineering/`，逆向工程）— 二进制分析、汇编解读、反汇编与反编译、固件与协议逆向
  - 上游英文描述（原文）：Binary analysis, assembly interpretation, disassembly, decompilation, firmware RE, and protocol reverse engineering
- **05-malware-analysis**（`skills/05-malware-analysis/`，逆向工程 / 样本分析）— 静态与动态恶意代码分析、YARA 规则生成、沙箱配置、行为画像与家族归类
  - 上游英文描述（原文）：Static and dynamic malware analysis, YARA rule generation, sandbox configuration, behavioral profiling, and malware family classification

### 防守 / 蓝队 / 检测 / 响应（防守（蓝队向））

- **06-threat-hunting**（`skills/06-threat-hunting/`，防守 / 威胁狩猎）— IOC 提取、威胁情报关联、MITRE ATT&CK 映射、狩猎假设与检测规则编写
  - 上游英文描述（原文）：IOC extraction, threat intelligence correlation, MITRE ATT&CK mapping, hunt hypothesis generation, and detection rule creation
- **07-incident-response**（`skills/07-incident-response/`，防守 / 事件响应）— IR 预案执行、证据固定、取证时间线、内存取证与复盘报告（NIST SP 800-61 / SANS PICERL）
  - 上游英文描述（原文）：IR playbook execution, evidence collection, forensic timeline analysis, memory forensics, and post-incident reporting following NIST SP 800-61 and SANS PICERL methodology
- **08-network-security**（`skills/08-network-security/`，防守 / 网络安全）— 流量分析、PCAP 解析、IDS/IPS 规则编写、防火墙配置审计与网络异常检测
  - 上游英文描述（原文）：Network traffic analysis, PCAP parsing, IDS/IPS rule creation, firewall configuration auditing, and network anomaly detection
- **11-csoc-automation**（`skills/11-csoc-automation/`，CSOC 运营）— SOC 告警分级、处置剧本自动化、升级流程、交接班报告与 SOC KPI
  - 上游英文描述（原文）：SOC alert triage, incident playbook automation, escalation workflows, shift reporting, and SOC KPI tracking
- **12-log-analysis**（`skills/12-log-analysis/`，防守 / 日志分析）— 日志解析、异常检测、SIEM 查询构建、Sigma 与关联规则（Splunk/Elastic/QRadar/Sentinel）
  - 上游英文描述（原文）：Security log parsing, anomaly detection, SIEM query building, Sigma rule creation, and correlation rule development across Splunk, Elastic, QRadar, and Microsoft Sentinel
- **15-blue-team-defense**（`skills/15-blue-team-defense/`，防守 / 蓝队）— 系统加固、检测工程、安全基线监控、补丁管理、纵深防御与安全态势提升
  - 上游英文描述（原文）：System hardening, detection engineering, security baseline monitoring, patch management, defense-in-depth architecture, and security posture improvement

### 专门领域安全（专域）

- **10-cloud-security**（`skills/10-cloud-security/`，云与容器安全）— AWS/Azure/GCP 安全审计、容器与 K8s 加固、IaC 扫描与云合规评估
  - 上游英文描述（原文）：AWS/Azure/GCP security auditing, container and Kubernetes hardening, Infrastructure as Code scanning, and cloud compliance assessment
- **13-crypto-analysis**（`skills/13-crypto-analysis/`，密码学安全）— SSL/TLS 审计、密码套件分析、哈希识别、加密实现复核与弱点检测
  - 上游英文描述（原文）：SSL/TLS auditing, cipher suite analysis, hash algorithm identification, encryption implementation review, and cryptographic weakness detection in code
- **16-ai-llm-security**（`skills/16-ai-llm-security/`，AI 安全）— LLM/AI 应用安全测试：提示注入、越狱抵抗、OWASP LLM Top 10、RAG 与工具调用安全、模型供应链
  - 上游英文描述（原文）：LLM and AI application security testing — prompt injection, jailbreak resistance, OWASP LLM Top 10 (2025), RAG and agent/tool-use security, model supply chain, and AI red teaming for authorized assessments
- **17-mobile-security**（`skills/17-mobile-security/`，移动安全）— Android/iOS 测试：静态与动态分析、APK/IPA 检查、OWASP MASVS/MASTG、存储与传输复核
  - 上游英文描述（原文）：Android and iOS application security testing — static and dynamic analysis, APK/IPA inspection, OWASP MASVS/MASTG verification, secure-storage and transport review, and mobile malware triage for authorized assessments
- **18-ot-ics-security**（`skills/18-ot-ics-security/`，OT / ICS 安全）— Purdue 模型分区、工业协议分析（Modbus/DNP3/S7/EtherNet-IP）、PLC/HMI 暴露面、IEC 62443 与 ATT&CK for ICS
  - 上游英文描述（原文）：Operational Technology and industrial control system security — Purdue model segmentation, industrial protocol analysis (Modbus, DNP3, S7, EtherNet/IP), PLC/HMI exposure, IEC 62443 alignment, and MITRE ATT&CK for ICS, for authorized and safety-conscious assessments

### 治理 / 情报 / 协作（治理与协作）

- **19-grc-compliance**（`skills/19-grc-compliance/`，GRC / 合规）— 风险量化打分、跨框架控制映射（NIST CSF 2.0/ISO 27001/SOC 2/CIS v8）、差距分析与审计证据
  - 上游英文描述（原文）：Governance, risk, and compliance — risk assessment and scoring, control mapping across NIST CSF 2.0 / ISO 27001:2022 / SOC 2 / CIS Controls v8, gap analysis, audit evidence preparation, and security policy generation
- **20-supply-chain-security**（`skills/20-supply-chain-security/`，供应链安全）— SBOM 生成分析、依赖混淆与仿冒包检测、恶意包指标、CI/CD 加固与制品签名（SLSA/Sigstore）
  - 上游英文描述（原文）：Software supply chain security — SBOM generation and analysis, dependency confusion and typosquatting detection, malicious package indicators, CI/CD pipeline hardening, and artifact provenance/signing (SLSA, Sigstore)
- **21-threat-intelligence**（`skills/21-threat-intelligence/`，威胁情报）— 情报循环、IOC 提取归一化富化、STIX/TAXII 与 MISP、结构化分析模型（Diamond/Kill Chain/ATT&CK）、来源评分
  - 上游英文描述（原文）：Cyber threat intelligence production — the intelligence cycle, IOC extraction/normalization/enrichment, STIX/TAXII and MISP, structured analytic models (Diamond, Kill Chain, ATT&CK), source scoring, actor/campaign tracking, and finished intelligence reporting
- **22-purple-team**（`skills/22-purple-team/`，紫队）— 威胁驱动的对手模拟规划（ATT&CK/Atomic Red Team/CALDERA）、检测调优验证环、覆盖率度量（DeTT&CT/Navigator）与 MTTD 报告
  - 上游英文描述（原文）：Collaborative purple-team operations — threat-informed adversary emulation planning (ATT&CK, CTID, Atomic Red Team, CALDERA), the detect-tune-validate loop, detection coverage measurement (DeTT&CT/Navigator), safe execution and deconfliction, and MTTD/coverage reporting

> 上表条目数：**22**（应为 22；缺任何一个都说明技能库不完整）。

## 触发词路由（选技能用）

| 你说的话 | 该用哪个技能 |
| --- | --- |
| 子域枚举 / OSINT / 指纹识别 / 资产发现 | 01-recon-osint |
| CVE / 依赖审计 / CVSS 打分 / 漏洞优先级 | 02-vulnerability-scanner |
| POC / payload / shellcode / 利用研究 | 03-exploit-development |
| 反汇编 / 反编译 / 固件 / 协议逆向 | 04-reverse-engineering |
| 样本分析 / YARA / 沙箱 / 家族归类 | 05-malware-analysis |
| 狩猎假设 / ATT&CK 映射 / IOC 关联 / Sigma | 06-threat-hunting |
| IR / 取证 / 时间线 / 证据保管链 / PICERL | 07-incident-response |
| PCAP / IDS-IPS / Suricata / 防火墙审计 | 08-network-security |
| OWASP Top 10 / SQLi / XSS / JWT / API 测试 | 09-web-security |
| 云审计 / K8s 加固 / IaC / Terraform | 10-cloud-security |
| 告警分级 / SOC 剧本 / 交接班 / SOC KPI | 11-csoc-automation |
| SIEM 查询 / Splunk / Elastic / Sentinel / 关联规则 | 12-log-analysis |
| TLS / 密码套件 / 哈希识别 / 加密实现复核 | 13-crypto-analysis |
| 红队规划 / C2 架构 / 横向移动 / OPSEC | 14-red-team-ops |
| 基线加固 / 检测工程 / CIS / 补丁管理 | 15-blue-team-defense |
| 提示注入 / 越狱 / OWASP LLM Top 10 / RAG 安全 | 16-ai-llm-security |
| APK / IPA / MASVS / Frida / 移动端测试 | 17-mobile-security |
| Modbus / DNP3 / PLC / Purdue / IEC 62443 | 18-ot-ics-security |
| 风险评估 / NIST CSF / ISO 27001 / SOC 2 / 差距分析 | 19-grc-compliance |
| SBOM / 依赖混淆 / typosquatting / SLSA / Sigstore | 20-supply-chain-security |
| CTI / STIX / TAXII / MISP / Diamond / 归属 | 21-threat-intelligence |
| 对手模拟 / Atomic Red Team / CALDERA / 检测覆盖率 / MTTD | 22-purple-team |

## 共享证据契约（所有 22 个技能都要遵守）

每个技能 `SKILL.md` 顶部都有一段 **Evidence contract**：把结论分成 **observed（观察到）/ inferred（推断）/ unverified（未验证）** 三类，逐条记录来源与制品引用、可用时附 SHA-256、采集时间、所做验证、局限与下一步验证。**抽取置信度不等于恶意置信度**——无法判定恶意性时保持 unknown，禁止脑补。
落地工具与规范（本包内）：
- `references/schemas/evidence.schema.json` — 证据条目 JSON Schema，写证据前先对照。
- `references/cyberskill/evidence.py` — 证据清单/清单摘要的共享实现。
- `references/cyberskill/indicators.py` — 指标归一化（refang：`hxxp`→`http`、`[.]`→`.` 等）与 **STIX 2.1 SCO bundle** 导出；只把抽取值当作可观测对象（SCO），**不**断言其为恶意活动；TLP 用 FIRST TLP 2.0 marking-definition（不是旧版 STIX TLP 枚举），不支持的类型会进 `x_cyberskill_unsupported_types`。
- `references/tools/evidence_manifest.py` — 生成证据清单（manifest）。
- `references/tools/standardize_skills.py` — 批量校验/标准化 22 个技能结构（上游用它保一致性）。
- `references/docs/QUALITY.md` — 质量门（输出质量标准原文）。
- `references/USAGE.md` — 上游使用说明（怎么把技能装进 Claude Code、怎么触发）。
- `references/tests/` — 上游自测（`test_evidence.py` / `test_intelligence.py` / `test_repository.py` + `conftest.py`），迁移自测口径时参考。

## 关于 `mappings/`：本仓库**没有**这个目录，对齐关系在别处

本仓库不存在 `mappings/` 目录（已用全量 git tree 核实：根目录只有 `cyberskill/`、`schemas/`、`docs/`、`tools/`、`tests/`、`.claude-plugin/`）。**框架映射不是集中表格，而是分散在三个位置**，用的时候按下面三处找：

1. **每个技能的 `SKILL.md` 里**：正文的 `Core Capabilities` / 输出模板中直接写死映射口径，末尾 `## References` 列出所用标准。例如 `06-threat-hunting` 的 ATT&CK 映射、`09-web-security` 的 OWASP Top 10、`18-ot-ics-security` 的 MITRE ATT&CK for ICS。
2. **技能元数据（frontmatter）**：22 个技能统一为 `metadata.version: 3.2.0`、`metadata.author: Masriyan`，`metadata.tags` 里带框架标签（如 `mitre-attack`、`owasp-llm`、`attack-ics`、`nist-csf`、`iso27001`、`masvs`、`iec62443`、`stix`、`attack`）——**按 tag 检索框架覆盖面最快**。
3. **共享导出实现**：`references/cyberskill/indicators.py`（指标 → STIX 2.1）+ `references/schemas/evidence.schema.json`（证据结构）。

常用框架 ↔ 技能编号对齐速查（依据上游 README 与各技能 References 段）：

| 框架 / 标准 | 相关技能 |
| --- | --- |
| MITRE ATT&CK（企业） | 06, 14, 21, 22 |
| MITRE ATT&CK for ICS | 18 |
| MITRE ATLAS / OWASP LLM Top 10 (2025) | 16 |
| OWASP Top 10（Web） | 09 |
| OWASP MASVS / MASTG | 17 |
| NIST SP 800-61 / SANS PICERL | 07 |
| NIST CSF 2.0 / ISO 27001:2022 / SOC 2 / CIS Controls v8 | 19（并见 10、15） |
| IEC 62443 / Purdue 模型 | 18 |
| STIX 2.1 / TAXII / MISP / TLP 2.0 | 21（实现见 `references/cyberskill/indicators.py`） |
| SLSA / Sigstore / SBOM（SPDX、CycloneDX） | 20 |
| Sigma / SIEM 查询语言（Splunk SPL、KQL、AQL） | 12（并见 06、11） |
| Atomic Red Team / CALDERA / DeTT&CT / ATT&CK Navigator | 22 |

## 插件与安装（上游元数据）

- `references/.claude-plugin/marketplace.json` — 上游以 Claude Code 插件市场条目发布；本机 dsh 侧不需要它，留档备查。
- `references/INSTALL.md` — 上游安装说明（Claude Code 侧装法），留档备查。
- 上游 `README.md` 里的相对链接（如 `skills/06-threat-hunting/`）**按上游仓库根解析**，即 `https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill/blob/HEAD/<相对路径>`。

## 使用顺序建议

1. 用上面的路由表定位编号 → 2. 打开对应 `secskills-*` 技能读 `Purpose`/`Activation Triggers` → 3. 按其 `Prerequisites` 备齐工具（Python 3.10+） → 4. 按 `Core Capabilities` 执行 → 5. 按该技能的 Output Template 出报告，并遵守本包 `Evidence contract` 与 `references/schemas/evidence.schema.json`。

> 转换备注：本包正文由叶节点智能体从上游仓库 `HEAD` 实拉后编写；22 个技能的 name 与 description **逐条读取上游 `skills/*/SKILL.md` 原文核实**（v3.2.0）。
