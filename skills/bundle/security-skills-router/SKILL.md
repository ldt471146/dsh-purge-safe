---
name: security-skills-router
description: 安全技能总路由：把本机 127 个安全技能按 9 类场景（代码审计／信息收集／漏洞发现／漏洞利用／隧道与横向／提权凭据／样本取证／云供应链AI／检测与合规）编排成「要干什么 → 先加载哪个技能」的对照表，并给出多技能串联的标准打法。当不确定该用哪个安全技能、或要按阶段推进一项安全工作（渗透、审计、应急、取证、合规）时先加载本技能。
---

# 安全技能总路由（security-skills-router）

本机 `$DSH_HOME/skills` 现有 **161** 个安全技能（其中本批从 8 个上游仓库摄入 127 个）。本技能只做**路由**：不重复技能内容，告诉你先加载谁、再加载谁。

- 完整清单与来源：[`_INDEX.md`](_INDEX.md)（同目录） + 工作区副本 [dsh-security-skills-INDEX.md](C:\Users\Administrator\Downloads\dsh-security-skills-INDEX.md)
- 上游中文技能库索引（735 条现取用）：`cszh-catalog`
- 本机红队工具类技能（nmap/nuclei/fscan/gogo/suo5/frp/chisel/hydra/hashcat 等）：`$DSH_HOME/redteam/skills`

## 用法

1. 先在下表找到最贴近你当前任务的**场景行**；
2. 按「先加载」列逐个 `skill` 加载（一次别超过 2–3 个，按需再加载第二个）；
3. 需要现取上游 735 条中文技能时，先加载 `cszh-catalog` 在 `references/all-skills.md` 里检索；
4. 阶段推进时按「串联打法」走，每一步的产出落到本机红队库（资产/漏洞/攻击链）。

## ① 代码/仓库安全审计（SAST 式）
- 什么时候用：给你一坨代码、一个仓库、一个 PR，要「看看有没有安全问题」
- 先加载：`security-review`、`security-audit`、`cybersecurity-review`、`copilot-audit-integrity`、`copilot-github-actions-hardening`、`copilot-mcp-implementation-security-review`
- 配合使用：`copilot-mcp-security-audit`、`cyberskills-owasp-audit`、`cyberskills-secrets-audit`、`cyberskills-dependency-audit`、`cyberskills-finding-triage`、`hfh-code-audit`

## ② 攻击面测绘与信息收集
- 什么时候用：只有单位名/域名，先摸清资产与入口
- 先加载：`hfh-reconnaissance`、`secskills-recon-osint`、`cyberskills-recon`、`cyberskills-osint-recon`、`cszh-catalog`
- 工具类（红队技能库 `$DSH_HOME/redteam/skills`）：`passive-recon`、`fofa-recon`、`recon-pipeline`、`web-fingerprint`、`asset-correlation`、`dir-bruteforce`

## ③ 漏洞发现与验证
- 什么时候用：资产清单在手，要逐条找可利用点并验证真伪
- 先加载：`secskills-vulnerability-scanner`、`hfh-vulnerability-scanning`、`cyberskills-vuln-research`、`cszh-catalog`、`copilot-audit-integrity`
- 工具类（红队技能库 `$DSH_HOME/redteam/skills`）：`nuclei-scan`、`active-scan`

## ④ 漏洞利用与拿权限（Web 为主）
- 什么时候用：已确认漏洞，要打通到服务器权限 / 数据库 / 后台账号
- 先加载：`cyberskills-web-pentest`、`secskills-web-security`、`hfh-exploitation`、`cszh-exploiting-sql-injection-with-sqlmap`、`cszh-exploiting-insecure-deserialization`、`cszh-exploiting-template-injection-vulnerabilities`
- 配合使用：`cszh-exploiting-http-request-smuggling`、`cszh-exploiting-jwt-algorithm-confusion-attack`、`cszh-performing-web-application-firewall-bypass`、`cszh-bypassing-authentication-with-forced-browsing`、`cyberskills-api-audit`、`cyberskills-prompt-injection`
- 工具类（红队技能库 `$DSH_HOME/redteam/skills`）：`unauth-exploit`、`webshell-toolkit`

## ⑤ 边界突破：隧道与内网横向
- 什么时候用：已有 WebShell / 一个入口，要把内网流量带出来并横向
- 先加载：`hfh-lateral-movement`、`hfh-post-exploitation`、`hfh-persistence`、`cszh-performing-lateral-movement-with-wmiexec`、`cszh-conducting-domain-persistence-with-dcsync`、`cszh-exploiting-kerberoasting-with-impacket`
- 配合使用：`cszh-exploiting-active-directory-with-bloodhound`、`cszh-exploiting-zerologon-vulnerability-cve-2020-1472`、`cszh-exploiting-nopac-cve-2021-42278-42287`、`cszh-extracting-credentials-from-memory-dump`、`cszh-performing-credential-access-with-lazagne`
- 工具类（红队技能库 `$DSH_HOME/redteam/skills`）：`suo5-tunnel`、`chisel-tunnel`、`frp-tunnel`、`nuclei-scan`、`gogo-intranet`、`fscan-intranet`、`lateral-movement`

## ⑥ 提权与凭据
- 什么时候用：拿到低权 shell 或一堆 hash，要提权 / 破解 / 复用
- 先加载：`hfh-privilege-escalation`、`cszh-performing-privilege-escalation-on-linux`、`cszh-performing-hash-cracking-with-hashcat`、`cyberskills-iam-audit`
- 工具类（红队技能库 `$DSH_HOME/redteam/skills`）：`credential-attack`

## ⑦ 样本/逆向/取证/应急（防守侧）
- 什么时候用：给你一个可疑样本、内存/磁盘镜像、一堆日志，要判断发生了什么
- 先加载：`secskills-malware-analysis`、`secskills-reverse-engineering`、`hfh-reverse-engineering`、`cszh-reverse-engineering-malware-with-ghidra`、`cszh-reverse-engineering-android-malware-with-jadx`、`cszh-analyzing-memory-dumps-with-volatility`
- 配合使用：`cszh-performing-memory-forensics-with-volatility3`、`cszh-analyzing-macro-malware-in-office-documents`、`cszh-analyzing-cobalt-strike-beacon-configuration`、`cszh-deobfuscating-powershell-obfuscated-malware`、`cszh-performing-malware-triage-with-yara`、`cyberskills-disk-forensics`、`secskills-incident-response`、`hfh-incident-response`、`cyberskills-incident-triage`、`secskills-log-analysis`、`secskills-network-security`

## ⑧ 云 / 容器 / 供应链 / AI / 移动 / 工控
- 什么时候用：目标不是传统内网，而是云账号、K8s、依赖链、LLM 应用或移动 App
- 先加载：`cyberskills-cloud-audit`、`secskills-cloud-security`、`cyberskills-container-audit`、`cszh-performing-kubernetes-penetration-testing`、`cszh-performing-cloud-penetration-testing`、`cszh-performing-aws-privilege-escalation-assessment`
- 配合使用：`cszh-performing-gcp-penetration-testing-with-gcpbucketbrute`、`secskills-supply-chain-security`、`hfh-supply-chain-security`、`copilot-agent-supply-chain`、`secskills-ai-llm-security`、`hfh-llm-security`、`secskills-mobile-security`、`cyberskills-mobile-audit`、`secskills-ot-ics-security`、`agent-skills-security`

## ⑨ 检测/威胁狩猎/紫队/合规（出报告、给建议）
- 什么时候用：要写检测规则、做威胁狩猎、对齐框架、交付报告
- 先加载：`cyberskills-siem-detection`、`secskills-log-analysis`、`cyberskills-threat-hunting`、`secskills-threat-hunting`、`secskills-purple-team`、`secskills-threat-intelligence`
- 配合使用：`cyberskills-soc-operations`、`secskills-csoc-automation`、`cyberskills-threat-modeling`、`copilot-threat-model-analyst`、`copilot-tm7-threat-model`、`cyberskills-csf-mapping`、`secskills-grc-compliance`、`cyberskills-pci-audit`、`cyberskills-hipaa-audit`、`cyberskills-privacy-engineering`、`cyberskills-security-comms`、`copilot-incident-postmortem`、`copilot-secret-scanning`

## 串联打法（按阶段）

**A. 打一个单位（外网 → 内网 → 靶标）**
1. `hfh-reconnaissance` / `secskills-recon-osint` + `fofa-recon` + `recon-pipeline`（铺资产面）
2. `asset-correlation`（域名↔IP↔C 段↔证书关联）→ 逐条资产过 `secskills-vulnerability-scanner` / `nuclei-scan`
3. 命中后 `cyberskills-web-pentest` 或 `hfh-exploitation` 做利用 → `webshell-toolkit` 上马
4. `suo5-tunnel` 建隧道 → `gogo-intranet` + `fscan-intranet` 铺内网 → `lateral-movement` / `hfh-lateral-movement` 横向
5. `credential-attack` + `hfh-privilege-escalation` 提权与复用凭据

**B. 审一份代码/仓库**
1. `security-review` 做推理式扫描 → `cyberskills-owasp-audit` 补 OWASP 覆盖
2. `cyberskills-secrets-audit` + `copilot-secret-scanning` 查泄露密钥
3. `cyberskills-dependency-audit` + `secskills-supply-chain-security` 查依赖与供应链
4. `copilot-audit-integrity` 做质量门（防误报、防漏报压制）→ `cyberskills-finding-triage` 出处置结论

**C. 处置一起安全事件**
1. `cyberskills-incident-triage` / `secskills-incident-response` 定性与止血
2. 样本/镜像类证据走 `secskills-malware-analysis`、`cszh-analyzing-memory-dumps-with-volatility`、`cyberskills-disk-forensics`
3. 日志类证据走 `cyberskills-siem-detection` / `secskills-log-analysis`；找潜伏走 `cyberskills-threat-hunting`
4. 收口 `copilot-incident-postmortem` + `cyberskills-security-comms`（分受众写结论）

## 已知重叠（同一主题多个来源，按需择一）

| 主题 | 可互换的技能（择一即可，不必全加载） |
| --- | --- |
| SQL 注入 | `cszh-exploiting-sql-injection-vulnerabilities` / `cszh-exploiting-sql-injection-with-sqlmap` / `cyberskills-web-pentest` |
| 云渗透 | `cszh-performing-cloud-penetration-testing` / `cszh-conducting-cloud-infrastructure-penetration-test` / `cszh-performing-cloud-penetration-testing-with-pacu` / `cyberskills-cloud-audit` |
| JWT | `cszh-exploiting-jwt-algorithm-confusion-attack` / `cyberskills-api-audit` |
| 内存取证 | `cszh-analyzing-memory-dumps-with-volatility` / `cszh-performing-memory-forensics-with-volatility3` / `cyberskills-disk-forensics` |
| 恶意样本静态分析 | `cszh-performing-static-malware-analysis-with-pe-studio` / `secskills-malware-analysis` / `hfh-reverse-engineering` |
| 威胁狩猎 | `cyberskills-threat-hunting` / `secskills-threat-hunting` |
| 威胁情报 | `secskills-threat-intelligence` / `cszh-catalog` 内同类条目 |
| 移动安全 | `secskills-mobile-security` / `cyberskills-mobile-audit` |
| 供应链 | `secskills-supply-chain-security` / `hfh-supply-chain-security` / `copilot-agent-supply-chain` |
| AI/LLM 安全 | `secskills-ai-llm-security` / `hfh-llm-security` / `cyberskills-prompt-injection` / `agent-skills-security` |
| 紫队/红蓝 | `secskills-purple-team` / `hfh-red-blue-team` |

## 维护

上游更新后可重跑：`node C:\Users\Administrator\.dsh\_skill-import-staging\build-index.mjs`（重建 `_INDEX.md`）与 `build-router.mjs`（重建本文件）；校验用 `validate-skills.mjs`（调用 dsh-purge 真实解析器）。
