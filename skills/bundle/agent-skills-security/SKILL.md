---
name: agent-skills-security
description: AI Agent 与技能（skill）生态安全策展知识地图，源自 LLMSecurity/awesome-agent-skills-security 上游 README（513 条条目、48 个基准、54 个工具、7 份规范）。按「攻击面 / 防御 / 框架与标准 / 基准测试」四类分节：攻击面含工具层提示注入、工具投毒与供应链、权限提升与过度自主、数据外泄与隐私、间接提示注入、Agent 欺骗、复合系统攻击、跨插件攻击、Agent 后门、越狱与护栏绕过；防御含权限与访问控制、运行时监控与沙箱、输入输出校验、形式化验证与分析、评估与红队；框架与标准含 OWASP Agentic Skills Top 10、OWASP Agentic AI Threats、MITRE ATLAS、NIST AI RMF、IETF Agent 认证与令牌衰减草案、MCP 与 AgentSkills 规范及可在 CI 落地的扫描/运行时防护工具；基准测试含 InjecAgent、ASB、SkillAtlas、SkillGuard 等 48 个基准与数据集。每条保留原始 URL 与一句中文导读，另附「评估第三方 agent skill 的检查点」（权限范围、外发数据、提示注入面、工具滥用、供应链完整性、代码执行面）的可操作检查动作，上游 README 全文见 references/upstream-readme.md。
---

# Agent 技能生态安全（Agent Skills Security）

> 上游来源：<https://github.com/LLMSecurity/awesome-agent-skills-security> → `README.md`（完整原文存于 `references/upstream-readme.md`，共 513 条 bullet 条目 + 48 个基准 + 54 个工具 + 7 份规范）
> 本技能包是**策展清单（curated list）的导航层**，不是工具本体：正文保留条目名与原始 URL，并给出一句中文导读；要看条目原文/摘要请打开对应链接，要看上游完整结构与全部条目请读 `references/upstream-readme.md`。

## 这个技能包解决什么问题

AI Agent 通过**外部工具、插件（plugin）与技能（skill）**与世界交互，于是多出一层新的攻击面：**skill 生态安全**——恶意或被投毒的 skill/工具描述、技能组合带来的越权、以及"模型看到的上下文"与"真正被授权的动作"之间的落差。
本清单按四类组织：**攻击面研究 → 防御研究 → 框架与标准 → 基准测试与数据集**，用于选型（该装哪层防护）、评估（这个 skill 能不能装）、以及给自己的 Agent 体系做威胁对照。

## 使用方式

1. 做**威胁建模**：先读「框架与标准」里的 OWASP AST10 / Agentic AI Threats / MITRE ATLAS，把风险编号对齐到自己的架构。
2. 做**skill 准入**：读本文末尾「评估第三方 agent skill 的检查点」，再按「工具与框架」一节挑静态扫描器与运行时网关。
3. 做**验证与验收**：用「基准测试与数据集」里的基准（InjecAgent、ASB、SkillAtlas、SkillGuard…）跑自己的 harness。
4. 做**研究与写材料**：按「攻击面」「防御」两节找论文与攻击面分类，条目名保持上游原样、URL 可直接引用。

> 条目数分布（上游 README 统计）：攻击面 175 条、防御 247 条、框架与标准 92 条（含规范与工具表）、基准 48 条、行业报告 22 条。

## 一、攻击面（Attack Research）

> 上游该章共 175 条，分 10 个子方向。以下为各方向代表条目（每条给出中文导读，条目名与 URL 保持上游原样）；全量条目见 `references/upstream-readme.md`。

### 1.1 工具层提示注入（Prompt Injection via Tools，18 条）

- **[Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection](https://arxiv.org/abs/2302.12173)** — 奠基之作：证明只需经工具输出/外部文档注入即可劫持真实 LLM 应用（Greshake 等），做威胁建模从这里起步。
- **[InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated LLM Agents](https://arxiv.org/abs/2403.02691)** — 工具集成 Agent 的间接注入基准（1,054 用例 / 17 工具，含直接危害与数据窃取两类），能力评估可直接照用。
- **[Climbing the Hill: Prompt Injection Red-Teaming Against Frontier Models with Curriculum Reinforcement Learning](https://arxiv.org/abs/2609.33628)** — 用课程强化学习解决"前沿模型下攻击全失败→零奖励"的冷启动，ASR@10 达 93.8%/45.0%，是注入红队的方法学参考。
- **[Same Bytes, Different Authority: Reserved-Token Representations in Chat-Template Prompt Injection](https://arxiv.org/abs/2609.35932)** — 同名不同权：伪造的 chat-template 标记若以保留控制令牌进入模型会显著增强注入；防御侧必须管住分词与协议令牌。
- **[Prompt Injection as Role Confusion](https://arxiv.org/abs/2603.12277)** — 解释注入为何得逞——模型用风格线索而非结构化角色标签推断权限，"去风格化"可让成功率从 61% 掉到 10%。
- **[On the Inseparability of Instructions and Data in Shared-Embedding Sequence Models](https://arxiv.org/abs/2606.27567)** — 理论结论：共享嵌入架构下"完美防注入"不可能，必须做指令/数据通道隔离，而不是继续加分类器。
- **[From Prompt Injection to Web Exploitation: Revisiting Classic Vulnerabilities in LLM-Integrated Applications](https://arxiv.org/abs/2608.10281)** — 把注入接到传统 Web sink（LLM2SQLi/XSS/SSTI/SSRF…），说明 Agent 让老漏洞以"被误用的代理人"形式回归。
- **[Surviving the Router: Optimizing Skill Injections for Retrieval and Execution](https://arxiv.org/abs/2610.08098)** — 指出评估若忽略"技能检索"环节会高估攻击成功率 87–97%，做 skill 注入评估前必看。
- **[Control-Token Injection Suppresses Chain-of-Thought and Defeats Reasoning-Based Oversight in Tool-Using Agents](https://arxiv.org/abs/2609.27542)** — 单个控制令牌即可抹掉思维链却照常触发工具调用（39.6% 拒绝转成外传），说明安全是模型 + 解码 harness 的联合属性。

### 1.2 工具投毒与供应链（Tool Poisoning & Supply Chain，47 条）

- **[ShareLock: A Stealthy Multi-Tool Threshold Poisoning Attack Against MCP](https://arxiv.org/abs/2606.27027)** — 把恶意指令用门限秘密分享拆进多个工具描述，逐个工具扫描都看不出问题——工具投毒的关键变种。
- **[PhantomSkill: Malicious Code Injection in Agent Skill Ecosystems](https://arxiv.org/abs/2606.19191)** — skill 生态中的恶意代码注入面与实证，做 skill 准入必读。
- **[Skill-Inject: Measuring Agent Vulnerability to Skill File Attacks](https://arxiv.org/abs/2602.20156)** — 量化 Agent 对 skill 文件攻击的脆弱性，可作为自建验收测试的蓝本。
- **[Skills Are Not Islands: Measuring Dependency and Risk in Agent Skill Supply Chains](https://arxiv.org/abs/2607.01136)** — "技能不是孤岛"：度量 skill 之间的依赖与风险传导，治理要覆盖依赖图。
- **[Skills That Don't Exist: A Large-Scale Study of Hallucinated Skill Recommendation in LLM Agents](https://arxiv.org/abs/2607.12340)** — 大规模研究"不存在的技能"被幻觉调用，供应链盘点要把幻觉技能算进去。
- **[Towards a Risk Assessment of Malicious Skill Files in Coding Agents](https://arxiv.org/abs/2608.05223)** — 恶意 skill 文件的风险评估框架，适合直接抄来设计准入评分卡。
- **[ColluSkill: Adversarial Cross-Skill Composition for Evading Agent Skill Scanners](https://arxiv.org/abs/2608.09732)** — 跨 skill 串谋（collusion）绕过单 skill 检测，是组合攻击的代表工作。
- **[CompoSkill: Compositional Skill Chain Attacks from Individually Scanner-Passing LLM Agent Skills](https://arxiv.org/abs/2608.16246)** — 由无害 skill 组合出攻击链，证明只审单个 skill 不够。
- **[Supply-Chain Poisoning Attacks Against LLM Coding Agent Skill Ecosystems](https://arxiv.org/abs/2604.03081)** — 直接针对编码 Agent（coding agent）skill 的供应链投毒研究。
- **[PyCache Trap: The Inspection-Execution Gap in Agent Skill Scanners](https://arxiv.org/abs/2610.10612)** — "检查-执行缝隙"：扫描器看不见但执行时会触发（PyCache 类），说明静态扫描必须配运行时。
- **[Pretext: Defeating Malicious Skill Detection Frameworks for AI Agents](https://arxiv.org/abs/2609.39607)** — 专打恶意 skill 检测框架的攻击，提醒检测器本身需要对抗性评估。

### 1.3 权限提升与过度自主（Privilege Escalation & Excessive Agency，14 条）

- **[Watch Out for Your Agents! Investigating Backdoor Threats to LLM-Based Agents](https://arxiv.org/abs/2402.11208)** — Agent 后门威胁的系统研究，做持久化/后门风险对照用。
- **[Post-Training Local LLM Agents for Linux Privilege Escalation with Verifiable Rewards](https://arxiv.org/abs/2603.17673)** — 实证本地 LLM Agent 会被用于 Linux 提权，说明权限边界必须在平台层卡死而不是靠模型自觉。
- **[When Lower Privileges Suffice: Investigating Over-Privileged Tool Selection in LLM Agents](https://arxiv.org/abs/2606.20023)** — 过度特权工具的问题与发现方法，"最小权限"落地的实测依据。
- **["Allow" to Achieve, Over-Privileged Inadvertently: The Unintended Cost of Task-Completion-Driven Pop-up Decisions in Mobile GUI Agents](https://arxiv.org/abs/2608.04755)** — 无意造成的过度授权：审批与默认配置设计缺陷类风险。
- **[The Missing Boundary: How Autonomous Agents Lose Control](https://arxiv.org/abs/2609.11024)** — 自主 Agent 的失控边界分析，适合做架构评审材料。
- **[Loopjacking: Hijacking Human-in-the-Loop Approval](https://arxiv.org/abs/2609.21081)** — 劫持 human-in-the-loop 审批（Loopjacking）——人工在环并不自动安全。

### 1.4 数据外泄与隐私（Data Exfiltration & Privacy，23 条）

- **[API Secrets Should Never Become Tokens in the LLM's Vocabulary: A Threat Analysis of API Credential Handling in LLM Agent Systems and an Empirical Evaluation of a Vault-Mediated Execution Boundary](https://arxiv.org/abs/2609.33371)** — 密钥一旦进入模型的词表就等于泄露，凭据管理要做到"永不进上下文"。
- **[Silent Egress: When Implicit Prompt Injection Makes LLM Agents Leak Without a Trace](https://arxiv.org/abs/2602.22450)** — 隐式注入让 Agent 静默外发数据（Silent Egress），外传检测与 DLP 必读。
- **[ToolPrivacyBench: Benchmarking Purpose-Bound Privacy in Tool-Using LLM Agents](https://arxiv.org/abs/2606.28061)** — 目的限定（purpose-bound）隐私基准，2,150 用例，可直接当验收标准。
- **[Behavioral Skill Reconstruction: Reconstructing Hidden Functionality from LLM Agent Skills](https://arxiv.org/abs/2608.04192)** — 从行为重建隐藏功能：skill 的能力会被反推出来，属于 skill 知识产权与能力泄露面。
- **[SkillWatermark: An Embedded Skill Watermark of Progressive Privacy Inference via Benign Prompts](https://arxiv.org/abs/2608.16026)** — skill 水印与溯源，用于判断 skill 是否被搬运、篡改或套壳。
- **[Codetta: High-Capacity, Keyless, and Undetectable Multi-Agent Collusion](https://arxiv.org/abs/2609.28900)** — 多 Agent 隐蔽信道做高容量外传，说明只盯网络出口不够。
- **[The Innocent Courier: Covert Exfiltration Through Legitimate LLM Web Fetching](https://arxiv.org/abs/2610.01768)** — 借合法工具（可信信使）做隐蔽外传的案例化研究。
- **[You Told Me to Do It: Measuring Instructional Text-induced Private Data Leakage in LLM Agents](https://arxiv.org/abs/2603.11862)** — 度量"指令性文本"诱导的隐私泄露，适合做提示工程侧的合规检查。

### 1.5 间接提示注入（Indirect Prompt Injection，32 条）

- **[IPI-proxy: An Intercepting Proxy for Red-Teaming Web-Browsing AI Agents Against Indirect Prompt Injection](https://arxiv.org/abs/2605.11868)** — 可拦截代理（工具可直接用）：对真实浏览器 Agent 做间接注入红队。
- **[ChatInject: Abusing Chat Templates for Prompt Injection in LLM Agents](https://arxiv.org/abs/2509.22830)** — 滥用 chat template 做注入，与"控制令牌"研究互补，属协议层攻击面。
- **[Adaptive Attacks Break Defenses Against Indirect Prompt Injection Attacks on LLM Agents](https://arxiv.org/abs/2503.00061)** — 自适应攻击能击穿现有 IPI 防御——自测防线时必跑对抗变体。
- **[LoginTrap: Uncovering Task-Agnostic Phishing-Style Indirect Prompt Injection Attacks against LLM-based Web Agents](https://arxiv.org/abs/2608.04741)** — 任务无关的钓鱼式间接注入（LoginTrap），贴近真实社工链路。
- **[Not an A11y: How Android Accessibility Exposes Mobile AI Agents to Indirect Prompt Injection](https://arxiv.org/abs/2608.08939)** — 安卓无障碍（A11y）接口成为移动 Agent 的注入面，移动端 skill 生态必看。
- **[Hijacking Robots with a Piece of Paper: A Systematic Study of Physical Prompt Injection in VLM-Controlled Robots](https://arxiv.org/abs/2608.05715)** — 一张纸就能劫持机器人：把注入载体扩展到物理世界。
- **[Who Is Your Agent Serving? Provider-Side Indirect Prompt Injection in Proactive Agents](https://arxiv.org/abs/2610.05266)** — 提供方侧间接注入：信任边界不止用户输入，还包括服务提供方。
- **[CodeSentinel: A Three-Layer Defense Against Indirect Prompt Injection in Code Contexts](https://arxiv.org/abs/2606.19235)** — 三层间接注入防御的工程化参考（含评测）。
- **[AttriGuard: Defeating Indirect Prompt Injection in LLM Agents via Causal Attribution of Tool Invocations](https://arxiv.org/abs/2603.10749)** — AttriGuard：不改模型的 IPI 防护思路，适合作为落地方案候选。

### 1.6 Agent 欺骗与操纵（Agent Deception & Manipulation，18 条）

- **[Hijacking Agent Memory: Stealthy Trojan Attacks Through Conversational Interaction](https://arxiv.org/abs/2605.29960)** — 劫持 Agent 记忆的隐蔽木马攻击，记忆层是 2026 年最热的攻击面之一。
- **[Your Agent's Memories Are Not Its Own: Forged Reasoning Attacks on LLM Agent Memory and Defenses](https://arxiv.org/abs/2607.05029)** — 伪造推理轨迹（forged reasoning）让 Agent 相信自己做过某事，适合做审计留痕设计参考。
- **[When Agents Remember Too Much: Memory Poisoning Attacks on Large Language Model Agents](https://arxiv.org/abs/2607.06595)** — "记得太多"的记忆投毒攻击与影响面。
- **[MemPoison: Uncovering Persistent Memory Threats and Structural Blind Spots in LLM Agents](https://arxiv.org/abs/2607.14651)** — 持久化记忆威胁与结构化防御（MemPoison），与 OWASP ASI06 Memory Poisoning 对齐。
- **[Salami Attack: Stealthy Collusive Memory Poisoning against OpenClaw](https://arxiv.org/abs/2608.01637)** — 萨拉米式合谋记忆投毒：小步慢投以规避单次检测。
- **[Can Trustless Agents Be Trusted? An Empirical Study of the ERC-8004 Decentralized AI Agent Ecosystem](https://arxiv.org/abs/2606.26028)** — 无信任（trustless）Agent 环境的实证评估，做多 Agent 信任设计可参考。
- **[When Coordination Becomes a Threat: Communication Attacks in LLM-Controlled Multi-Robot Systems](https://arxiv.org/abs/2608.06830)** — Agent 间通信攻击（协调即威胁），多 Agent 编排必看。
- **[Whose Side Is Your Agent On? Multi-Party Principal Loyalty in LLM Agents](https://arxiv.org/abs/2606.30383)** — 多方委派下的"忠诚度"问题：Agent 到底在替谁办事——治理与责任归属的关键议题。

### 1.7 复合系统攻击（Compound System Attacks，4 条）

- **[Self-State Attacks on Self-Hosted AI Agents: How Far Can OS Defenses Go?](https://arxiv.org/abs/2607.17986)** — 自托管 Agent 的"自状态攻击"：OS 层面能走多远，说明宿主加固是底线。
- **[Agent Harness Distillation: Inference-Time Harness Extraction and Exploitation in Autonomous Multi-Agent Systems](https://arxiv.org/abs/2607.28147)** — Agent harness 蒸馏：推理时被提取 harness（含安全机制的绕过），平台方需关注。
- **[Compositional Threat Analysis of Latent Compromise in LLM Agent Systems: The Order 66 Scenario](https://arxiv.org/abs/2608.08131)** — 潜在失陷（latent compromise）的组合威胁分析，适合作为长周期风险建模材料。
- **[Cascade: Composing Software-Hardware Attack Gadgets for Adversarial Threat Amplification in Compound AI Systems](https://arxiv.org/abs/2603.12023)** — 软硬件组合攻击 gadget（Cascade），提示攻击面可跨层叠加。

### 1.8 跨插件/跨技能攻击（Cross-Plugin Attacks，4 条）

- **[Shadow API: Covert Data Exfiltration via LLM-Mediated API Interactions](https://arxiv.org/abs/2603.01919)** — 通过 LLM 中介的 API 调用做隐蔽外传（Shadow API）。
- **[AgentSkillOS: Towards Secure and Composable Agent Skill Operating Systems](https://arxiv.org/abs/2603.02176)** — AgentSkillOS：面向安全与可组合的 agent skill 运营体系，做 skill 平台架构时值得对照。
- **[Benign in Isolation, Harmful in Composition: Security Risks in Agent Skill Ecosystems](https://arxiv.org/abs/2606.15242)** — "单独无害、组合有害"的风险实证，是组合治理的核心论据。
- **[MOSAIC: Knowledge-Guided CLI Command Composition Attack in LLM Coding Agents](https://arxiv.org/abs/2607.02857)** — 知识驱动的 CLI 命令组合攻击：工具链组合本身就能构成攻击路径。

### 1.9 Agent 后门（Backdoor Attacks on Agents，3 条）

- **[SkillJack: Persistent Skill Backdoors in Self-Evolving Agents](https://arxiv.org/abs/2608.03509)** — SkillJack：自演进 Agent 生态中的持久 skill 后门，skill 供应链后门的代表工作。
- **[Understanding and Enhancing Backdoor Persistency in LLM Agent Post-Training](https://arxiv.org/abs/2610.07510)** — 如何增强 Agent 后门的持久性（防御侧据此设计检测与清除）。
- **[SlowBA: An efficiency backdoor attack towards VLM-based GUI agents](https://arxiv.org/abs/2603.08316)** — 面向 VLM GUI Agent 的效率后门，说明"性能优化"也能被武器化。

### 1.10 越狱与护栏绕过（Jailbreaking & Guardrail Bypass，12 条）

- **[Claudini: Autoresearch Discovers State-of-the-Art Adversarial Attack Algorithms for LLMs](https://arxiv.org/abs/2603.24511)** — Claudini：自动研究发现 SOTA 对抗性越狱串，是自动化越狱研究的前沿参考。
- **[Jailbreaking ChatGPT via Prompt Engineering](https://arxiv.org/abs/2305.13860)** — 提示工程越狱的经典综述性起点，适合做团队科普与基线测试。
- **[MasterKey: Automated Jailbreaking of Large Language Model Chatbots](https://arxiv.org/abs/2307.08715)** — MasterKey：自动化越狱 LLM 聊天机器人（含防御绕过方法论）。
- **[One Word Opens the Gate: The Option-Channel Attack on Typed Decision Models as Agent Guardrails](https://arxiv.org/abs/2610.12292)** — 单选通道攻击：一个词就能打开类型化输出 Agent 的闸门。
- **[PentestGPT: An LLM-empowered Automatic Penetration Testing Tool](https://arxiv.org/abs/2308.06782)** — PentestGPT：把 LLM 用于自动化渗透测试，是"Agent 作为攻击工具"的代表条目。
- **[From Shield to Target: Denial-of-Service Attacks on LLM-Based Agent Guardrails](https://arxiv.org/abs/2606.14517)** — 把防护机制本身当目标做拒绝服务（Shield to Target），防御侧需要韧性设计。

## 二、防御（Defense Research）

> 上游该章共 247 条，分 5 个方向（权限与访问控制 / 运行时监控与沙箱 / 输入输出校验 / 形式化验证与分析 / 评估与红队）。防御类条目最直接可用于选型与自建，下面按方向给出代表条目。

### 2.1 权限与访问控制（Permission & Access Control，66 条）

- **[Zero-Trust Authorization and Discovery for Enterprise MCP](https://arxiv.org/abs/2609.22573)** — 企业 MCP 的零信任授权与发现：MCP 落地必读的授权模型。
- **[PAuth: Precise Task-Scoped Authorization For Agents](https://arxiv.org/abs/2603.17170)** — PAuth：精确的任务范围授权（task-scoped），是"按任务发权"的代表方案。
- **[ToolFence: Fine-Grained Authorization for Secure Tool-Using LLM Agents](https://arxiv.org/abs/2609.37196)** — ToolFence：工具使用的细粒度授权。
- **[ActionGuard: Tool Call Authorization under Poisoned Skills](https://arxiv.org/abs/2609.39450)** — ActionGuard：即使 skill 被投毒，工具调用仍在授权闸门内。
- **[CmdNeedle: Measuring the Incompleteness of Command Denylists for AI Agents](https://arxiv.org/abs/2606.15549)** — 命令黑名单为何不够（CmdNeedle 度量），说明必须做语义/策略级管控。
- **[Context-to-Execution Integrity for LLM Agents](https://arxiv.org/abs/2607.06000)** — 上下文到执行的完整性（context-to-execution integrity）框架。
- **[ToolGuardian: Declarative Security for AI Agent-Tool Interactions](https://arxiv.org/abs/2607.21835)** — ToolGuardian：Agent-工具交互的声明式安全策略。
- **[Scan the Skill, Govern the Action: Composing Registry Verdicts with Runtime Consequence Control](https://arxiv.org/abs/2609.12001)** — "扫描 skill、治理动作"：把注册表核验与运行时治理组合，skill 准入的端到端思路。
- **[Progressive Skill Discovery as Access Control for Tool-Using LLM Agents: Structural Governance through Role-Scoped Capability Delivery](https://arxiv.org/abs/2609.28693)** — 把渐进式 skill 发现当作访问控制，适合平台侧设计。
- **[Authorization Revocation for Long-Running AI Agents: Root-Scoped Quiescence under Delegation and Asynchronous Execution](https://arxiv.org/abs/2609.21284)** — 长时运行 Agent 的授权撤销机制（root-of-trust 思路）。

### 2.4 形式化验证与分析（Formal Verification & Analysis，13 条）

- **[Efficient and Sound Probabilistic Verification for AI Agents](https://arxiv.org/abs/2606.20510)** — 对 Agent 的高效可靠概率验证方法，形式化路线入门。
- **[Local LLM Agents as Vulnerable Runtimes: A Source-Code Audit of the Agent Runtime Layer](https://arxiv.org/abs/2606.21071)** — 把本地 LLM Agent 当"易受攻击的运行时"做源码审计，适合自托管场景。
- **[AgentFlow: Building Agent Dependency Graphs for Static Analysis of Agent Programs](https://arxiv.org/abs/2607.01640)** — AgentFlow：构建 Agent 依赖图做静态分析，工具链可直接借鉴。
- **[SkillsMetric: Mapping the Detection Boundary of Static Analysis for Malicious Agent Skills](https://arxiv.org/abs/2608.08468)** — SkillsMetric：静态分析对恶意 skill 的检测边界在哪里（决定静态扫描够不够）。
- **[SkillConsist: Detecting Inconsistencies in Agent Skills via Bidirectional Graph Alignment](https://arxiv.org/abs/2608.07639)** — SkillConsist：检测 skill 之间的不一致性（供应链一致性检查）。
- **[Formal Analysis and Supply Chain Security for Agentic AI Skills](https://arxiv.org/abs/2603.00195)** — Agentic AI 系统的形式化分析与供应链安全结合。
- **[NOMOS: Compiling Written Policies into Statically Verified Tool-Call Gates for LLM Agents](https://arxiv.org/abs/2610.11030)** — NOMOS：把书面策略编译成静态验证的约束，治理落地的可行路径。

### 2.2 运行时监控与沙箱（Runtime Monitoring & Sandboxing，74 条）

- **[AI Sandboxes: A Threat Model, Taxonomy, and Measurement Framework](https://arxiv.org/abs/2606.18532)** — Agent 沙箱的威胁模型、分类与度量框架，做隔离方案选型先看这个。
- **[ContractWarden: Kernel-Enforced Damage Boundaries for AI Agents via Human-Authorized Contracts](https://arxiv.org/abs/2609.38248)** — ContractWarden：内核级强制的"损害边界"，把兜底放在 OS 而不是模型。
- **[Tracekit: Tamper-Evident Intent-Reasoning-Action Auditing for Autonomous Coding Agents](https://arxiv.org/abs/2609.35659)** — Tracekit：防篡改的"意图-推理-动作"审计轨迹，满足取证与合规。
- **[SKILLLITE: Evidence-Guided Malicious Skill Auditing with Compact LLMs](https://arxiv.org/abs/2609.36879)** — SKILLLITE：证据引导的恶意 skill 审计（低成本筛查）。
- **[Behavioral Integrity Verification for AI Agent Skills](https://arxiv.org/abs/2605.11770)** — skill 的行为完整性校验（behavioral integrity），准入后还要持续验。
- **[Detecting Malicious Agent Skills in the Wild using Attention](https://arxiv.org/abs/2606.23416)** — 在野恶意 skill 检测（注意力机制路线），贴近真实 skill 生态。
- **[SkillGate: Cost Efficient Runtime Malicious Skill File Detection in Coding Agents](https://arxiv.org/abs/2607.25619)** — SkillGate：成本高效的运行时恶意 skill 文件检测。
- **[FlowGuard: From Signals to Evidence for MCP Security Detection](https://arxiv.org/abs/2607.14754)** — FlowGuard：MCP 安全检测从信号到证据的流水线。
- **[SafeFlow: Semantic Information-Flow Control for Blocking Malicious Propagation in Multi-Agent Systems](https://arxiv.org/abs/2607.25255)** — SafeFlow：语义信息流控制，阻断工具链上的恶意流。
- **[OpenClaw PRISM: A Zero-Fork, Defense-in-Depth Runtime Security Layer for Tool-Augmented LLM Agents](https://arxiv.org/abs/2603.11853)** — OpenClaw PRISM：零分叉的纵深防御运行时安全方案。

### 2.3 输入输出校验（Input/Output Validation，34 条）

- **[StruQ: Defending Against Prompt Injection with Structured Queries](https://arxiv.org/abs/2402.06363)** — StruQ：结构化查询/数据分离防注入，输入侧经典防御方案。
- **[AgentVisor: Defending LLM Agents Against Prompt Injection via Semantic Virtualization](https://arxiv.org/abs/2604.24118)** — AgentVisor：面向 Agent 的注入防御（可直接对照实现）。
- **[Mitigating Taint-Style Vulnerabilities in MCP Servers via Security-Aware Tool Descriptions](https://arxiv.org/abs/2607.07461)** — MCP Server 的污点型漏洞缓解，MCP 实现方必看。
- **[Tool Specifications Matter: Uncovering and Mitigating Safety Risks in AI Agents](https://arxiv.org/abs/2607.29254)** — 工具规格（tool spec）本身会引入安全问题，说明工具描述也是输入面。
- **[Cross-Layer Misalignment Detection in Agent Skills: A Progressive Loading-Aware Contrastive Learning Approach](https://arxiv.org/abs/2607.10534)** — skill 的跨层不一致检测，作为准入流水线的一道闸。
- **[The Verifiable Action Card: Trustworthy Human-in-the-Loop Control for Secure Autonomous Agents](https://arxiv.org/abs/2609.18411)** — 可验证动作卡（Verifiable Action Card）：让人机审批有据可依。
- **[Prompt Injection Detection for Email Agents Through Attack Chain Modeling](https://arxiv.org/abs/2609.30657)** — 面向邮件 Agent 的注入检测（用攻击数据训练检测器）。
- **[LTBD: Learnable Trust-Boundary Delimiters for Prompt Injection Defense](https://arxiv.org/abs/2610.11634)** — LTBD：可学习的信任边界分隔符，做提示层隔离的工程方案。
- **[SingGuard-NSFA: Extensible Guardrails for Agentic AI via Generative Reasoning and Real-Time Classification](https://arxiv.org/abs/2607.13081)** — SingGuard-NSFA：可扩展的 Agent 护栏（生成式/规则混合）。
- **[Multi-Agent Firewall Architecture for Privacy Protection of Sensitive Data in Interactions with Language Models](https://arxiv.org/abs/2607.08282)** — 多 Agent 架构的隐私保护防火墙。

### 2.5 评估与红队（Evaluation & Red Teaming，60 条）

- **[Agent Security Bench (ASB)](https://arxiv.org/abs/2410.02644)** — Agent Security Bench（ASB）：覆盖 10 个 Agent / 398 环境的综合安全基准，评估起点。
- **[SkillVetBench: LLM-as-Judge for Multi-Dimensional Security Risk Evaluation in Open-Source LLM Agent Skills](https://arxiv.org/abs/2606.15899)** — SkillVetBench：用 LLM-as-Judge 对开源 agent skill 做多维安全评估。
- **[SkillSafetyBench: Evaluating Agent Safety under Skill-Facing Attack Surfaces](https://arxiv.org/abs/2605.12015)** — SkillSafetyBench：skill 参与下的 Agent 安全评测（155 用例 / 47 任务）。
- **[Proteus: A Self-Evolving Red Team for Agent Skill Ecosystems](https://arxiv.org/abs/2605.11891)** — Proteus：自演进的 skill 生态红队（持续对抗而非一次性测试）。
- **[SkillSecurer: Detecting and Patching Prompt-Injection Vulnerabilities in AI Agent Skills](https://arxiv.org/abs/2609.14079)** — SkillSecurer：检测并修补 prompt 注入型 skill 漏洞。
- **[SkillSentry: Adaptive Honey Worlds for Dynamic Safety Testing of Agent Skills](https://arxiv.org/abs/2608.03485)** — SkillSentry：自适应蜜罐世界做动态安全测试。
- **[AutoDojo: Adaptive Attacks Expose Superficial Defenses and User-Underspecification Limits in LLM Agents](https://arxiv.org/abs/2606.15057)** — AutoDojo：自适应攻击揭示"表面防御"，评估必须跑自适应变体。
- **[Red-Teaming the Agentic Red-Team](https://arxiv.org/abs/2606.24496)** — "对红队做红队"（Red-Teaming the Agentic Red-Team），评估自身攻击能力的可靠性。
- **[Adaptive Adversaries: A Multi-Turn, Multi-LLM Benchmark for LLM Agent Security](https://arxiv.org/abs/2607.18063)** — 自适应对手：多轮、多 LLM 的红队基准，贴近真实持续对抗。
- **[Beyond Attack-Success Rate: Action-Graded Severity Scale for Tool-Using AI Agents](https://arxiv.org/abs/2607.07474)** — 不止看攻击成功率（ASR）：带动作分级的严重度标尺，汇报口径改进。
- **[Instrumental Monitor Evasion Emerges Under Ordinary Task Pressure](https://arxiv.org/abs/2609.30217)** — 监控规避会在普通任务压力下自发出现——运行时监控的有效性边界证据。

## 三、框架与标准（Frameworks & Standards）

> 这一层回答

### 3.1 威胁框架与标准（Threat Frameworks & Standards，11 条）

- **[OWASP Agentic Skills Top 10 (AST10)](https://owasp.org/www-project-agentic-skills-top-10/)** — 本项目最相关的标准：OWASP Agentic Skills Top 10（AST10），首次把风险枚举到 skill 层（AST01 恶意 skill 到 AST10 跨平台复用，前两条为 critical）。做 skill 准入评分时直接按它建矩阵。
- **[OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)** — OWASP ASI 的 Agentic AI 威胁与缓解措施：面向 agent 整体的威胁模型参考，与 AST10 互补（一个管 agent，一个管 skill）。
- **[OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)** — OWASP LLM Top 10：LLM01 提示注入、LLM06 过度自主、LLM07 不安全插件设计、LLM08 过度自主权——旧版基线仍要对照。
- **[MITRE ATLAS™](https://atlas.mitre.org/)** — MITRE ATLAS：AI 系统的对抗战术与技术库，把发现映射到编号便于汇报。
- **[NIST AI Risk Management Framework](https://www.nist.gov/artificial-intelligence/ai-risk-management-framework)** — NIST AI RMF：AI 风险管理框架，治理/合规侧的通用语言。
- **[NIST SP 800-218A: Secure Software Development for AI](https://csrc.nist.gov/pubs/sp/800/218/a/final)** — NIST SP 800-218A：面向 AI 的安全软件开发实践，把供应链安全要求落到流程。
- **[EU AI Act](https://artificialintelligenceact.eu/)** — EU AI Act：法规要求，涉及合规评估与落地时间表。
- **[Anthropic Responsible Scaling Policy](https://www.anthropic.com/index/anthropics-responsible-scaling-policy)** — Anthropic Responsible Scaling Policy：前沿模型厂商的负责任扩展政策参考。
- **[IETF draft-klrc-aiagent-auth-01: AI Agent Authentication and Authorization](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/)** — IETF 草案：AI Agent 的身份认证与授权（agent 之间怎么互相证明身份）。
- **[IETF draft-niyikiza-oauth-attenuating-agent-tokens-00: Attenuating Authorization Tokens for Agentic Delegation Chains](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/)** — IETF 草案：OAuth 令牌衰减（attenuating authorization），把"过程性授权逐步收窄"标准化，长任务 Agent 的授权设计必读。
- **[Certifying Ghosts: How Cybersecurity AI Agents Break the EU Cyber Resilience Act](https://arxiv.org/abs/2607.07109)** — 对"网络安全 AI Agent"做认证的讨论：把 AI Agent 纳入欧盟网络韧性法案（CRA）合规语境。

### 3.2 Agent Skill 与工具规范（Agent Skill Specifications，7 条）

- **[AgentSkills.io](https://agentskills.io/specification)** — AgentSkills.io 规范：agent skill 的定义与安全要求，写/审 skill 包的直接依据。（Open Standard：Agent skill definition and security requirements）
- **[Model Context Protocol (MCP)](https://modelcontextprotocol.io/)** — Model Context Protocol（MCP）：工具/资源集成协议，skill 生态最主要的连接层，安全设计从这里看起。（Anthropic：Tool/resource integration protocol for LLMs）
- **[OpenAI Function Calling](https://platform.openai.com/docs/guides/function-calling)** — OpenAI Function Calling：GPT 系工具调用规范。（OpenAI：Tool use specification for GPT models）
- **[Tool Use (Claude)](https://docs.anthropic.com/en/docs/build-with-claude/tool-use)** — Claude 工具使用（Tool Use）：Claude 原生工具接口规范。（Anthropic：Claude's native tool use interface）
- **[LangChain Tools](https://python.langchain.com/docs/modules/agents/tools/)** — LangChain Tools：常见 Agent 框架的工具抽象。（LangChain：Tool abstraction for agent frameworks）
- **[AutoGPT Plugins](https://github.com/Significant-Gravitas/AutoGPT)** — AutoGPT 插件体系：自主 Agent 插件的早期形态，可作历史对照。（AutoGPT：Plugin system for autonomous agents）
- **[OpenAPI/Swagger](https://swagger.io/specification/)** — OpenAPI/Swagger：最常见的"工具定义"载体，工具描述里的安全问题往往从它进来。（Linux Foundation：API specification commonly used as tool definitions）

### 3.3 工具与框架（Tools & Frameworks，54 个，以下为代表性 39 个）

- **[SkillGuard](https://github.com/LLMSecurity/skillguard)** — SkillGuard：LLM 原生的 agent skill 安全审计器（对齐 OWASP Agentic + MITRE ATLAS），skill 准入首选。
- **[SkillCI](https://github.com/kabirnarang39/skillci)** — SkillCI：把 OWASP AST10 映射成静态安全 lint + 回归测试，接进 CI 最省事。
- **[SkillPreflight](https://github.com/agent-contracts/skill-preflight)** — SkillPreflight：本地/GitHub skill 的只读预安装扫描，0-100 分（安全性、权限、工具面）。
- **[repo-agent-scan](https://github.com/sunxiayi/repo-agent-instruction-security-scan)** — repo-agent-scan：对 SKILL.md / AGENTS.md 等指令文件做确定性扫描。
- **[SkillTotal](https://github.com/pezhik/skilltotal)** — SkillTotal：离线扫描 MCP server、agent skill、npm/PyPI 包与仓库的供应链风险。
- **[SkilLock](https://github.com/skills-lock/skil-lock)** — SkilLock：行为锁文件 + 能力变更 PR 审查（SARIF 输出），防 skill 被悄悄改。
- **[SkillGate](https://github.com/selfradiance/skillgate)** — SkillGate：Skill 包在进入 harness 之前的确定性本地静态审查。
- **[Agent Audit](https://arxiv.org/abs/2603.22853)** — Agent Audit：对 LLM Agent 应用做数据流分析、凭据检测、MCP 配置解析与权限风险检查。
- **[mcp-sec-audit](https://arxiv.org/abs/2603.21641)** — mcp-sec-audit：MCP server 安全工具（静态匹配 + Docker/eBPF 动态沙箱模糊测试）。
- **[Agent Scan](https://github.com/snyk/agent-scan)** — Agent Scan（Snyk）：本地 agent 供应链扫描，覆盖 MCP server 与 skill 的注入/投毒/有毒流。
- **[AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard)** — AI-Infra-Guard（腾讯朱雀）：LLM 驱动的 skill-scan / mcp-scan / agent-scan 红队平台。
- **[DScan](https://github.com/DeepScan-Security/dscan)** — DScan：运行期工具调用追踪、注入屏蔽、MCP 审计与对抗测试的成套工具。
- **[Skill-audit](https://github.com/AgentPostmortem/Skill-audit)** — Skill-audit：静态扫 Claude/agent skill，标记注入、危险 shell、密钥访问与外传。
- **[AgentWarden](https://github.com/juangh123/AgentWarden)** — AgentWarden：MCP 配置与 skill 的静态安全闸门，含 SHA-256 完整性锁定与 Ed25519 发布者校验。
- **[agent-audit-kit](https://github.com/sattyamjjain/agent-audit-kit)** — agent-audit-kit：离线扫描 MCP/agent 配置，输出 SARIF + GitHub Action + 公开台账。
- **[Assay Harness](https://github.com/Rul1an/Assay-Harness)** — Assay Harness：CI 闸门，把 Agent"声称的副作用"与独立观测到的运行时行为比对。
- **[agent-diff-guard](https://github.com/cubxxw/agent-diff-guard)** — agent-diff-guard：推送前拦截高风险 diff（CI/CD 改动、依赖变更、删测试等）。
- **[Pipelock](https://github.com/luckyPipewrench/pipelock)** — Pipelock：Agent 防火墙 + MCP 感知的出网代理（DLP、注入扫描、进程沙箱）。
- **[NemoClaw](https://github.com/NVIDIA/NemoClaw)** — NemoClaw（NVIDIA）：常驻 Agent 的安全沙箱参考栈（网络策略、加固、路由推理）。
- **[CubeSandbox](https://github.com/TencentCloud/CubeSandbox)** — CubeSandbox（腾讯云）：硬件隔离的亚 60ms 沙箱 + 沙箱外凭据保管，代码执行隔离方案。
- **[agent-sentinel](https://github.com/junlinwk/agent-sentinel)** — agent-sentinel：eBPF/BPF-LSM 原型，监控本地 Agent 行为并原子阻断注入驱动的敏感访问。
- **[HOL Guard](https://github.com/hashgraph-online/hol-guard)** — HOL Guard：本地优先的运行时防火墙，拦截 shell、密钥读取、MCP 配置变更与包安装。
- **[Agent Memory Guard](https://github.com/OWASP/www-project-agent-memory-guard)** — Agent Memory Guard（OWASP）：ASI06（记忆投毒）的参考实现，运行时筛检进入 Agent 记忆的内容。
- **[Clawvisor](https://github.com/clawvisor/clawvisor)** — Clawvisor：Agent 网关——按目的授权、凭据保管、审计日志（人批后才放行）。
- **[Clay Seal](https://github.com/clayseal/clayseal-identity)** — Clay Seal：带证明的运行期身份 + Biscuit 能力令牌（GCP/K8s/AWS 节点证明、SPIFFE）。
- **[SkillWatch](https://github.com/kuzivaai/SkillWatch)** — SkillWatch：周期性复查 skill/MCP 引用的外部 URL 内容变化（防"复审后改内容"）。
- **[whatileaked](https://github.com/selan-ai/whatileaked)** — whatileaked：扫描编码 Agent 已经写到磁盘的凭据（Claude Code / Codex / Cursor 记录）。
- **[Humanbound](https://github.com/humanbound/humanbound)** — Humanbound：对抗测试引擎（在线端点、多轮、工具滥用测试）。
- **[pikit](https://github.com/Tencent/AI-Infra-Guard/tree/main/Research/pikit)** — pikit：可组合的间接注入研究工具包（13 种攻击、16 个通道）。
- **[Ziran](https://github.com/taoq-ai/ziran)** — Ziran：把工具建模成图来发现危险工具链与执行级副作用。
- **[Vestige](https://github.com/samvallad33/vestige)** — Vestige：基于 hook 的本地安全与记忆层，用确定性规则阻断破坏性 shell。
- **[mcp-sploit](https://github.com/Prasanna-27eng/mcp-sploit)** — mcp-sploit：Metasploit 风格的 MCP 授权安全测试框架（枚举 + 利用验证）。
- **[LLM Guard](https://github.com/protectai/llm-guard)** — LLM Guard：LLM 应用的输入/输出扫描。
- **[NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails)** — NeMo Guardrails（NVIDIA）：给 LLM 应用加护栏的通用工具包。
- **[Promptfoo](https://github.com/promptfoo/promptfoo)** — Promptfoo：LLM 红队与评测框架（做自动化测试流水线）。
- **[Garak](https://github.com/leondz/garak)** — Garak：LLM 漏洞扫描器（把 LLM 当被扫目标）。
- **[IPI-Proxy](https://github.com/VulcanLab/IPI-Proxy)** — IPI-Proxy：针对网页浏览型 Agent 的间接注入红队拦截代理。
- **[Sunglasses](https://github.com/sunglasses-dev/sunglasses)** — Sunglasses：skill 与工具使用的运行时信任扫描（100+ 攻击类别模式库）。
- **[Nobulex](https://github.com/arian-gogani/nobulex)** — Nobulex：Agent 信任评分层（执行前/后双签 Ed25519 收据 + 内容寻址）。

### 3.4 综述与系统化研究（Surveys & Systematizations，52 条）

- **[Agent Skill Security: Threat Models, Attacks, Defenses, and Evaluation](https://arxiv.org/abs/2607.13987)** — 《Agent Skill Security》综述：直接对着本技能包主题写威胁模型、攻击、防御与评测，做文献综述的第一篇。
- **[SoK: The Attack Surface of Agentic AI — Tools, and Autonomy](https://arxiv.org/abs/2603.22928)** — SoK：Agentic AI 的攻击面（工具与自主性）——把"工具层"独立成攻击面的系统化梳理。
- **[The Attack and Defense Landscape of Agentic AI: A Comprehensive Survey](https://arxiv.org/abs/2603.11088)** — Agentic AI 攻击与防御全景综述，适合当路线图。
- **[Connecting the Dots in Agentic AI Security: A Cross-Dimensional Threat Taxonomy, Evaluation Maturity, and Open Challenges](https://arxiv.org/abs/2609.23894)** — 跨维度连接 Agentic AI 安全的综述，用于建立完整知识框架。
- **[Authorization Architectures for Tool-Using AI Agents](https://arxiv.org/abs/2609.15906)** — 工具使用型 AI Agent 的授权架构综述：做权限设计时的方案对照表。
- **[MCP-in-SoS: Risk Assessment Framework for Open-Source MCP Servers](https://arxiv.org/abs/2603.10194)** — 开源 MCP server 的风险评估框架（MCP-in-SoS），MCP 资产盘点参考。
- **[An Empirical Study of Model Context Protocol Applications](https://arxiv.org/abs/2607.25635)** — MCP 应用的实证研究：真实生态里 MCP 的用法与问题。
- **[After the Party: Governing What a Viral Agent-Skill Ecosystem Left Behind](https://arxiv.org/abs/2609.17274)** — "派对之后"：病毒式 skill 生态爆发后的治理问题（skill 生态治理必读）。
- **[The Chronos Vulnerability: A Taxonomy of Temporal Persistence and Memory-Based Deception in Agentic AI](https://arxiv.org/abs/2607.19433)** — 时间持久化漏洞的分类学（含记忆/持久状态），长时 Agent 风险建模。
- **[Prompt Injection Attacks and Defenses in LLM-Integrated Applications](https://arxiv.org/abs/2310.12815)** — LLM 集成应用的提示注入攻防综述：注入方向的经典综述。

## 四、基准测试与数据集（Benchmarks & Datasets，48 个）

> 用于
- **[InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent)** — InjecAgent：间接提示注入的经典基准（1,054 用例、17 工具），skill 安全验收必跑。（规模/重点：Indirect prompt injection；1,054 test cases）
- **[ASB](https://github.com/agiresearch/ASB)** — ASB（Agent Security Bench）：10 个 Agent、398 个环境的综合 Agent 安全评测。（规模/重点：Comprehensive agent security；10 agents, 398 envs）
- **[SkillSafetyBench](https://arxiv.org/abs/2605.12015)** — SkillSafetyBench：skill 参与下的 Agent 安全（155 用例 / 47 任务），贴合 skill 生态。（规模/重点：Skill-mediated agent safety；155 cases, 47 tasks）
- **[SkillVetBench](https://arxiv.org/abs/2606.15899)** — SkillVetBench：开源 agent skill 的安全风险评估（带实时排行榜），选 skill 前可先查分。（规模/重点：Security risk eval of open-source agent skills；Live leaderboard）
- **[SCR-Bench](https://arxiv.org/abs/2606.15242)** — SCR-Bench：skill 组合风险（多 skill 链式场景），组合攻击的评测入口。（规模/重点：Skill composition risk；Multi-skill chains）
- **[SkillAtlas](https://arxiv.org/abs/2609.13353)** — SkillAtlas：面向 agent skill 的攻击轨迹库（3,014 用例 / 6,589 轨迹），做检测与复核的语料。（规模/重点：Attack trace library for agent skills；3,014 cases, 6,589 traces）
- **[OpenSkillRisk](https://arxiv.org/abs/2607.20121)** — OpenSkillRisk：使用真实第三方风险 skill 时的 Agent 安全性（263 个 skill / 7 类）。（规模/重点：Agent safety with risky third-party skills；263 skills, 7 categories）
- **[Skill-Inject](https://www.skill-inject.com/)** — Skill-Inject：skill 文件攻击的多场景评测，skill 面攻击的标准靶场。（规模/重点：Skill file attacks；Multi-scenario）
- **[SkillGuard Dataset](https://github.com/LLMSecurity/skillguard)** — SkillGuard Dataset：恶意 skill 检测数据集（157 个恶意 skill），检测器训练/评测可用。（规模/重点：Malicious skill detection；157 malicious skills）
- **[HarnessSecurity-Bench](https://tsingpig.github.io/HarnessSecurity-Benchmark/)** — HarnessSecurity-Bench：评测编码 Agent harness 的安全机制到底防不防得住（覆盖 Claude Code、Codex CLI、Gemini CLI、Copilot）。（规模/重点：Whether coding-agent harness security mechanisms actually protect against attacks (6 harnesses incl. Claude Code, Codex CLI, Gemini CLI, Copilot)；23 tasks, 5 attack surfaces, 9 mechanisms）
- **[mcp-defense-bench](https://github.com/Gowthaman90/mcp-defense-bench)** — mcp-defense-bench：MCP 防御代理的攻击面覆盖（24 向量 / 35 用例）。（规模/重点：MCP defensive-proxy attack-surface coverage；24 vectors, 35 cases）
- **[Orca AI Incident Archive](https://github.com/Continuum-AI-Corp/Orca-AI-Incident-Archive)** — Orca AI Incident Archive：真实 Agent 安全事故档案（380+ 条，标注"确认受害 vs 研究演示"），写威胁材料的一手素材。（规模/重点：Real-world agent security incidents (MCP, tool/skill supply chain, indirect prompt injection, rogue tool actions), each flagged confirmed victim vs. research demo；380+ records, each with a primary source）
- **[StepJack](https://github.com/BorealisAI/StepJack)** — StepJack：针对computer-use 型 Agent 的多步间接注入（480 用例）。（规模/重点：Multi-step indirect prompt injection vs. computer-use agents；480 test cases）
- **[IssueTrojanBench](https://arxiv.org/abs/2607.20759)** — IssueTrojanBench：恶意 issue 请求对抗编码 Agent（4 类攻击 / 6 个向量）。（规模/重点：Malicious issue requests vs. coding agents；4 attack categories, 6 vectors）
- **[EvasionBench](https://arxiv.org/abs/2609.30217)** — EvasionBench：普通任务压力下的运行时监控规避，验证监控有效性时必跑。（规模/重点：Instrumental runtime-monitor evasion under ordinary task pressure；50 task-policy pairs）
- **[HTB (Hallucinated-Tools Benchmark)](https://arxiv.org/abs/2609.19425)** — HTB：工具幻觉基准（含跨 MCP server 命名空间冲突）。（规模/重点：Tool hallucination (fabricated tools/args) incl. cross-server MCP namespace collisions；322 single-registry + 154 MCP hallucinations, H1–H5 / M1–M5 taxonomy）
- **[MemSecBench](https://arxiv.org/abs/2607.27080)** — MemSecBench：Agent 记忆投毒的全生命周期安全评测（310 用例）。（规模/重点：Lifecycle security of agent memory poisoning；310 cases, 24-config matrix）
- **[DecepEval](https://arxiv.org/abs/2610.07967)** — DecepEval：LLM Agent 的条件性欺骗评测（压力/激励/机会/冲突四条件配对）。（规模/重点：Condition-dependent deception in LLM agents (pressure, incentive, opportunity, conflict) with paired neutral/induced instances；1,532 instances, 3 task families, 28 scenarios）
- **[IH-Benchmark](https://arxiv.org/abs/2607.25987)** — IH-Benchmark：指令层级鲁棒性（含工具中介冲突，44 约束族 / 37 模型）。（规模/重点：Instruction-hierarchy robustness incl. tool-mediated conflicts；44 constraint families, 37 models）
- **[WIPI](https://arxiv.org/abs/2402.16965)** — WIPI：网页型间接注入的早期用例集。（规模/重点：Web-based indirect injection；Multi-scenario）
- **[R-Judge](https://github.com/Lordog/R-Judge)** — R-Judge：Agent 安全风险意识评测（162 条 / 27 场景）。（规模/重点：Safety risk awareness；162 records, 27 scenarios）
- **[AgentHarm](https://arxiv.org/abs/2410.09024)** — AgentHarm：Agent 误用的行为级评测（110 行为 / 440 变体）。（规模/重点：Agent misuse；110 behaviors, 440 variants）

### 4.1 补充：行业报告与实战案例（Industry Reports & Blog Posts，22 条）

- **[Snowflake Cortex AI Escapes Sandbox and Executes Malware](https://www.promptarmor.com/resources/snowflake-ai-escapes-sandbox-and-executes-malware)** — 沙箱逃逸并执行恶意代码的真实案例（Snowflake Cortex），说明"AI 功能里的代码执行"是真风险。
- **[Confused Deputy Attacks on Autonomous AI Agents](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-confused-deputy-prompt-injection/)** — 混淆代理人（Confused Deputy）攻击自主 AI Agent：授权被借用是最常见的失陷路径。
- **[Compromising Agents via MCP](https://invariantlabs.ai/blog/mcp-security)** — 通过 MCP 攻陷 Agent 的公开研究：工具层投毒的实战化解读。
- **[Simon Willison: Prompt Injection Explained](https://simonwillison.net/2023/Apr/14/worst-that-can-happen/)** — Simon Willison 的提示注入科普：给团队讲"为什么注入不能靠提示词解决"的首选材料。
- **[The sorry state of skill distribution](https://blog.trailofbits.com/2026/06/03/the-sorry-state-of-skill-distribution/)** — "skill 分发的糟糕现状"：skill 生态当下的真实治理缺口。
- **[LiteLLM Hack: Were You One of the 47,000?](https://futuresearch.ai/blog/litellm-hack-were-you-one-of-the-47000/)** — LiteLLM 被入侵事件（影响面 47,000 量级）：AI 基础设施供应链的教科书案例。
- **[Lack of Isolation in Agentic Browsers Resurfaces Old Vulnerabilities](https://blog.trailofbits.com/2026/01/13/lack-of-isolation-in-agentic-browsers-resurfaces-old-vulnerabilities/)** — Agentic 浏览器缺乏隔离导致老漏洞复活：浏览器型 Agent 的必读风险。
- **[Is sandboxing sufficient to contain rogue agents?](https://blog.cryptographyengineering.com/2026/09/30/is-sandboxing-sufficient-to-contain-rogue-agents/)** — "沙箱足以关住失控 Agent 吗？"——直接讨论隔离的边界与不足。
- **[ClawHub by the Numbers: Metadata on All 52,652 Packages](https://trent.ai/blog/clawhub-by-the-numbers/)** — ClawHub 全量包元数据分析（52,652 个包）：skill/插件生态的规模与质量画像。
- **[Caught in the Hook: RCE and API Token Exfiltration Through Claude Code Project Files](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)** — 通过 Claude Code 项目文件实现 RCE 与 API Token 窃取：编码 Agent 项目级攻击面。

### 4.2 相关资源清单（Related Awesome Lists，6 条）

- **[awesome-llm-security](https://github.com/corca-ai/awesome-llm-security)** — awesome-llm-security：LLM 安全更大的资源清单，作为本清单的外层扩展。
- **[awesome-mcp-servers](https://github.com/punkpeye/awesome-mcp-servers)** — awesome-mcp-servers：MCP server 资源清单，做 MCP 资产盘点与选型用。
- **[awesome-ai-safety](https://github.com/hari-sikchi/awesome-ai-safety)** — awesome-ai-safety：AI 安全（对齐/评测/治理）资源清单，补齐非攻击视角。
## 五、评估第三方 agent skill 的检查点

> 这是本技能包的**落地部分**：拿到一个第三方 skill（或 MCP server / 插件）准备装进自己的 Agent 前，按下列 8 组检查点逐条过一遍。每条都要留下证据（命令 + 输出 + 结论），未通过项按 OWASP Agentic Skills Top 10 的对应条目（AST01 恶意 skill、AST02 供应链篡改…）归档，并给出"拒绝 / 有条件接受 / 接受"的结论。

### 5.1 权限范围（Permission scope）
- 列出 skill **声明**的权限与它**实际**需要的权限：文件读写路径、网络目标、命令执行、环境变量与凭据、可否修改 MCP/hook 配置；两者不一致时以实测为准。
- 检查是否有通配授权（`*`、`/`、`sudo`、`curl … | bash`、无白名单的出网），以及能否**自我扩权**（改自身配置、改 skill 目录、注册新工具/新 hook）。
- 可操作动作：在带审计的沙箱里跑一遍全流程，记录真实 syscall 与网络目标，和声明权限做**差异表**；对差异项逐条要求解释或拒绝安装。
- 判定口径：宁可按"任务范围授权（task-scoped）"收紧——只给它完成当前任务所需的最小集合。

### 5.2 外发数据（Data egress）
- 枚举所有出网目标：域名/IP、webhook、遥测端点、包仓库、模型 API；确认**白名单外一律拒绝**。
- 检查是否存在把上下文、文件内容、环境变量、会话记录发出的逻辑（包括"经 LLM 中转"的隐性外发——Shadow API 类）。
- 检查落盘：日志、缓存、记忆、transcript 是否写入敏感内容，是否会随会话长期保留。
- 可操作动作：断网（仅放行白名单）+ 出网代理记录全部目标、请求体大小与频次；对照 skill 声明核对有无未声明的第三方。

### 5.3 提示注入面（Prompt injection surface）
- 分辨 skill 会**消费**哪些不可信输入：网页/邮件/Issue/文档、工具返回值、其他 agent 的消息、长期记忆。
- 检查是否存在指令与数据分离（结构化查询、边界分隔符、渲染后再读、可信来源标注），以及"读到即执行"的路径（工具输出被当指令或命令用）。
- 可操作动作：对每条不可信通道投喂注入样例（含隐藏文本、Unicode TAG 块、伪 chat 模板/控制令牌、音频/图片中的隐藏指令），观察是否越权或外发。
- 判定口径：只要有一条通道的注入能触发**高影响动作**（外发、写盘、执行、改配置），即视为未通过。

### 5.4 工具滥用（Tool abuse）
- 盘点它能调用的工具与参数面，找出**危险组合链**：读密钥 + 出网、写配置 + 提权、删数据 + 循环、跨 skill 串谋。
- 检查是否有执行前校验（pre-execution gate）、人工确认、超时/预算上限、循环与递归上限；hook/中间件是否可被 skill 自己修改（改钩子等于改安全策略）。
- 可操作动作：把工具依赖画成图（或用 Ziran 类工具自动发现危险链），针对最短危险链做一次受控复现，确认拦截生效。

### 5.5 供应链完整性（Supply chain integrity）
- **固定版本**：用 commit/tag + 哈希引用，禁止 `@latest` 与浮动分支；记录来源、作者、许可证与获取时间。
- 校验发布者与签名（Sigstore/Ed25519 类）、比对完整性清单（SHA-256）；检查外部引用（URL、脚本、模型权重）是否会在安装或运行时被替换。
- 检查传递依赖（npm/PyPI/MCP server/子 skill）并生成 SBOM；对"同名不同源"（typosquatting、同名不同 server）做核对。
- 可操作动作：入库前生成哈希清单 + 依赖树；此后每次更新走 **diff 审查**，出现能力变更（新增网络/执行/凭据权限）时必须人工复审。

### 5.6 代码执行面（Code execution surface）
- 找出所有执行点：shell、eval/exec、子进程、模板渲染、反序列化、插件/动态加载、安装期脚本（setup/postinstall）。
- 检查危险模式：`curl|sh`、未校验参数拼接、通配路径删除、提权调用、动态下载并执行。
- 隔离要求：低权限账户 + 沙箱 + 网络默认拒绝 + 文件系统只读挂载加临时目录 + 不注入真实凭据。
- 可操作动作：在**不含真实凭据**的沙箱跑完整流程，比对"声称的副作用"与"实测的副作用"（文件、网络、进程三条线）。

### 5.7 记忆与状态（Memory & state）
- 检查是否写入长期记忆/向量库、写入是否可被外部内容影响（记忆投毒）、是否能被后续会话继承、是否能被清理。
- 可操作动作：投喂一段带指令的记忆写入，观察后续无关会话是否被影响；确认记忆有来源标注与过期策略。

### 5.8 变更、复核与退出（Change, re-review & removal）
- 设定周期性复核：定期复查 skill 引用的外部内容是否变化（防"审查通过后改内容"），并监控能力变更。
- 确认可**完整卸载**：hook、计划任务、缓存、凭据、MCP 注册项、后台进程是否残留。
- 可操作动作：做一次"安装 → 使用 → 卸载 → 复核"演练，卸载后扫描残留文件与配置项，并把复核周期写进登记表。

### 5.9 一页速查（结论表模板）

| 检查点 | 结论（通过/有条件/拒绝） | 关键证据 | 对应 AST10 条目 | 复核时间 |
| --- | --- | --- | --- | --- |
| 权限范围 | | | AST01 / 过度授权类 | |
| 外发数据 | | | 数据外泄类 | |
| 提示注入面 | | | AST01 恶意 skill | |
| 工具滥用 | | | 工具滥用类 | |
| 供应链完整性 | | | AST02 供应链篡改 | |
| 代码执行面 | | | RCE 类 | |
| 记忆与状态 | | | 记忆投毒类 | |
| 变更与退出 | | | 跨平台复用 AST10 | |

## 六、来源与完整清单

- 上游仓库：<https://github.com/LLMSecurity/awesome-agent-skills-security>
- 上游 README 全文（含全部 513 条条目、48 个基准、54 个工具、7 份规范的原始描述）：`references/upstream-readme.md`
- 上游许可与贡献规则见 README 内的 `Citation` 与 `License` 小节；引用具体条目时请使用本文保留的原始 URL。
- 统计口径：本正文收录代表条目 100 余条 + 全部 7 份规范 + 39 个工具 + 22 个基准；其余条目（攻击面 175 条中的大量论文、防御 247 条中的大量论文）请按小节名在 `references/upstream-readme.md` 中检索。
