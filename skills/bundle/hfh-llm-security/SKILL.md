---
name: hfh-llm-security
description: 网络安全知识库「大模型安全」分类技能包，源自 Hi-FullHouse/CyberSecurity-Skills 上游 16-大模型安全-LLMSecurity。参照 OWASP LLM Top 10 与 MITRE ATLAS，覆盖提示注入与防护（直接/间接注入、越狱、评估矩阵）、LLM 数据泄露与隐私保护（训练数据记忆、推理泄露、差分隐私）、AI 供应链安全（模型权重投毒、依赖劫持、Hugging Face 恶意模型、CI/CD 劫持）、AI Agent 权限与访问控制（工具调用链、参数混淆、越权场景与最小权限设计）、AI 应用安全配置审计（API 端点、模型、数据、基础设施、合规 Checklist）、大模型红队测试（ATLAS 攻击矩阵全战术与 ASR 等指标）、模型对抗攻击与防御（Token/嵌入/梯度/黑盒/通用触发器）、模型输出安全与幻觉检测、多模态 AI 安全与联邦学习安全，含 11 份中文原文 references。
---

# 大模型安全（LLM Security）

> 上游来源：<https://github.com/Hi-FullHouse/CyberSecurity-Skills> → `16-大模型安全-LLMSecurity`
> 本技能包由上游 11 个 Markdown 文件转存，正文是导航与一句话要点，**中文原文完整保留在 `references/`**。
> 主要映射：**OWASP LLM Top 10**（LLM-01 提示注入、LLM-02 不安全输出处理、LLM-05 供应链、LLM-06 数据泄露、LLM-08 过度自主）、**MITRE ATLAS**。

## 使用方式

1. 按目标挑文件：**应用层**（提示注入、输出安全）→ **数据层**（泄露与隐私）→ **供应链层**（模型与依赖）→ **Agent 层**（权限控制）→ **基础设施层**（配置审计）。
2. 需要"评估结论"时用 `LLMRedTeaming` 的指标口径（ASR / 拒绝率 / 过度拒绝率 / 对抗鲁棒性）。
3. 面向 agent skill 生态做审查时，配合 `agent-skills-security` 的「评估第三方 agent skill 的检查点」交叉使用。

## 知识清单（逐文件要点）

### 1. LLM 提示注入与安全防护（Prompt Injection Defense）
- **一句话要点**：提示注入是大模型应用**最严重的安全威胁**（OWASP LLM-01），攻击者用精心构造的输入覆盖系统指令。
- **覆盖**：直接提示注入、间接提示注入（含经文档/网页/工具返回值注入）、越狱手法分类、防护设计（输入过滤、指令分层、上下文隔离）、**漏洞评级与评估矩阵**、常用工具。
- **原文**：`references/LLM-PromptInjectionDefense.md`

### 2. LLM 数据泄露与隐私保护（Data Leakage & Privacy）
- **一句话要点**：训练、推理、部署各阶段都会泄数据（OWASP LLM-06），**既要防模型记忆泄漏也要防管道外泄**。
- **覆盖**：训练数据记忆泄露（提取攻击）、推理时敏感信息泄露、第三方 API 数据外泄、差分隐私与脱敏、数据生命周期 Checklist（收集/处理/推理/API）、合规标准映射、**数据泄露应急响应**。
- **原文**：`references/LLM-DataLeakagePrivacy.md`

### 3. AI 供应链安全（AI Supply Chain Security）
- **一句话要点**：模型托管、第三方 API、开源组件、训练数据、部署设施都是入口（OWASP LLM-05）。
- **覆盖**：五类真实场景——模型权重投毒、Python 依赖劫持（Typosquatting）、Hugging Face 恶意模型、训练数据污染、CI/CD 管道劫持；模型获取/依赖管理/部署安全/持续监控四组 Checklist（含 SBOM）；模型来源验证与完整性校验。
- **原文**：`references/AI-AISupplyChainSecurity.md`

### 4. AI Agent 权限与访问控制（Agent Authorization）
- **一句话要点**：Agent 能调工具、访资源、处理敏感数据，**权限失控即越权执行**（OWASP LLM-08 Excessive Agency）。
- **覆盖**：Agent 权限模型设计；四类攻击场景——工具调用链攻击（递归绕过单次检查）、参数混淆攻击、权限提升（改自身配置）、社会工程间接注入；五项设计原则（最小权限、纵深防御、人工参与、可审计、故障安全）。
- **原文**：`references/AI-Agent-AgentAuthorization.md`

### 5. AI 应用安全配置审计（AI App Security Config Audit）
- **一句话要点**：LLM 服务部署、API 端点、推理服务、向量库的**安全基线检查**（参照 OWASP ASVS 与 CIS AI 基准）。
- **覆盖**：LLM API 端点审计；五组检查——API 安全（认证/限流）、模型安全（完整性校验）、数据安全（不落盘/定期清理）、基础设施（防火墙与隔离）、合规（GDPR/CCPA/个保法）；CIS AI 安全基准参考与自动化审计脚本。
- **原文**：`references/AI-AIAppSecurityConfig.md`

### 6. 大模型红队测试（LLM Red Teaming）
- **一句话要点**：按 **MITRE ATLAS** 的攻击战术做系统化对抗评估，产出可量化的安全边界结论。
- **覆盖**：ATLAS 全战术对照（侦察 T1501、资源开发 T1510、初始访问 T1520、执行 T1530、持久化 T1540、提权 T1550、防御规避 T1560、凭证访问 T1570、发现 T1580、横向移动 T1590、收集 T1601、C2 T1610、影响 T1620）；评估指标口径——**ASR 攻击成功率、稳健性、拒绝率、过度拒绝率、对抗鲁棒性**；报告模板与工具。
- **原文**：`references/LLMRedTeaming.md`

### 7. 模型对抗攻击与防御（Adversarial Attack & Defense）
- **一句话要点**：对人眼不可察觉的微小扰动即可让模型出错，**LLM 时代表现为对抗 Token、嵌入扰动与通用后缀**。
- **覆盖**：对抗样本生成五类（Token 级替换、嵌入空间攻击、白盒梯度攻击、黑盒查询攻击、通用对抗触发器）、评估指标、攻击威胁级别划分、防御与工具框架。
- **原文**：`references/AdversarialAttackDefense.md`

### 8. 模型输出安全与幻觉检测（Output Safety & Hallucination）
- **一句话要点**：输出侧风险包括有害内容、事实幻觉与版权问题（OWASP LLM-02 不安全输出处理）。
- **覆盖**：输出内容安全过滤、幻觉检测与事实一致性验证、输出侧注入（下游渲染/XSS/命令拼接）、版权与合规、工具与检测流程。
- **原文**：`references/OutputSafetyHallucination.md`

### 9. 多模态 AI 安全（Multimodal AI Security）
- **一句话要点**：文本、图像、音频、视频多模态并存时，**视觉隐写与音频隐蔽指令成为新的注入通道**。
- **覆盖**：视觉对抗攻击（图片中隐藏文字指令）、视觉隐写注入、音频隐蔽指令注入、跨模态对抗攻击（视觉-文本）、评估维度与防御措施。
- **原文**：`references/AI-MultimodalAISecurity.md`

### 10. 联邦学习安全（Federated Learning Security）
- **一句话要点**：联邦学习不共享原始数据，但**梯度本身就是可攻击面**。
- **覆盖**：联邦学习威胁模型；五类攻击——模型投毒、梯度泄露（反推训练数据）、成员推理、拜占庭攻击、自由骑；隐私保护与投毒防御机制、工具。
- **原文**：`references/FederatedLearningSecurity.md`

### 11. 分类导读（README）
- **一句话要点**：上游该分类的官方目录说明（参照 OWASP LLM Top 10 与 MITRE ATLAS 的能力地图）。
- **原文**：`references/README.md`

## 评估纪律

- **区分"影响到输出"与"影响到系统"**：能改模型输出只是表层，能触发工具调用/数据外带/权限变更才是高危。
- **指标要量化**：测试结论附 ASR、样本数、对照组，避免"试了几个 prompt 就下结论"。
- **提示注入的间接面优先测**：RAG 文档、网页内容、工具返回值、其他 Agent 消息这些非用户直输的通道更容易被忽视。
- **供应链先查版本与来源**：模型权重哈希、依赖锁定、CI 权限三个点最容易出问题。
