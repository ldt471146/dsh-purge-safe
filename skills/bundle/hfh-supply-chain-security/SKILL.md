---
name: hfh-supply-chain-security
description: 网络安全知识库「供应链安全」分类技能包，源自 Hi-FullHouse/CyberSecurity-Skills 上游 25-供应链安全-SupplyChainSecurity。覆盖 SBOM 生成与验证（SPDX/CycloneDX、生成工具与漏洞联动）、代码签名与供应链完整性（Sigstore/cosign、SLSA 框架、可验证构建与透明日志）、供应链攻击检测与响应（SolarWinds/Codecov/Log4Shell 类事件的检测策略与五阶段响应时间线、安全度量指标）、第三方供应商风险评估（安全问卷、合同约束、数据保护条款与风险矩阵）以及软件依赖与开源合规审计（许可证识别、合规检查、策略实施与自动化审计），含 6 份中文原文 references。
---

# 供应链安全（Supply Chain Security）

> 上游来源：<https://github.com/Hi-FullHouse/CyberSecurity-Skills> → `25-供应链安全-SupplyChainSecurity`
> 本技能包由上游 6 个 Markdown 文件转存，正文是导航与一句话要点，**中文原文完整保留在 `references/`**。

## 使用方式

1. 三条主线：**可见性**（SBOM 与依赖清单）→ **完整性**（签名与可验证构建）→ **响应力**（被投毒后能不能快速定位影响面）。
2. 评估他人软件时，先看「有没有 SBOM + 有没有签名 + 构建是否可复现」，这三项直接决定事件响应速度。
3. 与 `agent-skills-security`、`hfh-llm-security` 的 AI 供应链部分交叉使用（模型/权重也属于供应链资产）。

## 知识清单（逐文件要点）

### 1. SBOM 生成与验证（SBOM Generation）
- **一句话要点**：SBOM 是供应链安全的基石——**清楚知道自己用了什么，才能在漏洞爆出时快速定位影响面**。
- **覆盖**：标准格式（**SPDX**、**CycloneDX**）、SBOM 生成工具（多语言生态）、SBOM 存储与版本关联、SBOM 与漏洞库联动分析、SBOM 验证与完整性、工具链。
- **原文**：`references/SBOM-SBOMGeneration.md`

### 2. 代码签名与供应链完整性（Code Signing & Integrity）
- **一句话要点**：用数字签名、透明日志与可验证构建，**建立从开发到部署的信任链**。
- **覆盖**：**Sigstore/cosign** 容器签名与验证、**SLSA** 框架与构建级别、源码与制品签名、透明日志（Rekor 类）与溯源、密钥管理与签名策略、工具链。
- **原文**：`references/CodeSigningIntegrity.md`

### 3. 供应链攻击检测与响应（Supply Chain Attack Response）
- **一句话要点**：上游被污染（SolarWinds / Codecov / Log4Shell 类）时，**响应速度取决于可见性**。
- **覆盖**：供应链攻击检测策略（依赖变更监控、异常外连、构建产物比对）、**五阶段响应时间线**（0-2h 确认评估 → 2-4h 遏制 → 4-24h 根除 → 24-72h 恢复 → 1-4 周改进）、影响面排查方法、供应链安全度量指标、常用工具。
- **原文**：`references/SupplyChainAttackResponse.md`

### 4. 第三方供应商风险评估（Third-Party Vendor Risk）
- **一句话要点**：第三方是供应链里**最薄弱的一环**，需要问卷、合同与持续监控三件套。
- **覆盖**：供应商安全问卷设计、数据保护条款与合同约束（含服务水平与事件通报义务）、持续监控与再评估、**供应商风险矩阵**与分级、常用工具。
- **原文**：`references/ThirdPartyVendorRisk.md`

### 5. 软件依赖与开源合规审计（Dependency & License Compliance）
- **一句话要点**：开源组件是软件基石，但**许可证合规风险**同样要审计与制度化。
- **覆盖**：许可证识别与分析（常见许可证义务差异）、合规检查流程、许可证策略与准入、自动化审计与 CI 集成、例外审批与台账管理、常用工具。
- **原文**：`references/DependencyLicenseCompliance.md`

### 6. 分类导读（README）
- **一句话要点**：上游该分类的官方目录说明（SBOM、代码签名、镜像扫描、供应商风险、开源合规、攻击检测响应）。
- **原文**：`references/README.md`

## 落地纪律

- **SBOM 要进流水线**：每次构建自动产出并归档，与制品哈希绑定，否则事后补不回来。
- **依赖要锁版本**：使用 lock 文件与私有镜像源校验，防止依赖混淆（dependency confusion）与 Typosquatting。
- **构建要可复现**：记录构建环境与调用链（SLSA provenance），否则无法证明制品与源码一致。
- **告警要能落到资产**：新增 CVE 出现时，能在小时内回答"哪些系统受影响"才算具备响应能力。
- **第三方要有退出方案**：合同里写清数据取回、通报时限与终止支持安排。
