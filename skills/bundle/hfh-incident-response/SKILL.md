---
name: hfh-incident-response
description: 网络安全知识库「应急响应」分类技能包，源自 Hi-FullHouse/CyberSecurity-Skills 上游 15-应急响应-IncidentResponse。按 NIST SP 800-61 与 SANS PICERL 给出完整事件生命周期方法论：事件分类与优先级评估、日志收集与分析（含关键日志源与 IoC 提取）、网络流量分析（C2 与外传识别）、事件遏制与清除、事件复盘与报告（含报告模板与 5 Whys 根因分析）、云环境应急响应（AWS/Azure 责任共担与云原生取证），以及一份完整的 AI 安全应急响应手册（检测→分类→遏制→取证→清除→恢复→复盘，含 MITRE 映射与 SOAR 自动化），含 9 份中文原文 references。
---

# 应急响应（Incident Response）

> 上游来源：<https://github.com/Hi-FullHouse/CyberSecurity-Skills> → `15-应急响应-IncidentResponse`
> 本技能包由上游 9 个 Markdown 文件转存，正文是导航与一句话要点，**中文原文完整保留在 `references/`**。

## 使用方式

1. 主流程按 **SANS PICERL**（准备→识别→遏制→清除→恢复→复盘）或 **NIST SP 800-61** 推进，阶段顺序不要跳。
2. 先定级（`IncidentTriage`）再动手（`ContainmentEradication`）；证据固定优先于速度，除非仍在加密/外传。
3. 每个阶段都要留证据链：日志原文、流量导出、时间线、处置命令与时间戳。

## 知识清单（逐文件要点）

### 1. 事件分类与优先级评估（Incident Triage）
- **一句话要点**：**快速定级**，把有限的人力压到影响最大的事件上。
- **覆盖**：事件分类体系（按攻击类型与影响面）、NIST SP 800-61 四阶段分类模型、FIRST CVSS 评分体系、优先级判定与升级路径、常用工具。
- **原文**：`references/IncidentTriage.md`

### 2. 日志收集与分析（Log Collection & Analysis）
- **一句话要点**：日志是最关键的证据来源，**用于还原攻击路径、确定影响范围、提取 IoC**。
- **覆盖**：关键日志源清单（操作系统、网络设备、应用、云服务）、日志集中采集与保全、时间线重建、异常与攻击特征检索、IoC 提取、常用工具（SIEM/日志分析）。
- **原文**：`references/LogCollectionAnalysis.md`

### 3. 网络流量分析（Network Traffic Analysis）
- **一句话要点**：从流量里找**恶意通信模式**——C2、数据外传、横向移动的证据都在这。
- **覆盖**：流量捕获（镜像/探针/抓包）、协议与行为分析、C2 特征识别、数据外传判定、横向移动流量特征、IoC 提取与 PCAP 留存、常用工具。
- **原文**：`references/NetworkTrafficAnalysis.md`

### 4. 事件遏制与清除（Containment & Eradication）
- **一句话要点**：**在最小化业务影响的前提下**阻断攻击者进一步活动，并彻底清除威胁。
- **覆盖**：遏制策略选择（隔离主机/断网/封锁账号/加策略）、取证与遏制并行的取舍、清除步骤（清恶件、改口令、补漏洞、重建系统）、恢复与回归监测、常用工具。
- **原文**：`references/ContainmentEradication.md`

### 5. 事件复盘与报告（Lessons Learned & Reporting）
- **一句话要点**：生命周期最后也是最有价值的一环——**把事件变成体系改进**。
- **覆盖**：事件报告模板（概要/时间线/杀伤链还原/影响评估/RCA/改进措施/附录）、复盘会议议程与角色、5 Whys 与根因分类、改进项跟踪与持续改进循环、常用工具。
- **原文**：`references/LessonsLearnedReporting.md`

### 6. 云环境应急响应（Cloud Incident Response）
- **一句话要点**：云上 IR 与本地差异大——**共享责任模型、API 控制平面、资源瞬时性、云原生取证**。
- **覆盖**：云安全责任共担与 IR 边界、参照 AWS IR Guide / Azure Security Benchmark 的处置流程、控制平面日志与审计、快照与云原生取证、密钥与凭据泄露处置、常用工具。
- **原文**：`references/CloudIncidentResponse.md`

### 7. AI 安全应急响应（AI Security Incident Response）
- **一句话要点**：AI 事件的独特类型（**提示注入、模型数据泄露、Agent 越权、对抗攻击、供应链投毒**）需要专门流程。
- **覆盖**：检测与发现、AI 事件分级模型、短期与长期遏制、AI 事件取证数据收集、清除与恢复、复盘模板（概要/时间线/5 Whys/影响/修复/经验教训/KPI）、RCA 技术、SOAR 自动化响应、标准映射表（附录 A）、供应链与漏洞管理阶段。
- **原文**：`references/AI-AISecurityIncidentResponse.md`

### 8. AI 安全应急响应（扩展完整版）
- **一句话要点**：同一主题的**加长版手册**（约 60KB），含准备、检测、分类、遏制、取证、清除与恢复、复盘、供应链、漏洞管理、自动化与 SOAR 十个阶段的完整表格与命令。
- **原文**：`references/AI-AISecurityIncidentResponse-extended.md`

### 9. 分类导读（README）
- **一句话要点**：上游该分类的官方目录说明（参照 NIST SP 800-61 Rev 2、SANS PICERL 的生命周期划分）。
- **原文**：`references/README.md`

## 响应纪律

- **先固定证据再清除**：内存、日志、流量、磁盘镜像优先保全；重装或删除前必须已提取 IoC。
- **时间线统一时区**：所有日志与处置动作按同一时区记录，避免复盘时对不上。
- **遏制不等于清除**：隔离住后要确认持久化机制是否清干净（服务、计划任务、账户、密钥）。
- **改进项要有责任人与期限**，否则复盘等于没做。
- **IoC 要能直接用于检测**：给出哈希、域名/IP、互斥体、命令行特征，而不是只写"发现可疑文件"。
