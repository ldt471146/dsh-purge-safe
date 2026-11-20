---
name: analyzing-campaign-attribution-evidence
description: 攻击活动溯源归因分析涉及系统性地评估证据，以确定哪个威胁行为者或组织对某次网络行动负责。本技能涵盖使用 Diamond Model 和 ACH（竞争假设分析）收集并加权溯源归因指标、分析基础设施重叠、TTP 一致性、恶意软件代码相似性、操作时序模式和语言痕迹，以构建置信度加权的溯源归因评估。
domain: cybersecurity
subdomain: threat-intelligence
tags: [threat-intelligence, cti, ioc, mitre-attack, stix, attribution, campaign-analysis]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# 分析攻击活动溯源归因证据

## 概述

攻击活动溯源归因（Attribution）分析涉及系统性地评估证据，以确定哪个威胁行为者（Threat Actor）或组织对某次网络行动负责。本技能涵盖使用 Diamond Model 和 ACH（竞争假设分析）收集并加权溯源指标、分析基础设施重叠、TTP 一致性、恶意软件代码相似性、操作时序模式和语言痕迹，以构建置信度加权的归因评估报告。

## 前置条件

- Python 3.9+，安装 `attackcti`、`stix2`、`networkx` 库
- 访问威胁情报平台（MISP、OpenCTI）
- 了解 Diamond Model 入侵分析框架
- 熟悉 MITRE ATT&CK 威胁组织画像
- 掌握恶意软件分析和基础设施追踪技术

## 核心概念

### 溯源证据类别
1. **基础设施重叠**：共享 C2 服务器、域名、IP 范围、托管服务商
2. **TTP 一致性**：跨攻击活动中匹配的 ATT&CK 技术和子技术
3. **恶意软件代码相似性**：共享代码库、编译器、PDB 路径、加密例程
4. **操作模式**：时序（工作时间、时区）、目标模式、操作节奏
5. **语言痕迹**：特定语言的嵌入字符串、变量名、错误消息
6. **受害者学**：目标行业、地理位置和组织画像一致性

### 置信度级别
- **高置信度**：多个独立证据类别聚焦于同一行为者
- **中置信度**：若干证据类别匹配，但存在一定模糊性
- **低置信度**：证据有限，可能存在伪旗或共享工具

### 竞争假设分析（ACH）
一种结构化分析方法，针对多个竞争假设评估证据。每条证据针对每个假设被评分为一致、不一致或中性。不一致证据最少的假设为优先假设。

## 实践步骤

### 步骤 1：收集溯源证据

```python
from stix2 import MemoryStore, Filter
from collections import defaultdict

class AttributionAnalyzer:
    def __init__(self):
        self.evidence = []
        self.hypotheses = {}

    def add_evidence(self, category, description, value, confidence):
        self.evidence.append({
            "category": category,
            "description": description,
            "value": value,
            "confidence": confidence,
            "timestamp": None,
        })

    def add_hypothesis(self, actor_name, actor_id=""):
        self.hypotheses[actor_name] = {
            "actor_id": actor_id,
            "consistent_evidence": [],
            "inconsistent_evidence": [],
            "neutral_evidence": [],
            "score": 0,
        }

    def evaluate_evidence(self, evidence_idx, actor_name, assessment):
        """评估证据与假设的关系：一致/不一致/中性。"""
        if assessment == "consistent":
            self.hypotheses[actor_name]["consistent_evidence"].append(evidence_idx)
            self.hypotheses[actor_name]["score"] += self.evidence[evidence_idx]["confidence"]
        elif assessment == "inconsistent":
            self.hypotheses[actor_name]["inconsistent_evidence"].append(evidence_idx)
            self.hypotheses[actor_name]["score"] -= self.evidence[evidence_idx]["confidence"] * 2
        else:
            self.hypotheses[actor_name]["neutral_evidence"].append(evidence_idx)

    def rank_hypotheses(self):
        """按溯源分数对假设进行排序。"""
        ranked = sorted(
            self.hypotheses.items(),
            key=lambda x: x[1]["score"],
            reverse=True,
        )
        return [
            {
                "actor": name,
                "score": data["score"],
                "consistent": len(data["consistent_evidence"]),
                "inconsistent": len(data["inconsistent_evidence"]),
                "confidence": self._score_to_confidence(data["score"]),
            }
            for name, data in ranked
        ]

    def _score_to_confidence(self, score):
        if score >= 80:
            return "HIGH"
        elif score >= 40:
            return "MODERATE"
        else:
            return "LOW"
```

### 步骤 2：基础设施重叠分析

```python
def analyze_infrastructure_overlap(campaign_a_infra, campaign_b_infra):
    """比较两个攻击活动的基础设施以进行溯源。"""
    overlap = {
        "shared_ips": set(campaign_a_infra.get("ips", [])).intersection(
            campaign_b_infra.get("ips", [])
        ),
        "shared_domains": set(campaign_a_infra.get("domains", [])).intersection(
            campaign_b_infra.get("domains", [])
        ),
        "shared_asns": set(campaign_a_infra.get("asns", [])).intersection(
            campaign_b_infra.get("asns", [])
        ),
        "shared_registrars": set(campaign_a_infra.get("registrars", [])).intersection(
            campaign_b_infra.get("registrars", [])
        ),
    }

    overlap_score = 0
    if overlap["shared_ips"]:
        overlap_score += 30
    if overlap["shared_domains"]:
        overlap_score += 25
    if overlap["shared_asns"]:
        overlap_score += 15
    if overlap["shared_registrars"]:
        overlap_score += 10

    return {
        "overlap": {k: list(v) for k, v in overlap.items()},
        "overlap_score": overlap_score,
        "assessment": "STRONG" if overlap_score >= 40 else "MODERATE" if overlap_score >= 20 else "WEAK",
    }
```

### 步骤 3：跨攻击活动的 TTP 对比

```python
from attackcti import attack_client

def compare_campaign_ttps(campaign_techniques, known_actor_techniques):
    """将攻击活动 TTP 与已知威胁行为者画像进行对比。"""
    campaign_set = set(campaign_techniques)
    actor_set = set(known_actor_techniques)

    common = campaign_set.intersection(actor_set)
    unique_campaign = campaign_set - actor_set
    unique_actor = actor_set - campaign_set

    jaccard = len(common) / len(campaign_set.union(actor_set)) if campaign_set.union(actor_set) else 0

    return {
        "common_techniques": sorted(common),
        "common_count": len(common),
        "unique_to_campaign": sorted(unique_campaign),
        "unique_to_actor": sorted(unique_actor),
        "jaccard_similarity": round(jaccard, 3),
        "overlap_percentage": round(len(common) / len(campaign_set) * 100, 1) if campaign_set else 0,
    }
```

### 步骤 4：生成溯源归因报告

```python
def generate_attribution_report(analyzer):
    """生成结构化溯源归因评估报告。"""
    rankings = analyzer.rank_hypotheses()

    report = {
        "assessment_date": "2026-02-23",
        "total_evidence_items": len(analyzer.evidence),
        "hypotheses_evaluated": len(analyzer.hypotheses),
        "rankings": rankings,
        "primary_attribution": rankings[0] if rankings else None,
        "evidence_summary": [
            {
                "index": i,
                "category": e["category"],
                "description": e["description"],
                "confidence": e["confidence"],
            }
            for i, e in enumerate(analyzer.evidence)
        ],
    }

    return report
```

## 验收标准

- 证据收集涵盖全部六个溯源类别
- ACH 矩阵正确地针对竞争假设评估证据
- 基础设施重叠分析识别共享指标
- TTP 对比使用 ATT&CK 技术 ID 确保精准性
- 溯源置信度级别有充分依据
- 报告包含替代假设和伪旗考量

## 参考资料

- [Diamond Model of Intrusion Analysis](https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf)
- [MITRE ATT&CK Groups](https://attack.mitre.org/groups/)
- [Analysis of Competing Hypotheses](https://www.cia.gov/static/9a5f1162fd0932c29e985f0159f56c07/Tradecraft-Primer-apr09.pdf)
- [Threat Attribution Framework](https://www.mandiant.com/resources/reports)
