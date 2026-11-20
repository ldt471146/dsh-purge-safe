---
name: analyzing-apt-group-with-mitre-navigator
description: 使用 MITRE ATT&CK Navigator 分析高级持续性威胁（APT）组织的技术手法，创建对手 TTP 的分层热力图，用于检测差距分析和威胁导向防御。
domain: cybersecurity
subdomain: threat-intelligence
tags: [mitre-attack, navigator, apt, threat-actor, ttp-analysis, heatmap, detection-gap, threat-intelligence]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# 使用 MITRE ATT&CK Navigator 分析 APT 组织

## 概述

MITRE ATT&CK Navigator 是一款基于 Web 的工具，用于标注和探索 ATT&CK 矩阵，使分析人员能够可视化威胁行为者（Threat Actor）的技术覆盖情况、比较多个 APT 组织、识别检测差距，并构建威胁导向防御策略。本技能涵盖通过编程方式查询 ATT&CK 数据、将 APT 组织的 TTP 映射到 Navigator 层、创建多层叠加进行差距分析，以及为检测工程团队生成可执行情报报告。

## 前置条件

- Python 3.9+，安装 `attackcti`、`mitreattack-python`、`stix2`、`requests` 库
- ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/) 或本地部署版本
- 了解 ATT&CK Enterprise 矩阵：14 个战术、200+ 个技术及子技术
- 访问威胁情报报告或 MISP/OpenCTI 获取威胁行为者数据
- 熟悉 STIX 2.1 的 Intrusion Set 和 Attack Pattern 对象

## 核心概念

### ATT&CK Navigator 层

Navigator 层是 JSON 文件，用于为 ATT&CK 技术添加分数、颜色、注释和元数据标注。每个层可以代表单个 APT 组织的技术使用情况、检测能力图谱或组合叠加层。4.5 版本层格式支持 enterprise-attack、mobile-attack 和 ics-attack 域，并可按平台（Windows、Linux、macOS、Cloud、Azure AD、Office 365、SaaS）进行过滤。

### ATT&CK 中的 APT 组织画像

ATT&CK 收录了超过 140 个威胁组织及其记录在案的技术使用情况。每个组织画像包含别名、目标行业、关联攻击活动、所用软件及技术映射（含过程级详情）。组织通过 G 代码标识（如 APT29 为 G0016，APT28 为 G0007，Lazarus Group 为 G0032）。

### 多层分析

Navigator 支持同时加载多个层，使分析人员能够将威胁行为者的 TTP 叠加到检测覆盖范围上以识别差距，比较多个 APT 组织以发现值得优先处理的共同技术，并追踪技术覆盖随时间的变化。

## 实践步骤

### 步骤 1：查询 APT 组织的 ATT&CK 数据

```python
from attackcti import attack_client
import json

lift = attack_client()

# 获取所有威胁组织
groups = lift.get_groups()
print(f"Total ATT&CK groups: {len(groups)}")

# 查找 APT29（Cozy Bear / Midnight Blizzard）
apt29 = next((g for g in groups if g.get('name') == 'APT29'), None)
if apt29:
    print(f"Group: {apt29['name']}")
    print(f"Aliases: {apt29.get('aliases', [])}")
    print(f"Description: {apt29.get('description', '')[:300]}")

# 获取 APT29（G0016）使用的技术
techniques = lift.get_techniques_used_by_group("G0016")
print(f"APT29 uses {len(techniques)} techniques")

technique_map = {}
for tech in techniques:
    tech_id = ""
    for ref in tech.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            tech_id = ref.get("external_id", "")
            break
    if tech_id:
        tactics = [p.get("phase_name", "") for p in tech.get("kill_chain_phases", [])]
        technique_map[tech_id] = {
            "name": tech.get("name", ""),
            "tactics": tactics,
            "description": tech.get("description", "")[:500],
            "platforms": tech.get("x_mitre_platforms", []),
            "data_sources": tech.get("x_mitre_data_sources", []),
        }
```

### 步骤 2：生成 Navigator 层 JSON

```python
def create_navigator_layer(group_name, technique_map, color="#ff6666"):
    techniques_list = []
    for tech_id, info in technique_map.items():
        for tactic in info["tactics"]:
            techniques_list.append({
                "techniqueID": tech_id,
                "tactic": tactic,
                "color": color,
                "comment": info["name"],
                "enabled": True,
                "score": 100,
                "metadata": [
                    {"name": "group", "value": group_name},
                    {"name": "platforms", "value": ", ".join(info["platforms"])},
                ],
            })

    layer = {
        "name": f"{group_name} TTP Coverage",
        "versions": {"attack": "16.1", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Techniques attributed to {group_name}",
        "filters": {
            "platforms": ["Linux", "macOS", "Windows", "Cloud",
                          "Azure AD", "Office 365", "SaaS", "Google Workspace"]
        },
        "sorting": 0,
        "layout": {
            "layout": "side", "aggregateFunction": "average",
            "showID": True, "showName": True,
            "showAggregateScores": False, "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques_list,
        "gradient": {"colors": ["#ffffff", color], "minValue": 0, "maxValue": 100},
        "legendItems": [
            {"label": f"Used by {group_name}", "color": color},
            {"label": "Not observed", "color": "#ffffff"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }
    return layer

layer = create_navigator_layer("APT29", technique_map)
with open("apt29_layer.json", "w") as f:
    json.dump(layer, f, indent=2)
print("[+] Layer saved: apt29_layer.json")
```

### 步骤 3：比较多个 APT 组织

```python
groups_to_compare = {"G0016": "APT29", "G0007": "APT28", "G0032": "Lazarus Group"}
group_techniques = {}

for gid, gname in groups_to_compare.items():
    techs = lift.get_techniques_used_by_group(gid)
    tech_ids = set()
    for t in techs:
        for ref in t.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_ids.add(ref.get("external_id", ""))
    group_techniques[gname] = tech_ids

common_to_all = set.intersection(*group_techniques.values())
print(f"Techniques common to all groups: {len(common_to_all)}")
for tid in sorted(common_to_all):
    print(f"  {tid}")

for gname, techs in group_techniques.items():
    others = set.union(*[t for n, t in group_techniques.items() if n != gname])
    unique = techs - others
    print(f"\nUnique to {gname}: {len(unique)} techniques")
```

### 步骤 4：使用层叠加进行检测差距分析

```python
# 定义当前检测能力
detected_techniques = {
    "T1059", "T1059.001", "T1071", "T1071.001", "T1566", "T1566.001",
    "T1547", "T1547.001", "T1053", "T1053.005", "T1078", "T1027",
}

actor_techniques = set(technique_map.keys())
covered = actor_techniques.intersection(detected_techniques)
gaps = actor_techniques - detected_techniques

print(f"=== Detection Gap Analysis for APT29 ===")
print(f"Actor techniques: {len(actor_techniques)}")
print(f"Detected: {len(covered)} ({len(covered)/len(actor_techniques)*100:.0f}%)")
print(f"Gaps: {len(gaps)} ({len(gaps)/len(actor_techniques)*100:.0f}%)")

# 创建差距层（红色=未检测，绿色=已检测）
gap_techniques = []
for tech_id in actor_techniques:
    info = technique_map.get(tech_id, {})
    for tactic in info.get("tactics", [""]):
        color = "#66ff66" if tech_id in detected_techniques else "#ff3333"
        gap_techniques.append({
            "techniqueID": tech_id,
            "tactic": tactic,
            "color": color,
            "comment": f"{'DETECTED' if tech_id in detected_techniques else 'GAP'}: {info.get('name', '')}",
            "enabled": True,
            "score": 100 if tech_id in detected_techniques else 0,
        })

gap_layer = {
    "name": "APT29 Detection Gap Analysis",
    "versions": {"attack": "16.1", "navigator": "5.1.0", "layer": "4.5"},
    "domain": "enterprise-attack",
    "description": "Green = detected, Red = gap",
    "techniques": gap_techniques,
    "gradient": {"colors": ["#ff3333", "#66ff66"], "minValue": 0, "maxValue": 100},
    "legendItems": [
        {"label": "Detected", "color": "#66ff66"},
        {"label": "Detection Gap", "color": "#ff3333"},
    ],
}
with open("apt29_gap_layer.json", "w") as f:
    json.dump(gap_layer, f, indent=2)
```

### 步骤 5：战术分类分析

```python
from collections import defaultdict

tactic_breakdown = defaultdict(list)
for tech_id, info in technique_map.items():
    for tactic in info["tactics"]:
        tactic_breakdown[tactic].append({"id": tech_id, "name": info["name"]})

tactic_order = [
    "reconnaissance", "resource-development", "initial-access",
    "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

print("\n=== APT29 Tactic Breakdown ===")
for tactic in tactic_order:
    techs = tactic_breakdown.get(tactic, [])
    if techs:
        print(f"\n{tactic.upper()} ({len(techs)} techniques):")
        for t in techs:
            print(f"  {t['id']}: {t['name']}")
```

## 验收标准

- 成功通过 TAXII 服务器查询 ATT&CK 数据
- APT 组织已映射到所有记录在案的技术及过程示例
- Navigator 层 JSON 在 ATT&CK Navigator 中验证通过并正确渲染
- 多层叠加显示威胁行为者与检测覆盖情况的对比
- 检测差距分析识别出未监控的技术并提供数据源建议
- 跨组织比较揭示共同和独特的 TTP
- 输出结果可供检测工程优先级排序使用

## 参考资料

- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [ATT&CK Groups](https://attack.mitre.org/groups/)
- [attackcti Python Library](https://github.com/OTRF/ATTACK-Python-Client)
- [Navigator Layer Format v4.5](https://github.com/mitre-attack/attack-navigator/blob/master/layers/LAYERFORMATv4_5.md)
- [CISA Best Practices for MITRE ATT&CK Mapping](https://www.cisa.gov/sites/default/files/2023-01/Best%20Practices%20for%20MITRE%20ATTCK%20Mapping.pdf)
- [Picus: Leverage MITRE ATT&CK for Threat Intelligence](https://www.picussecurity.com/how-to-leverage-the-mitre-attack-framework-for-threat-intelligence)
