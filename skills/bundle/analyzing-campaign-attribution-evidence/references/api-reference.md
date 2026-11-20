# API 参考：攻击活动溯源归因证据分析

## Diamond Model 入侵分析

### 四个核心要素
| 要素 | 描述 | 溯源价值 |
|---------|-------------|-------------------|
| 对手 | 威胁行为者身份 | 直接溯源 |
| 能力 | 恶意软件、漏洞利用、工具 | 间接 - 共享工具 |
| 基础设施 | C2、域名、IP | 较强 - 操作重叠 |
| 受害者 | 目标、行业、地区 | 上下文 - 目标模式 |

### 枢纽分析
```
对手 ←→ 能力 ←→ 基础设施 ←→ 受害者
  ↕          ↕           ↕          ↕
(HUMINT) (恶意软件库) (WHOIS/DNS) (受害者学)
```

## 竞争假设分析（ACH）

### 矩阵格式
```
证据 \ 假设          |  APT28  |  APT29  |  Lazarus  |  未知
-----------------------------------------------------------------
基础设施重叠          |   ++    |    -    |     -     |    N
TTP 一致性           |   ++    |   ++    |     -     |    N
恶意软件相似性         |    +    |    -    |     -     |    N
时序（UTC+3）         |   ++    |   ++    |     -     |    N
语言（俄语）           |   ++    |   ++    |     -     |    N
```

### 评分
| 符号 | 含义 | 权重 |
|--------|---------|--------|
| `++` | 强一致 | +2 |
| `+` | 一致 | +1 |
| `N` | 中性 | 0 |
| `-` | 不一致 | -1 |
| `--` | 强不一致 | -2 |

## MITRE ATT&CK 组织查询

### Python (mitreattack-python)
```python
from mitreattack.stix20 import MitreAttackData
attack = MitreAttackData("enterprise-attack.json")
group = attack.get_group_by_alias("APT29")
techniques = attack.get_techniques_used_by_group(group.id)
```

### STIX2 关系查询
```python
from stix2 import Filter
relationships = src.query([
    Filter("type", "=", "relationship"),
    Filter("source_ref", "=", group_id),
    Filter("relationship_type", "=", "uses"),
])
```

## 基础设施重叠工具

### PassiveTotal / RiskIQ
```bash
# WHOIS 历史记录
curl -u user:key "https://api.passivetotal.org/v2/whois?query=domain.com"

# 被动 DNS
curl -u user:key "https://api.passivetotal.org/v2/dns/passive?query=1.2.3.4"
```

### VirusTotal 关联关系
```bash
curl -H "x-apikey: KEY" \
  "https://www.virustotal.com/api/v3/domains/example.com/communicating_files"
```

## 置信度评估框架

| 级别 | 分数范围 | 标准 |
|-------|------------|---------|
| 高 | 0.8-1.0 | 多种独立证据类型汇聚 |
| 中 | 0.5-0.8 | 重要证据存在但有差距 |
| 低 | 0.2-0.5 | 证据有限，替代假设仍然存在 |
| 可忽略 | 0.0-0.2 | 证据不足以进行溯源 |

## STIX 溯源对象

### Campaign 对象
```json
{
  "type": "campaign",
  "name": "Operation DarkShadow",
  "first_seen": "2024-01-15T00:00:00Z",
  "last_seen": "2024-03-20T00:00:00Z",
  "objective": "Espionage targeting defense sector"
}
```

### 溯源关系
```json
{
  "type": "relationship",
  "relationship_type": "attributed-to",
  "source_ref": "campaign--abc123",
  "target_ref": "intrusion-set--def456",
  "confidence": 75
}
```
