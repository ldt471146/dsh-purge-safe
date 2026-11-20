# API 参考：MITRE ATT&CK Navigator APT 分析

## ATT&CK Navigator 层格式

### 层 JSON 结构
```json
{
  "name": "APT29 - TTPs",
  "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
  "domain": "enterprise-attack",
  "techniques": [
    {
      "techniqueID": "T1566.001",
      "tactic": "initial-access",
      "color": "#ff6666",
      "score": 100,
      "comment": "Used by APT29",
      "enabled": true
    }
  ],
  "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 100}
}
```

## ATT&CK STIX 数据访问

### 下载 Enterprise ATT&CK 数据包
```bash
curl -o enterprise-attack.json \
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

### STIX 对象类型
| 类型 | 描述 |
|------|-------------|
| `intrusion-set` | APT 组织 / 威胁行为者 |
| `attack-pattern` | 技术和子技术 |
| `relationship` | 将组织与技术关联（`uses`） |
| `malware` | 恶意软件家族 |
| `tool` | 对手使用的合法工具 |

## mitreattack-python 库

### 安装
```bash
pip install mitreattack-python
```

### 查询组织技术
```python
from mitreattack.stix20 import MitreAttackData

attack = MitreAttackData("enterprise-attack.json")
groups = attack.get_groups()
for g in groups:
    techs = attack.get_techniques_used_by_group(g)
    print(f"{g.name}: {len(techs)} techniques")
```

### 获取技术详情
```python
technique = attack.get_object_by_attack_id("T1566.001", "attack-pattern")
print(technique.name)          # Spearphishing Attachment
print(technique.x_mitre_platforms)  # ['Windows', 'macOS', 'Linux']
```

## Navigator CLI (attack-navigator)

### 导出层为 SVG
```bash
npx attack-navigator-export \
  --layer layer.json \
  --output output.svg \
  --theme dark
```

## ATT&CK API (TAXII)
```python
from stix2 import TAXIICollectionSource, Filter
from taxii2client.v20 import Collection

collection = Collection(
    "https://cti-taxii.mitre.org/stix/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e/"
)
tc_source = TAXIICollectionSource(collection)
groups = tc_source.query([Filter("type", "=", "intrusion-set")])
```

## 主要 APT 组织参考
| ID | 名称 | 已知别名 |
|----|------|--------------|
| G0016 | APT29 | Cozy Bear, The Dukes, NOBELIUM |
| G0007 | APT28 | Fancy Bear, Sofacy, Strontium |
| G0022 | APT3 | Gothic Panda, UPS |
| G0032 | Lazarus Group | HIDDEN COBRA, Zinc |
| G0074 | Dragonfly 2.0 | Energetic Bear, Berserk Bear |
| G0010 | Turla | Waterbug, Venomous Bear |
