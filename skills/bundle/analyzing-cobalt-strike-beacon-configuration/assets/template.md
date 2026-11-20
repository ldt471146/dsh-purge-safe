# Cobalt Strike Beacon 分析报告模板

## 报告元数据
| 字段 | 值 |
|-------|-------|
| 报告编号 | CS-BEACON-YYYY-NNNN |
| 日期 | YYYY-MM-DD |
| 样本哈希（SHA-256） | |
| 密级 | TLP:AMBER |
| 分析师 | |

## Beacon 配置摘要

| 配置项 | 值 |
|---------|-------|
| Beacon 类型 | HTTP / HTTPS / SMB / DNS |
| C2 服务器 | |
| 端口 | |
| 休眠时间 | ms |
| 抖动 | % |
| User-Agent | |
| 水印 | |
| SpawnTo (x86) | |
| SpawnTo (x64) | |
| Named Pipe | |
| Host Header | |
| 加密方案 | |

## C2 基础设施

| 指标 | 类型 | 值 | 上下文 |
|-----------|------|-------|---------|
| C2 域名 | domain | | 主要回调地址 |
| C2 IP | ip | | 解析地址 |
| URI 路径（GET） | uri | | Beacon 签入 |
| URI 路径（POST） | uri | | 数据外泄 |

## Malleable C2 配置

### HTTP GET 配置
| 参数 | 值 |
|-----------|-------|
| URI | |
| Verb | |
| Headers | |
| 元数据编码 | |

### HTTP POST 配置
| 参数 | 值 |
|-----------|-------|
| URI | |
| Verb | |
| ID 编码 | |
| 输出编码 | |

## 水印溯源

| 水印 | 已知关联 | 置信度 |
|-----------|------------------|------------|
| | 破解版 / 授权版 / 威胁行为者 | 高/中/低 |

## 网络检测签名

```
# Suricata 签名，用于检测 beacon C2 流量
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Cobalt Strike Beacon C2 Communication";
    content:"[USER_AGENT]"; http_user_agent;
    content:"[URI_PATH]"; http_uri;
    sid:1000001; rev:1;
)
```

## YARA 检测规则

```yara
rule CobaltStrike_Beacon_[CAMPAIGN] {
    meta:
        description = "Detects Cobalt Strike beacon from [CAMPAIGN]"
        hash = "[SHA256]"
    strings:
        $c2 = "[C2_DOMAIN]" ascii
        $pipe = "[NAMED_PIPE]" ascii
        $ua = "[USER_AGENT]" ascii
    condition:
        2 of them
}
```

## 建议

1. **封锁**：将 C2 域名/IP 加入防火墙拒绝列表
2. **狩猎**：在终端日志中搜索 named pipe 和 spawn-to 进程
3. **检测**：将 YARA 和网络签名部署到检测体系
4. **关联**：对照威胁情报数据库核查水印
