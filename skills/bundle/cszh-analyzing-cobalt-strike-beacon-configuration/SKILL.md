---
name: cszh-analyzing-cobalt-strike-beacon-configuration
description: 从 PE 文件和内存转储中提取并分析 Cobalt Strike beacon 配置，以识别 C2 基础设施、Malleable C2 配置文件和攻击者操作惯例。
---

> 本技能源自中文网络安全技能库 killvxk/cybersecurity-skills-zh（上游目录 analyzing-cobalt-strike-beacon-configuration），正文按中文原文照录。

**这个技能干什么**：从 PE 文件和内存转储中提取并分析 Cobalt Strike beacon 配置，以识别 C2 基础设施、Malleable C2 配置文件和攻击者操作惯例。

**什么时候用**：需要按上游中文方法论执行「analyzing-cobalt-strike-beacon-configuration」对应任务时加载本技能。

**关键工具**：见正文各章节列出的命令与工具清单。

# 分析 Cobalt Strike Beacon 配置

## 概述

Cobalt Strike 是一个商业对抗模拟工具，被威胁行为者广泛滥用于后渗透操作。Beacon 载荷包含嵌入式配置数据，揭示 C2 服务器地址、通信协议、休眠间隔、抖动值、Malleable C2 配置文件设置、水印标识符和加密密钥。从 PE 文件、shellcode 或内存转储中提取此配置对于事件响应人员绘制攻击者基础设施和关联攻击活动至关重要。Beacon 配置使用单字节 XOR 编码（版本 3 使用 0x69，版本 4 使用 0x2e），以类型-长度-值（TLV）格式存储在 .data 节中。

## 前置条件

- Python 3.9+，安装 `dissect.cobaltstrike`、`pefile`、`yara-python`
- SentinelOne CobaltStrikeParser（`parse_beacon_config.py`）
- 十六进制编辑器（010 Editor、HxD）用于手动检查
- 了解 PE 文件格式和 XOR 编码
- 内存转储获取工具（Volatility3、WinDbg）
- 网络分析工具（Wireshark）用于 C2 流量关联

## 核心概念

### Beacon 配置结构

Cobalt Strike beacon 将其配置存储为 PE 文件 .data 节中的 TLV（类型-长度-值）条目集合。无分段 beacon 使用 4 字节密钥对整个 beacon 代码进行 XOR 编码。配置集合本身使用单字节 XOR 密钥。每个 TLV 条目包含一个 2 字节的类型标识符（如 0x0001 表示 BeaconType，0x0008 表示 C2Server）、一个 2 字节长度和可变长度数据。

### Malleable C2 配置文件

Beacon 配置编码了 Malleable C2 配置文件，该文件规定了 HTTP 请求/响应转换，包括 URI 路径、请求头、元数据编码（Base64、NetBIOS）和数据转换。分析这些设置可揭示 beacon 如何伪装其流量以融入合法的 Web 流量。

### 水印和许可证识别

每个 Cobalt Strike 许可证都会在生成的 beacon 中嵌入唯一水印（4 字节整数）。提取水印可将多个 beacon 关联到同一操作者或破解许可证。威胁情报提供商维护的已知水印数据库可将水印映射到特定威胁行为者或泄露的许可证密钥。

## 实操步骤

### 步骤 1：使用 CobaltStrikeParser 提取配置

```python
#!/usr/bin/env python3
"""从 PE 文件或内存转储中提取 Cobalt Strike beacon 配置。"""
import sys
import json

# 使用 SentinelOne 的 CobaltStrikeParser
# pip install dissect.cobaltstrike
from dissect.cobaltstrike.beacon import BeaconConfig

def extract_beacon_config(filepath):
    """从文件解析 beacon 配置。"""
    configs = list(BeaconConfig.from_path(filepath))

    if not configs:
        print(f"[-] 在 {filepath} 中未找到 beacon 配置")
        return None

    for i, config in enumerate(configs):
        print(f"\n[+] Beacon 配置 #{i+1}")
        print(f"{'='*60}")

        settings = config.as_dict()

        # 事件响应的关键字段
        critical_fields = [
            "SETTING_C2_REQUEST",
            "SETTING_C2_RECOVER",
            "SETTING_PUBKEY",
            "SETTING_DOMAINS",
            "SETTING_BEACONTYPE",
            "SETTING_PORT",
            "SETTING_SLEEPTIME",
            "SETTING_JITTER",
            "SETTING_MAXGET",
            "SETTING_SPAWNTO_X86",
            "SETTING_SPAWNTO_X64",
            "SETTING_PIPENAME",
            "SETTING_WATERMARK",
            "SETTING_C2_VERB_GET",
            "SETTING_C2_VERB_POST",
            "SETTING_USERAGENT",
            "SETTING_PROTOCOL",
        ]

        for field in critical_fields:
            value = settings.get(field, "N/A")
            print(f"  {field}: {value}")

        return settings

    return None


def extract_c2_indicators(config):
    """从 beacon 配置中提取可操作的 C2 指标。"""
    indicators = {
        "c2_domains": [],
        "c2_ips": [],
        "c2_urls": [],
        "user_agent": "",
        "named_pipes": [],
        "spawn_processes": [],
        "watermark": "",
    }

    if not config:
        return indicators

    # 提取 C2 域名
    domains = config.get("SETTING_DOMAINS", "")
    if domains:
        for domain in str(domains).split(","):
            domain = domain.strip().rstrip("/")
            if domain:
                indicators["c2_domains"].append(domain)

    # 提取 User Agent
    indicators["user_agent"] = str(config.get("SETTING_USERAGENT", ""))

    # 提取命名管道
    pipe = config.get("SETTING_PIPENAME", "")
    if pipe:
        indicators["named_pipes"].append(str(pipe))

    # 提取注入目标进程
    for arch in ["SETTING_SPAWNTO_X86", "SETTING_SPAWNTO_X64"]:
        proc = config.get(arch, "")
        if proc:
            indicators["spawn_processes"].append(str(proc))

    # 提取水印
    indicators["watermark"] = str(config.get("SETTING_WATERMARK", ""))

    return indicators


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法：{sys.argv[0]} <beacon_file_or_dump>")
        sys.exit(1)

    config = extract_beacon_config(sys.argv[1])
    if config:
        indicators = extract_c2_indicators(config)
        print(f"\n[+] 提取的 C2 指标：")
        print(json.dumps(indicators, indent=2))
```

### 步骤 2：手动 XOR 解密 Beacon 配置

```python
import struct

def find_and_decrypt_config(data):
    """手动定位并解密 beacon 配置。"""
    # Cobalt Strike 4.x 使用 0x2e 作为 XOR 密钥
    xor_keys = [0x2e, 0x69]  # v4, v3

    for xor_key in xor_keys:
        # 搜索 XOR 后的配置魔数字节
        # 配置以 0x0001（BeaconType）XOR 后开始
        magic = bytes([0x00 ^ xor_key, 0x01 ^ xor_key,
                       0x00 ^ xor_key, 0x02 ^ xor_key])

        offset = data.find(magic)
        if offset == -1:
            continue

        print(f"[+] 在偏移 0x{offset:x} 处找到配置（XOR 密钥：0x{xor_key:02x}）")

        # 解密配置集合（通常 4096 字节）
        config_size = 4096
        encrypted = data[offset:offset + config_size]
        decrypted = bytes([b ^ xor_key for b in encrypted])

        # 解析 TLV 条目
        entries = parse_tlv(decrypted)
        return entries

    return None


def parse_tlv(data):
    """解析类型-长度-值配置条目。"""
    entries = {}
    offset = 0

    # TLV 字段类型映射
    field_names = {
        0x0001: "BeaconType",
        0x0002: "Port",
        0x0003: "SleepTime",
        0x0004: "MaxGetSize",
        0x0005: "Jitter",
        0x0006: "MaxDNS",
        0x0007: "Deprecated_PublicKey",
        0x0008: "C2Server",
        0x0009: "UserAgent",
        0x000a: "PostURI",
        0x000b: "Malleable_C2_Instructions",
        0x000c: "Deprecated_HttpGet_Metadata",
        0x000d: "SpawnTo_x86",
        0x000e: "SpawnTo_x64",
        0x000f: "CryptoScheme",
        0x001a: "Watermark",
        0x001d: "C2_HostHeader",
        0x0024: "PipeName",
        0x0025: "Year",
        0x0026: "Month",
        0x0027: "Day",
        0x0036: "ProxyHostname",
    }

    while offset + 6 <= len(data):
        entry_type = struct.unpack(">H", data[offset:offset+2])[0]
        entry_len_type = struct.unpack(">H", data[offset+2:offset+4])[0]
        entry_len = struct.unpack(">H", data[offset+4:offset+6])[0]

        if entry_type == 0:
            break

        value_start = offset + 6
        value_end = value_start + entry_len
        value_data = data[value_start:value_end]

        field_name = field_names.get(entry_type, f"Unknown_0x{entry_type:04x}")

        if entry_len_type == 1:  # 短整型
            value = struct.unpack(">H", value_data[:2])[0]
        elif entry_len_type == 2:  # 整型
            value = struct.unpack(">I", value_data[:4])[0]
        elif entry_len_type == 3:  # 字符串/二进制
            value = value_data.rstrip(b'\x00').decode('utf-8', errors='replace')
        else:
            value = value_data.hex()

        entries[field_name] = value
        print(f"  {field_name}: {value}")

        offset = value_end

    return entries
```

### 步骤 3：用于 Beacon 检测的 YARA 规则

```python
import yara

cobalt_strike_rule = """
rule CobaltStrike_Beacon_Config {
    meta:
        description = "检测 Cobalt Strike beacon 配置"
        author = "恶意软件分析团队"
        date = "2025-01-01"

    strings:
        // CS 4.x 的 XOR 配置标记（密钥 0x2e）
        $config_v4 = { 2e 2f 2e 2c }

        // CS 3.x 的 XOR 配置标记（密钥 0x69）
        $config_v3 = { 69 68 69 6b }

        // 常见 beacon 字符串
        $str_pipe = "\\\\.\\pipe\\" ascii wide
        $str_beacon = "beacon" ascii nocase
        $str_sleeptime = "sleeptime" ascii nocase

        // 反射加载器模式
        $reflective = { 4D 5A 41 52 55 48 89 E5 }

    condition:
        ($config_v4 or $config_v3) or
        (2 of ($str_*) and $reflective)
}
"""

def scan_for_beacons(filepath):
    """使用 YARA 规则扫描文件中的 Cobalt Strike beacon。"""
    rules = yara.compile(source=cobalt_strike_rule)
    matches = rules.match(filepath)

    for match in matches:
        print(f"[+] YARA 匹配：{match.rule}")
        for string_match in match.strings:
            offset = string_match.instances[0].offset
            print(f"    字符串：{string_match.identifier} 位于偏移 0x{offset:x}")

    return matches
```

### 步骤 4：网络流量关联

```python
from dissect.cobaltstrike.c2 import HttpC2Config

def analyze_c2_profile(beacon_config):
    """分析 beacon 配置中的 Malleable C2 配置文件。"""
    print("\n[+] Malleable C2 配置文件分析")
    print("=" * 60)

    # HTTP GET 配置
    get_verb = beacon_config.get("SETTING_C2_VERB_GET", "GET")
    get_uri = beacon_config.get("SETTING_C2_REQUEST", "")
    print(f"\n  HTTP GET 请求：")
    print(f"    方法：{get_verb}")
    print(f"    URI：{get_uri}")

    # HTTP POST 配置
    post_verb = beacon_config.get("SETTING_C2_VERB_POST", "POST")
    post_uri = beacon_config.get("SETTING_C2_POSTREQ", "")
    print(f"\n  HTTP POST 请求：")
    print(f"    方法：{post_verb}")
    print(f"    URI：{post_uri}")

    # User Agent
    ua = beacon_config.get("SETTING_USERAGENT", "")
    print(f"\n  User-Agent：{ua}")

    # Host 请求头
    host = beacon_config.get("SETTING_C2_HOSTHEADER", "")
    print(f"  Host 请求头：{host}")

    # 休眠和抖动用于流量模式分析
    sleep_ms = beacon_config.get("SETTING_SLEEPTIME", 60000)
    jitter = beacon_config.get("SETTING_JITTER", 0)
    print(f"\n  休眠时间：{sleep_ms}ms")
    print(f"  抖动：{jitter}%")

    # 生成 Suricata/Snort 签名
    print(f"\n[+] 建议的网络签名：")
    if ua:
        print(f'  alert http any any -> any any (msg:"CS Beacon UA"; '
              f'content:"{ua}"; http_user_agent; sid:1000001; rev:1;)')
    if get_uri:
        print(f'  alert http any any -> any any (msg:"CS Beacon URI"; '
              f'content:"{get_uri}"; http_uri; sid:1000002; rev:1;)')
```

## 验证标准

- Beacon 配置已从 PE 文件或内存转储中成功提取
- C2 服务器域名/IP 与端口和协议正确识别
- Malleable C2 配置文件参数已解码，显示 HTTP 转换
- 水印值已提取用于溯源关联
- 休眠时间和抖动值与观察到的网络 beacon 间隔匹配
- YARA 规则可检测压缩和未压缩样本中的 beacon
- 从提取的 C2 配置文件生成网络签名

## 参考资料

- SentinelOne CobaltStrikeParser
- dissect.cobaltstrike 库
- SentinelLabs Beacon 配置分析
- Cobalt Strike 分段和配置提取
- MITRE ATT&CK - Cobalt Strike S0154
