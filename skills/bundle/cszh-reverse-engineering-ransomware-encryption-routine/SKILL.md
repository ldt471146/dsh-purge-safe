---
name: cszh-reverse-engineering-ransomware-encryption-routine
description: 对勒索软件加密例程进行逆向工程，以识别密码学算法、密钥生成缺陷，以及通过静态和动态分析挖掘潜在的解密机会。
---

> 本技能源自中文网络安全技能库 killvxk/cybersecurity-skills-zh（上游目录 reverse-engineering-ransomware-encryption-routine），正文按中文原文照录。

**这个技能干什么**：对勒索软件加密例程进行逆向工程，以识别密码学算法、密钥生成缺陷，以及通过静态和动态分析挖掘潜在的解密机会。

**什么时候用**：需要按上游中文方法论执行「reverse-engineering-ransomware-encryption-routine」对应任务时加载本技能。

**关键工具**：见正文各章节列出的命令与工具清单。

# 对勒索软件加密例程进行逆向工程

## 概述

现代勒索软件使用混合加密方案，将对称算法（AES-256-CBC/CTR、ChaCha20、Salsa20）用于文件加密，将非对称算法（RSA-2048/4096、Curve25519）用于密钥保护。加密例程通常为每个文件生成一个随机对称密钥，加密文件内容，然后用攻击者内嵌的公钥加密对称密钥。对这些例程进行逆向工程，可以识别具体算法、密钥派生方法、初始化向量（IV）、文件定向模式，以及可能在不支付赎金的情况下实现解密的实现缺陷。典型案例包括 Rhysida（AES-256-CTR + RSA-4096）、Qilin.B（带 AES-NI 的 AES-256-CTR 或 ChaCha20 回退）和 Medusa（AES-256 + RSA）。

## 前置条件

- IDA Pro 或 Ghidra，用于静态反汇编
- x64dbg/WinDbg，用于动态调试
- Python 3.9+，安装 `pycryptodome`、`pefile`
- 理解 AES、RSA、ChaCha20、Curve25519 算法
- 了解 Windows CryptoAPI 和 CNG（BCrypt）函数
- 用于安全执行的沙箱环境

## 核心概念

### 混合加密模型

勒索软件为每个文件生成唯一的 AES 密钥和 IV。文件内容使用该对称密钥加密。对称密钥再用攻击者的 RSA 公钥（内嵌于二进制文件中或从 C2 获取）加密。加密后的密钥追加或前置到加密后的文件中。只有持有 RSA 私钥的攻击者才能解密每个文件的对称密钥。

### 密码学 API 识别

Windows 勒索软件通常使用 CryptoAPI（`CryptAcquireContext`、`CryptGenKey`、`CryptEncrypt`）或 CNG（`BCryptGenerateSymmetricKey`、`BCryptEncrypt`）。部分使用 OpenSSL 或自定义实现。识别这些 API 调用可立即获取算法、密钥大小和操作模式的信息。

### 实现缺陷

解密机会来自：硬编码加密密钥、密钥生成使用弱伪随机数生成器（PRNG）（以 `GetTickCount` 或 `time()` 为种子）、跨文件复用 IV、使用 ECB 模式、加密后密钥仍留在内存中，以及在加密过程中可捕获密钥的竞争条件。

## 实践步骤

### 步骤 1：识别密码学函数

```python
#!/usr/bin/env python3
"""识别勒索软件 PE 文件中的密码学函数。"""
import pefile
import sys

CRYPTO_APIS = {
    # Windows CryptoAPI
    "CryptAcquireContextA": "CryptoAPI 上下文获取",
    "CryptAcquireContextW": "CryptoAPI 上下文获取",
    "CryptGenKey": "密钥生成",
    "CryptDeriveKey": "密钥派生",
    "CryptEncrypt": "加密操作",
    "CryptDecrypt": "解密操作",
    "CryptImportKey": "密钥导入（公钥？）",
    "CryptExportKey": "密钥导出",
    "CryptGenRandom": "随机数生成",
    "CryptCreateHash": "哈希创建",
    "CryptHashData": "哈希操作",
    # Windows CNG（BCrypt）
    "BCryptOpenAlgorithmProvider": "CNG 算法初始化",
    "BCryptGenerateSymmetricKey": "CNG 对称密钥生成",
    "BCryptEncrypt": "CNG 加密",
    "BCryptDecrypt": "CNG 解密",
    "BCryptGenerateKeyPair": "CNG 密钥对生成",
    "BCryptImportKeyPair": "CNG 密钥导入",
    # OpenSSL
    "EVP_EncryptInit_ex": "OpenSSL 加密初始化",
    "EVP_EncryptUpdate": "OpenSSL 加密更新",
    "EVP_EncryptFinal_ex": "OpenSSL 加密完成",
    "RSA_public_encrypt": "OpenSSL RSA 加密",
    "AES_set_encrypt_key": "OpenSSL AES 密钥设置",
    # 文件操作
    "CreateFileW": "文件打开（目标文件）",
    "ReadFile": "文件读取（加密前）",
    "WriteFile": "文件写入（加密后）",
    "FindFirstFileW": "文件枚举（目标定向）",
    "FindNextFileW": "文件枚举",
    "MoveFileW": "文件重命名（扩展名更改）",
    "DeleteFileW": "文件删除（原始文件）",
}

AES_SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
])

CHACHA20_CONSTANT = b"expand 32-byte k"


def analyze_imports(filepath):
    """分析 PE 导入表中的密码学 API。"""
    try:
        pe = pefile.PE(filepath)
    except pefile.PEFormatError:
        print("[-] 非有效 PE 文件")
        return

    print("[+] 密码学 API 分析")
    print("=" * 60)

    crypto_imports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('utf-8', errors='replace')
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode('utf-8', errors='replace')
                    if name in CRYPTO_APIS:
                        desc = CRYPTO_APIS[name]
                        crypto_imports.append((dll, name, desc))
                        print(f"  [{dll}] {name}: {desc}")

    if not crypto_imports:
        print("  导入表中未发现已知密码学 API")
        print("  恶意软件可能使用自定义实现或动态加载")

    return crypto_imports


def find_crypto_constants(filepath):
    """搜索内嵌的密码学常量。"""
    with open(filepath, 'rb') as f:
        data = f.read()

    print("\n[+] 密码学常量搜索")
    print("=" * 60)

    # AES S-Box
    offset = data.find(AES_SBOX)
    if offset != -1:
        print(f"  AES S-Box 位于偏移量 0x{offset:x}")

    # ChaCha20/Salsa20 常量
    offset = data.find(CHACHA20_CONSTANT)
    if offset != -1:
        print(f"  ChaCha20 常量位于偏移量 0x{offset:x}")

    # RSA 公钥标记
    rsa_markers = [
        b'-----BEGIN PUBLIC KEY-----',
        b'-----BEGIN RSA PUBLIC KEY-----',
        b'\x30\x82',  # ASN.1 SEQUENCE
    ]
    for marker in rsa_markers:
        offset = data.find(marker)
        if offset != -1:
            print(f"  RSA 密钥标记位于偏移量 0x{offset:x}")

    # 常见勒索软件文件扩展名模式
    import re
    ext_pattern = re.compile(rb'\.\w{3,10}(?=\x00)', re.IGNORECASE)
    extensions = set()
    for match in ext_pattern.finditer(data):
        ext = match.group().decode('ascii', errors='replace').lower()
        target_exts = [
            '.doc', '.docx', '.xls', '.xlsx', '.pdf', '.ppt',
            '.jpg', '.png', '.sql', '.mdb', '.bak', '.zip',
        ]
        if ext in target_exts:
            extensions.add(ext)

    if extensions:
        print(f"\n  目标文件扩展名: {', '.join(sorted(extensions))}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <勒索软件样本>")
        sys.exit(1)

    analyze_imports(sys.argv[1])
    find_crypto_constants(sys.argv[1])
```

### 步骤 2：分析加密流程

```python
def analyze_encryption_pattern(filepath):
    """从勒索软件产物分析文件加密模式。"""
    import os
    import struct

    with open(filepath, 'rb') as f:
        data = f.read()

    file_size = len(data)
    print(f"\n[+] 加密文件分析: {filepath}")
    print(f"  大小: {file_size:,} 字节")

    # 检查追加的密钥材料（常见模式）
    # 许多勒索软件家族在文件末尾追加加密后的密钥
    tail_sizes = [256, 512, 1024, 2048]  # 常见 RSA 密文大小
    for size in tail_sizes:
        if file_size > size + 16:
            tail = data[-size:]
            # 高熵值表明为加密数据
            entropy = calculate_entropy(tail)
            if entropy > 7.5:
                print(f"  文件末尾可能存在加密密钥（{size} 字节），"
                      f"熵值: {entropy:.2f}")

    # 检查头部修改
    # 许多勒索软件会前置元数据
    header = data[:64]
    print(f"  前 16 字节: {header[:16].hex()}")

    # 检查原始文件头是否被保留
    known_headers = {
        b'PK': 'ZIP/Office',
        b'\x89PNG': 'PNG',
        b'\xff\xd8\xff': 'JPEG',
        b'%PDF': 'PDF',
        b'\xd0\xcf\x11\xe0': 'OLE（DOC/XLS）',
    }
    for magic, ftype in known_headers.items():
        if header.startswith(magic):
            print(f"  原始格式已保留: {ftype}")
            break
    else:
        print("  原始文件头已被销毁/加密")


def calculate_entropy(data):
    """计算数据的香农熵。"""
    from collections import Counter
    import math

    if not data:
        return 0

    freq = Counter(data)
    length = len(data)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )
    return entropy
```

## 验证标准

- 识别密码学算法（AES、RSA、ChaCha20 等）
- 确定密钥大小和操作模式
- 分析密钥生成方法中的潜在弱点
- 记录每个文件的密钥加密方案
- 提取文件定向模式和扩展名列表
- 提取内嵌公钥用于基础设施关联
- 评估潜在解密机会

## 参考资料

- Morphisec - 拆解勒索软件加密: https://www.morphisec.com/blog/breaking-down-ransomware-encryption-key-strategies-algorithms-and-implementation-trends/
- Emsisoft - 勒索软件加密方法: https://www.emsisoft.com/en/blog/27649/ransomware-encryption-methods/
- Halcyon 勒索软件排名 Q4-2024: https://www.halcyon.ai/raas-mq/power-rankings-ransomware-malicious-quartile-q4-2024
- No More Ransom 项目: https://www.nomoreransom.org/
- MITRE ATT&CK T1486 - 数据加密影响: https://attack.mitre.org/techniques/T1486/
