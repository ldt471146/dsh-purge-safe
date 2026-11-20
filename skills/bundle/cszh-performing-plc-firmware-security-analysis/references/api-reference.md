# API参考 — 执行PLC固件安全分析

## 使用的库
- **subprocess**: 执行binwalk进行固件提取
- **hashlib**: MD5/SHA256固件哈希计算
- **re**: 凭据和漏洞模式扫描
- **pathlib**: 对提取的固件进行递归文件扫描
- **math**: 香农熵计算

## CLI接口
```
python agent.py extract --firmware plc_fw.bin [--output /tmp/fw_extract]
python agent.py metadata --firmware plc_fw.bin
python agent.py creds --dir /tmp/fw_extract
python agent.py vulns --dir /tmp/fw_extract
python agent.py full --firmware plc_fw.bin [--output /tmp/fw_extract]
```

## 核心函数

### `extract_firmware(firmware_file, output_dir)` — Binwalk提取
### `analyze_firmware_metadata(firmware_file)` — 哈希和熵分析
高熵（>7.5）可能表示存在加密或压缩。

### `scan_for_credentials(extract_dir)` — 硬编码凭据检测
模式：密码、默认凭据、私钥、API密钥、连接字符串。

### `scan_for_vulnerabilities(extract_dir)` — 代码漏洞模式
检测：命令注入（system/popen）、缓冲区溢出风险（strcpy/gets）、
不安全协议（telnet/FTP）、调试模式、后门指示符。

### `full_analysis(firmware_file, output_dir)` — 完整分析流水线

## 漏洞模式
| 模式 | 风险 | 指示符 |
|------|------|--------|
| command_injection | 高 | system(), popen(), exec() |
| buffer_overflow_risk | 高 | strcpy, strcat, sprintf, gets |
| insecure_protocol | 中 | telnet, ftp, http:// |
| debug_enabled | 中 | debug=true, DEBUG_MODE |
| backdoor_indicator | 严重 | backdoor, rootkit, reverse shell |

## 依赖
```
pip install binwalk
```
