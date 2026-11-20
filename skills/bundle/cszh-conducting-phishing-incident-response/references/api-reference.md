# API 参考：网络钓鱼事件响应 Agent

## 概述

分析钓鱼邮件：解析 EML 文件，提取 URL 和附件哈希，通过 VirusTotal 和 urlscan.io 检查信誉，评估 SPF/DKIM/DMARC 认证，并生成带严重性评级的 IR 报告。

## 依赖项

| 包 | 版本 | 用途 |
|----|------|------|
| requests | >=2.28 | VirusTotal 和 urlscan.io API 调用 |

## CLI 用法

```bash
python agent.py --eml suspicious_email.eml --vt-key <key> --output report.json
```

## 关键函数

### `parse_email_file(eml_path)`
解析 EML 文件，提取 Subject、From、To、Received 邮件头以及 SPF/DKIM/DMARC 认证结果。

### `extract_urls(msg)`
使用正则表达式从邮件正文（纯文本和 HTML 部分）中提取所有 URL。

### `extract_attachments(msg)`
提取附件文件名、内容类型、大小并计算 SHA-256/MD5 哈希。

### `check_url_virustotal(url, api_key)`
通过 VirusTotal v3 API 检查 URL 信誉（恶意、可疑、无害计数）。

### `check_url_urlscan(url)`
将 URL 提交到 urlscan.io 进行视觉和行为分析。

### `check_hash_virustotal(file_hash, api_key)`
在 VirusTotal 上检查附件哈希信誉以进行恶意软件检测。

### `assess_phishing_severity(parsed_email, url_results, attachment_results)`
根据认证失败和恶意内容评估钓鱼严重性（低/中/严重）。

## 使用的外部 API

| API | 端点 | 认证 | 用途 |
|-----|------|------|------|
| VirusTotal v3 | `/api/v3/urls/{id}` | API key | URL 信誉 |
| VirusTotal v3 | `/api/v3/files/{hash}` | API key | 文件哈希信誉 |
| urlscan.io | `/api/v1/scan/` | 无 | URL 视觉分析 |

## 邮件认证检查

| 检查项 | 通过 | 失败 | 影响 |
|--------|------|------|------|
| SPF | 发件人 IP 已授权 | 可能存在伪造 | 严重性 +1 |
| DKIM | 签名有效 | 邮件可能被篡改 | 严重性 +1 |
| DMARC | 策略已执行 | SPF+DKIM 对齐失败 | 严重性 +1 |
