---
name: analyzing-api-gateway-access-logs
description: >
  解析 API 网关访问日志（AWS API Gateway、Kong、Nginx），检测 BOLA/IDOR 攻击、速率限制绕过、凭据扫描和注入尝试。使用 pandas 进行请求模式的统计分析和异常检测。适用于调查 API 滥用或构建 API 专项威胁检测规则。
domain: cybersecurity
subdomain: security-operations
tags: [analyzing, api, gateway, access]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# 分析 API 网关访问日志

## 使用说明

解析 API 网关访问日志，识别攻击模式，包括对象级别授权缺失（BOLA）、过度数据暴露和注入尝试。

```python
import pandas as pd

df = pd.read_json("api_gateway_logs.json", lines=True)
# 检测 BOLA：同一用户访问大量不同资源 ID
bola = df.groupby(["user_id", "endpoint"]).agg(
    unique_ids=("resource_id", "nunique")).reset_index()
suspicious = bola[bola["unique_ids"] > 50]
```

关键检测模式：
1. BOLA/IDOR：顺序资源 ID 枚举
2. 通过 Header 操纵绕过速率限制
3. 凭据扫描（单一来源的 401 激增）
4. 查询参数中的 SQL/NoSQL 注入
5. 只读端点上的异常 HTTP 方法（DELETE、PATCH）

## 示例

```python
# 检测 401 激增，指示凭据扫描
auth_failures = df[df["status_code"] == 401]
scanner_ips = auth_failures.groupby("source_ip").size()
scanners = scanner_ips[scanner_ips > 100]
```
