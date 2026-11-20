# API 参考：分析 API 网关访问日志

## AWS API Gateway 日志字段

```json
{
  "requestId": "abc-123",
  "ip": "203.0.113.50",
  "httpMethod": "GET",
  "resourcePath": "/api/users/{id}",
  "status": 200,
  "requestTime": "2025-03-15T14:00:00Z",
  "responseLength": 1024
}
```

## Pandas 日志分析

```python
import pandas as pd

df = pd.read_json("access_logs.json", lines=True)

# BOLA 检测
df.groupby("user_id")["resource_id"].nunique()

# 认证失败激增
df[df["status_code"] == 401].groupby("source_ip").size()

# 请求速率
df.set_index("timestamp").resample("1min").size()
```

## OWASP API Top 10 检测模式

| 风险 | 检测模式 |
|------|-------------------|
| BOLA (API1) | 用户访问超过 50 个唯一资源 ID |
| 认证缺失 (API2) | 单个 IP 产生超过 100 次 401/403 |
| 过度数据暴露 (API3) | 响应大小超过平均值 10 倍 |
| 速率限制 (API4) | 单个 IP 每分钟请求超过 100 次 |
| BFLA (API5) | 对只读端点发送 DELETE/PUT 请求 |
| 注入 (API8) | 参数中包含 SQL/NoSQL 模式 |

## 注入正则表达式模式

```python
sql = r"union\s+select|drop\s+table|'\s*or\s+'1'"
nosql = r"\$ne|\$gt|\$regex|\$where"
xss = r"<script|javascript:|onerror="
path_traversal = r"\.\./\.\./|/etc/passwd"
```

### 参考资料

- OWASP API Security Top 10: https://owasp.org/API-Security/
- AWS API Gateway 日志: https://docs.aws.amazon.com/apigateway/latest/developerguide/
- pandas: https://pandas.pydata.org/docs/
