---
name: analyzing-cloud-storage-access-patterns
description: >-
  通过分析 CloudTrail Data Events、GCS 审计日志和 Azure Storage Analytics，检测 AWS S3、GCS 和 Azure Blob Storage 中的异常访问模式。识别非工作时间的批量下载、来自新 IP 地址的访问、异常 API 调用（GetObject 峰值）以及使用统计基线和时间序列异常检测的潜在数据外泄行为。
domain: cybersecurity
subdomain: cloud-security
tags: [analyzing, cloud, storage, access]
version: "1.0"
author: mahipal
license: Apache-2.0
---

## 说明

1. 安装依赖：`pip install boto3 requests`
2. 使用 AWS CLI 或 boto3 查询 CloudTrail 的 S3 Data Events。
3. 建立访问基线：按小时请求量、每用户对象计数、源 IP 历史记录。
4. 检测异常：
   - 非工作时间访问（本地时间 8am-6pm 以外）
   - 批量下载：单个主体在 1 小时内 >100 次 GetObject 调用
   - 最近 30 天内未见过的新源 IP
   - ListBucket 枚举峰值（侦察指标）
5. 生成优先级排序的发现报告。

```bash
python scripts/agent.py --bucket my-sensitive-data --hours-back 24 --output s3_access_report.json
```

## 示例

### CloudTrail S3 Data Event
```json
{"eventName": "GetObject", "requestParameters": {"bucketName": "sensitive-data", "key": "financials/q4.xlsx"},
 "sourceIPAddress": "203.0.113.50", "userIdentity": {"arn": "arn:aws:iam::123456789012:user/analyst"}}
```
