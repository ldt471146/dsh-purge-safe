---
name: analyzing-azure-activity-logs-for-threats
description: >
  通过 azure-monitor-query 查询 Azure Monitor 活动日志和登录日志，检测可疑管理操作、不可能的地理旅行（Impossible Travel）、权限提升和资源修改。为 Azure 环境的威胁狩猎构建 KQL 查询。适用于调查可疑的 Azure 租户活动或构建云 SIEM 检测规则。
domain: cybersecurity
subdomain: security-operations
tags: [analyzing, azure, activity, logs]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# 分析 Azure 活动日志中的威胁

## 使用说明

使用 azure-monitor-query 对 Azure Log Analytics 工作区执行 KQL 查询，检测可疑管理操作和登录异常。

```python
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient
from datetime import timedelta

credential = DefaultAzureCredential()
client = LogsQueryClient(credential)

response = client.query_workspace(
    workspace_id="WORKSPACE_ID",
    query="AzureActivity | where OperationNameValue has 'MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE' | take 10",
    timespan=timedelta(hours=24),
)
```

关键检测查询：
1. 角色分配变更（权限提升）
2. 资源组和订阅修改
3. 来自新 IP 的密钥保管库访问
4. 网络安全组规则变更
5. 条件访问策略修改

## 示例

```python
# 检测新的全局管理员角色分配
query = '''
AuditLogs
| where OperationName == "Add member to role"
| where TargetResources[0].modifiedProperties[0].newValue has "Global Administrator"
'''
```
