# API 参考：分析 Azure 活动日志中的威胁

## azure-monitor-query

```python
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from datetime import timedelta

credential = DefaultAzureCredential()
client = LogsQueryClient(credential)

response = client.query_workspace(
    workspace_id="WORKSPACE_ID",
    query="AzureActivity | take 10",
    timespan=timedelta(hours=24),
)
if response.status == LogsQueryStatus.SUCCESS:
    for table in response.tables:
        columns = [col.name for col in table.columns]
        for row in table.rows:
            print(dict(zip(columns, row)))
```

## Azure 主要日志表

| 表名 | 内容 |
|-------|---------|
| `AzureActivity` | 控制平面操作（ARM） |
| `SigninLogs` | Azure AD 登录事件 |
| `AuditLogs` | Azure AD 审计追踪 |
| `AzureDiagnostics` | 资源诊断（密钥保管库、NSG） |
| `SecurityAlert` | Defender for Cloud 告警 |

## 威胁检测 KQL 模式

```kql
// 权限提升
AzureActivity | where OperationNameValue has "ROLEASSIGNMENTS/WRITE"

// 不可能的地理旅行
SigninLogs | where ResultType == 0
| extend Distance = geo_distance_2points(...)

// 批量删除
AzureActivity | where OperationNameValue endswith "/DELETE"
| summarize count() by Caller, bin(TimeGenerated, 1h)
```

### 参考资料

- azure-monitor-query: https://pypi.org/project/azure-monitor-query/
- KQL 参考: https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/
- Azure 活动日志架构: https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log-schema
