# API 参考：云存储访问模式分析

## AWS CLI - CloudTrail 查询
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceType,AttributeValue=AWS::S3::Object \
  --start-time 2024-01-15T00:00:00Z \
  --output json
```

## CloudTrail S3 Data Event 结构
```json
{
  "EventTime": "2024-01-15T10:30:00Z",
  "EventName": "GetObject",
  "Username": "analyst",
  "CloudTrailEvent": "{\"sourceIPAddress\":\"10.0.0.1\",\"userAgent\":\"aws-cli\",\"requestParameters\":{\"bucketName\":\"data\",\"key\":\"file.csv\"},\"userIdentity\":{\"arn\":\"arn:aws:iam::123:user/analyst\"}}"
}
```

## 关键 S3 事件名称
| 事件 | 含义 |
|-------|---------|
| GetObject | 对象下载 |
| PutObject | 对象上传 |
| DeleteObject | 对象删除 |
| ListBucket / ListObjectsV2 | 存储桶枚举 |
| GetBucketPolicy | 策略读取 |
| PutBucketPolicy | 策略修改 |

## 检测阈值
| 异常 | 阈值 | 严重程度 |
|---------|-----------|----------|
| 批量下载 | 每用户每小时 >100 次 GetObject | 严重 |
| 非工作时间 | 08:00-18:00 UTC 以外的访问 | 中 |
| 新源 IP | IP 不在 30 天基线中 | 高 |
| 枚举 | 每用户 >20 次 ListBucket | 高 |

## boto3 CloudTrail 客户端（备选）
```python
import boto3
client = boto3.client("cloudtrail")
response = client.lookup_events(
    LookupAttributes=[{"AttributeKey":"ResourceType","AttributeValue":"AWS::S3::Object"}],
    StartTime=datetime(2024,1,15),
    MaxResults=50
)
events = response["Events"]
```
