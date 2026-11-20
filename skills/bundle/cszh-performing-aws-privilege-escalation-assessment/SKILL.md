---
name: cszh-performing-aws-privilege-escalation-assessment
description: 在 AWS 环境中执行已授权的权限提升（Privilege Escalation）评估，使用 Pacu、CloudFox、Principal Mapper 和手动 IAM 策略分析技术，识别允许用户或角色提升权限的 IAM 配置错误。
---

> 本技能源自中文网络安全技能库 killvxk/cybersecurity-skills-zh（上游目录 performing-aws-privilege-escalation-assessment），正文按中文原文照录。

**这个技能干什么**：在 AWS 环境中执行已授权的权限提升（Privilege Escalation）评估，使用 Pacu、CloudFox、Principal Mapper 和手动 IAM 策略分析技术，识别允许用户或角色提升权限的 IAM 配置错误。

**什么时候用**：需要按上游中文方法论执行「performing-aws-privilege-escalation-assessment」对应任务时加载本技能。

**关键工具**：见正文各章节列出的命令与工具清单。

# 执行 AWS 权限提升评估

## 适用场景

- 对 AWS IAM 配置进行已授权的渗透测试时
- 验证 IAM 策略是否遵循最小权限原则时
- 评估受损 AWS 凭据的影响范围时
- 在 CI/CD 流水线中为 IAM 角色和策略变更构建安全审查时
- 评估跨账户信任关系的权限提升风险时

**不适用于**：未授权的 AWS 账户测试、非 IAM 攻击向量（SSRF、应用漏洞）的评估，或作为全面云渗透测试的替代方案。测试前务必获取书面授权。

## 前置条件

- 目标 AWS 账户权限提升测试的书面授权
- 作为起点的具有有限权限的测试 IAM 用户或角色
- 已安装 Pacu（`pip install pacu`）
- 已安装 CloudFox（`go install github.com/BishopFox/cloudfox@latest`）
- 已安装 PMapper（Principal Mapper）（`pip install principalmapper`）
- 配置了测试凭据并已启用 CloudTrail 日志的 AWS CLI（用于审计追踪）

## 工作流程

### 步骤 1：枚举初始权限

在尝试权限提升前，建立测试主体的基线权限。

```bash
# 获取当前身份
aws sts get-caller-identity

# 枚举当前用户的内联和附加策略
aws iam list-user-policies --user-name test-user
aws iam list-attached-user-policies --user-name test-user

# 获取组成员关系和组策略
aws iam list-groups-for-user --user-name test-user
for group in $(aws iam list-groups-for-user --user-name test-user --query 'Groups[*].GroupName' --output text); do
  echo "=== 组: $group ==="
  aws iam list-group-policies --group-name "$group"
  aws iam list-attached-group-policies --group-name "$group"
done

# 模拟特定 API 调用以映射有效权限
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::ACCOUNT:user/test-user \
  --action-names iam:CreateUser iam:AttachUserPolicy iam:PassRole \
    lambda:CreateFunction ec2:RunInstances sts:AssumeRole \
  --query 'EvaluationResults[*].[EvalActionName,EvalDecision]' --output table
```

### 步骤 2：使用 Pacu 扫描权限提升路径

使用 Pacu 的权限提升扫描器识别已知的 IAM 提升技术。

```bash
# 启动 Pacu 会话
pacu

# 创建会话并设置凭据
Pacu (new:session) > set_keys --key-alias privesc-test

# 枚举 IAM 配置
Pacu > run iam__enum_users_roles_policies_groups
Pacu > run iam__enum_permissions

# 运行权限提升扫描器
Pacu > run iam__privesc_scan

# 扫描器检查 21+ 种已知提升方法，包括：
# - iam:CreatePolicyVersion（创建管理员策略版本）
# - iam:SetDefaultPolicyVersion（恢复到宽松的旧版本）
# - iam:AttachUserPolicy / iam:AttachRolePolicy（附加管理员策略）
# - iam:PutUserPolicy / iam:PutRolePolicy（创建内联管理员策略）
# - iam:PassRole + lambda:CreateFunction（使用管理员角色的 Lambda）
# - iam:PassRole + ec2:RunInstances（使用管理员实例配置文件的 EC2）
# - iam:CreateLoginProfile / iam:UpdateLoginProfile（设置控制台密码）
# - iam:CreateAccessKey（为其他用户创建密钥）
# - sts:AssumeRole（担任权限更高的角色）
# - glue:CreateDevEndpoint + iam:PassRole（使用管理员角色的 Glue）
```

### 步骤 3：使用 PMapper 绘制权限提升图

使用 Principal Mapper 构建所有 IAM 主体的图谱并识别提升边。

```bash
# 收集 IAM 数据用于图谱构建
pmapper graph create --account ACCOUNT_ID

# 查询到管理员的路径
pmapper query 'who can do iam:AttachUserPolicy with * on *'
pmapper query 'who can do sts:AssumeRole with arn:aws:iam::ACCOUNT:role/AdminRole'

# 找出所有可以提升到管理员的主体
pmapper analysis

# 可视化权限提升图谱
pmapper visualize --filetype png

# 检查特定提升路径
pmapper query 'can arn:aws:iam::ACCOUNT:user/test-user do iam:CreatePolicyVersion with *'
pmapper query 'can arn:aws:iam::ACCOUNT:user/test-user do sts:AssumeRole with arn:aws:iam::ACCOUNT:role/*'
```

### 步骤 4：测试跨账户角色担任

评估跨账户信任策略中配置错误的角色担任，这些错误可能允许未授权的权限提升。

```bash
# 列出所有角色及其信任策略
aws iam list-roles --query 'Roles[*].[RoleName,Arn]' --output text | while read name arn; do
  trust=$(aws iam get-role --role-name "$name" --query 'Role.AssumeRolePolicyDocument' --output json 2>/dev/null)
  # 检查通配符或宽泛信任
  echo "$trust" | python3 -c "
import json, sys
doc = json.load(sys.stdin)
for stmt in doc.get('Statement', []):
    principal = stmt.get('Principal', {})
    condition = stmt.get('Condition', {})
    if isinstance(principal, dict):
        aws_princ = principal.get('AWS', '')
    else:
        aws_princ = principal
    if '*' in str(aws_princ) or 'root' in str(aws_princ):
        has_external_id = 'sts:ExternalId' in str(condition)
        has_mfa = 'aws:MultiFactorAuthPresent' in str(condition)
        print(f'角色: $name')
        print(f'  主体: {aws_princ}')
        print(f'  需要 ExternalId: {has_external_id}')
        print(f'  需要 MFA: {has_mfa}')
        if not has_external_id and not has_mfa:
            print(f'  警告: 无 ExternalId 或 MFA 条件 - 存在混淆代理风险')
" 2>/dev/null
done

# 测试角色担任
aws sts assume-role \
  --role-arn arn:aws:iam::TARGET_ACCOUNT:role/CrossAccountRole \
  --role-session-name privesc-test \
  --duration-seconds 900
```

### 步骤 5：使用 CloudFox 枚举攻击路径

使用 CloudFox 识别额外的攻击面，包括基于资源的策略和特定服务的提升路径。

```bash
# 运行所有 CloudFox 检查
cloudfox aws --profile target-account all-checks -o ./cloudfox-output/

# 特定权限提升检查
cloudfox aws --profile target-account permissions
cloudfox aws --profile target-account role-trusts
cloudfox aws --profile target-account access-keys
cloudfox aws --profile target-account env-vars  # Lambda 环境变量中的密钥
cloudfox aws --profile target-account instances  # 带实例配置文件的 EC2
cloudfox aws --profile target-account endpoints  # 暴露的服务
```

### 步骤 6：记录发现和修复建议

整理所有发现的提升路径，包含概念验证步骤和修复建议。

```bash
# 生成综合报告
cat > privesc-report.md << 'EOF'
# AWS 权限提升评估报告

## 已测试的提升向量

| 向量 | 状态 | 起始主体 | 提升至 | 风险 |
|--------|--------|--------------------|--------------|------|
| iam:CreatePolicyVersion | 可利用 | test-user | AdministratorAccess | 严重 |
| iam:PassRole + lambda:CreateFunction | 可利用 | dev-role | LambdaAdminRole | 严重 |
| sts:AssumeRole（跨账户） | 可利用 | test-user | ProdAdminRole | 高 |
| iam:AttachUserPolicy | 已阻止 | test-user | N/A | N/A |
| ec2:RunInstances + iam:PassRole | 已阻止 | test-user | N/A | N/A |

## 修复建议
1. 对所有 IAM 用户和角色应用权限边界
2. 从非管理员主体移除 iam:CreatePolicyVersion
3. 为所有跨账户角色信任策略添加 sts:ExternalId 条件
4. 实施 SCP 护栏，阻止权限提升操作
EOF
```

## 核心概念

| 术语 | 定义 |
|------|------|
| IAM 权限提升（IAM Privilege Escalation） | 利用过度宽松的 IAM 策略，获取比原本授予主体更高级别的访问权限 |
| 权限边界（Permission Boundary） | 设置主体最大权限的 IAM 策略，无论其附加的基于身份的策略如何 |
| iam:PassRole | 允许主体将 IAM 角色传递给 AWS 服务的 IAM 操作，使服务能够以该角色的权限行事 |
| 混淆代理（Confused Deputy） | 攻击者欺骗受信任服务代表其执行操作的攻击，通过无外部 ID 验证的跨账户角色担任实现 |
| 服务控制策略（Service Control Policy） | AWS Organizations 策略，为成员账户设置最大权限，提供防止权限提升的护栏 |
| Principal Mapper | 将 IAM 主体及其提升路径建模为有向图进行分析的开源工具 |

## 工具与系统

- **Pacu**：AWS 利用框架，拥有 21+ 个权限提升模块，用于自动化检测和利用
- **Principal Mapper**：基于图谱的 IAM 分析工具，映射主体之间的提升路径
- **CloudFox**：以攻击者视角识别攻击路径的 AWS 枚举工具
- **IAM Policy Simulator**：AWS 原生工具，用于针对特定 API 操作测试有效权限
- **AWS Access Analyzer**：识别授予外部访问权限的资源策略并验证 IAM 策略变更的服务

## 常见场景

### 场景：具有 iam:CreatePolicyVersion 的开发者角色导致管理员访问

**场景背景**：在已授权评估期间，测试人员发现一个开发者角色具有 `iam:CreatePolicyVersion` 权限，该权限允许创建具有任意权限的任何客户管理策略的新版本。

**方法**：
1. 使用 Pacu 中的 `iam__enum_permissions` 枚举附加到开发者角色的策略
2. 识别出该角色可以对其自身附加的策略调用 `iam:CreatePolicyVersion`
3. 创建一个具有 `"Action": "*", "Resource": "*", "Effect": "Allow"` 的新策略版本
4. 将新版本设置为默认策略版本
5. 通过调用 `iam:ListUsers`、`s3:ListBuckets` 等验证管理员访问
6. 记录提升链，建议移除 `iam:CreatePolicyVersion` 并实施权限边界

**常见陷阱**：AWS 将托管策略限制为 5 个版本。如果已有 5 个版本，必须先删除一个版本才能创建新版本。始终记录原始默认版本以便清理时恢复。如果权限边界配置正确，可以阻止此提升，因此在声明发现前先验证边界策略。

## 输出格式

```
AWS 权限提升评估报告
=============================================
账户: 123456789012（生产环境）
评估日期: 2026-02-23
起始主体: arn:aws:iam::123456789012:user/test-user
起始权限: S3 只读、Lambda 调用、EC2 描述
授权: CISO 签署，项目编号 #PT-2026-014

发现的提升路径: 4

[PRIVESC-001] iam:CreatePolicyVersion -> 管理员
  严重程度: 严重
  起始权限: policy/dev-policy 上的 iam:CreatePolicyVersion
  提升方式: 创建版本 6，设置 Action:* Resource:*
  利用时间: < 2 分钟
  修复建议: 移除 iam:CreatePolicyVersion，应用权限边界

[PRIVESC-002] iam:PassRole + lambda:CreateFunction -> LambdaAdminRole
  严重程度: 严重
  起始权限: iam:PassRole, lambda:CreateFunction
  提升方式: 使用 AdminRole 创建 Lambda 函数，调用以获取管理员凭据
  利用时间: < 5 分钟
  修复建议: 使用条件键将 iam:PassRole 限制到特定角色 ARN

[PRIVESC-003] sts:AssumeRole -> 跨账户管理员
  严重程度: 高
  起始权限: sts:AssumeRole（arn:aws:iam::987654321098:role/SharedRole）
  提升方式: 角色信任策略允许源账户中的任何主体
  修复建议: 添加 sts:ExternalId 条件，将 Principal 限制为特定角色

提升路径总计: 4（2 个严重，1 个高，1 个中）
已实施权限边界: 0 / 47 个 IAM 主体
SCP 护栏阻止提升: 0 / 3 个已测试向量
```
