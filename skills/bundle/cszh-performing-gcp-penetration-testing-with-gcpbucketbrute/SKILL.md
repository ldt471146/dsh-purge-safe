---
name: cszh-performing-gcp-penetration-testing-with-gcpbucketbrute
description: 使用 GCPBucketBrute 执行 GCP 安全测试，进行存储桶（Storage Bucket）枚举、gcloud IAM 权限提升路径分析和服务账号权限审计。
---

> 本技能源自中文网络安全技能库 killvxk/cybersecurity-skills-zh（上游目录 performing-gcp-penetration-testing-with-gcpbucketbrute），正文按中文原文照录。

**这个技能干什么**：使用 GCPBucketBrute 执行 GCP 安全测试，进行存储桶（Storage Bucket）枚举、gcloud IAM 权限提升路径分析和服务账号权限审计。

**什么时候用**：需要按上游中文方法论执行「performing-gcp-penetration-testing-with-gcpbucketbrute」对应任务时加载本技能。

**关键工具**：见正文各章节列出的命令与工具清单。

# 使用 GCPBucketBrute 执行 GCP 渗透测试

## 概述

本技能涵盖使用 GCPBucketBrute 进行 Google Cloud Platform（GCP）安全测试，包括存储桶枚举和访问权限测试，结合 gcloud CLI IAM 枚举以识别权限提升（Privilege Escalation）路径。该方法测试公开可访问的存储桶、过度宽松的 IAM 绑定以及服务账号（Service Account）密钥暴露情况。

## 前置条件

- Python 3.8+ 及 google-cloud-storage 库
- 从 RhinoSecurityLabs GitHub 安装的 GCPBucketBrute
- 使用测试凭据认证的 gcloud CLI
- 目标 GCP 项目已获授权的渗透测试范围
- google-api-python-client 和 google-auth 库

## 步骤

1. **枚举存储桶** — 使用 GCPBucketBrute 通过关键词排列组合发现可访问的 GCP 存储桶
2. **测试存储桶权限** — 对每个发现的存储桶调用 TestIamPermissions API，确定读/写/管理员访问级别
3. **审计 IAM 绑定** — 枚举项目级别的 IAM 策略，识别过度宽松的角色绑定
4. **检查服务账号密钥** — 识别具有用户管理密钥的服务账号，并测试通过模拟（Impersonation）进行权限提升的可能性
5. **测试权限提升路径** — 检查 iam.serviceAccounts.actAs、setIamPolicy 及其他权限提升向量
6. **生成发现报告** — 输出带有风险严重级别评级的结构化安全评估报告

## 预期输出

- 包含权限级别的已发现存储桶 JSON 报告
- IAM 权限提升路径分析
- 服务账号安全评估
- 带有修复建议的风险评分发现
