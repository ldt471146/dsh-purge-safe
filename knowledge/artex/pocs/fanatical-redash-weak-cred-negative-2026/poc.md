## 复核范围与证据
- 信道：https://redash.fanatical.com（DNS 即源站 107.21.85.212，无 CDN/CF）与 bi.fanatical.com 源站直连（--noproxy '*' --resolve bi.fanatical.com:443:107.21.85.212 -H 'Host: bi.fanatical.com'），两者同一登录页（200/2239B，nginx/1.9.10）。
- 登录协议：GET /login → csrf_token cookie + session cookie + hidden csrf_token（同值，可复用）；POST /login 表单 email/password/csrf_token/remember=on。
- 组合：14,300（A 2700 + B 8800 + C 1200 + D 800 + E 800）+ 补充 500 = 14,800 唯一对；全部 HTTP 200 "Wrong email or password."，零 302、零异常、零 429/403/超时；无锁定。
- 时序：疑似存在账号 vs 随机不存在邮箱中位数 0.093–0.111s，无区分（无用户枚举 oracle）。
- 旁证：/api/session、/api/users、/api/data_sources、/api/queries、/api/dashboards 未认证 404；/api/config 匿名 200（googleLoginEnabled=true, ldapLoginEnabled=false）；登录页 email 回显经 Jinja2 转义（无 XSS）。
- 产物：/opt/artex/data/tasks/5/i3052/brute.log、hits.txt(未生成)、anomalies.jsonl(未生成)。