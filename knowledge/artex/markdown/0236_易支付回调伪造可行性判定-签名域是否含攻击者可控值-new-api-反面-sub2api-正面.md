# 易支付回调伪造可行性判定（签名域是否含攻击者可控值）——new-api 反面 / sub2api 正面

- **code**: 易支付回调伪造可行性判定-签名域是否含攻击者可控值-new-api-反面-sub2api-正面
- **kind**: poc
- **category**: auth-bypass
- **component**: 易支付/EasyPay 兼容网关回调（go-epay 系）
- **severity**: critical
- **language**: http
- **source**: manual
- **verified_note**: 反面（new-api）已在真实目标 example.com 实测：差分 A=success、B=fail，下单 13 字段注入全部被忽略 → 判定不可利用。补充：核对 new-api 全历史（2023-08-14 "add epay" → main），`EpayRequest` 结构体从未包含 ReturnUrl 字段，return_url 始终由 constant.ServerAddress / paymentReturnPath() / GetCallbackAddress() 服务端生成 ⇒ 任何版本的 new-api 都不受此链影响，不必再逐版本试。正面（sub2api）仅在本地 fixture 单测验证，未在真实 sub2api 站点复现。
- **path**: pocs/易支付回调伪造可行性判定-签名域是否含攻击者可控值-new-api-反面-sub2api-正面/easypay-forgery-triage.md
- **tags**: payment,webhook,signature,parameter-smuggling,easypay,new-api,sub2api,triage
- **created_at**: 2026-10-06T12:31:54.938Z
- **found_by**: exploit

## 描述

易支付/聚合支付「伪造回调入账」的可行性判定法。核心不是签名算法强弱，而是**下单侧签名域里有没有攻击者可控字节**。给出 3 步判定（判栈 → 差分测试 → 走私窗口判定）与正反两侧的实测结论。

## 用法

```
1) `curl -sI https://TARGET/ | grep -i new-api` 判栈；2) 用浏览器/接口下单取 `data.sign`；3) 打差分 A/B：`curl -X POST https://TARGET/api/user/epay/notify -d '<原样参数集>&sign=<S>'` 应回 success，追加 `&trade_status=TRADE_SUCCESS` 应回 fail；4) 把 return_url 等字段注入下单请求，比对响应签名参数集是否变化。变化=可打，不变=该链不适用。
```

## 正文

```
# 判定流程（3 步，10 分钟内出结论）

## 1. 判栈（决定走哪条链）
- sub2api：无 `x-new-api-version`；有 `/api/v1/payment/webhook/easypay`。
- new-api（QuantumNous）：`x-new-api-version: main-<hash>`、`/api/status` 可读、回调在 `/api/user/epay/notify`。

## 2. 差分测试（无认证，直接打回调）
用自己下单拿到的**合法签名**（下单响应 `data.sign` 就回给客户端，两种栈都暴露）：
A) 原样参数集 + sign → new-api 回 `success`（验签过但 trade_status 空 → 忽略事件，不入账）
B) A + 顶层 `trade_status=TRADE_SUCCESS` → `fail` ⇒ trade_status 在签名域内，不能靠加参数绕过

## 3. 走私可行性判定（唯一决定成败的一步）
签名原文是 `k=v&k=v...&<key尾>` 裸拼接、值不转义。含真实 trade_status 键时它在排序中落在 `return_url` 与 `type` 之间 ⇒ 下单侧串里 `return_url=` 之后必须紧跟 `&trade_status=TRADE_SUCCESS` ⇒ **下单侧 return_url 的值末尾必须可被攻击者塞入这串字节**。

验证方法：把 return_url / notify_url / name / money / device / out_trade_no / pid / trade_status 全塞进下单请求，看响应签名参数集是否变化。变了=可打；一个都没变=签名域服务端固化=该链死。

# 宿主清单（2026-10 核实）

## ✅ 可复现（客户端可控 return_url）
- **Wei-Shaw/sub2api**：`backend/internal/payment/provider/easypay.go`。`resolveURLs(req)` 取 `req.ReturnURL`；`CanonicalizeReturnURL` 只清 Fragment、保留 query；`buildPaymentReturnURL` 用 `query.Encode()` 排序 → trade_status 恰落在 return_url 值末尾；`VerifyNotification` 无白名单/无重复键检测。popup 模式签名暴露在下单响应里。
- **TokenFlux/TokenRouter**：sub2api 逐字 fork（同路径同实现），同样可控。
- **wenyi401/ikik-api**：sub2api fork（`backend/internal/payment/provider/easypay.go` 同构）。
- **kakui-lau/token-boat**（new-api 二开）：`controller/topup.go` 的 `EpayRequest` 带 `ReturnURL string `json:"return_url,omitempty"``，非空即覆盖 `paymentReturnPath()`，仅过 `validatePaymentRedirectURL`（需确认只校验 scheme/host/path、保留 query）。回调是 go-epay `client.Verify` → 同一条走私链。

## ❌ 不可复现
- **QuantumNous/new-api 官方**：全历史（2023-08-14 "add epay" → main）`EpayRequest` 从未有 ReturnUrl 字段；`return_url = paymentReturnPath()` = `system_setting.ServerAddress + suffix`，`notify_url = service.GetCallbackAddress() + ...`（`CustomCallbackAddress || ServerAddress`）全服务端配置。已在 example.com 实测 + 源码双证。

## ⚠️ 待判定（把 args.ReturnUrl 传给网关，需看调用方是否用客户端值）
MartialBE/one-hub、deanxv/done-hub（`payment/gateway/epay/client.go`）、topjohncian/cloudreve-epay、ai365vip/chat-api（`epay/order.go`）、hjxwz123/Aivory（`return_url: req.SuccessURL`）、ddcat-ai/open-ai-canvas（`backend/payment-plugins/epay.go`）、linux-do/credit（EPayRequest 带 ReturnURL binding）。

# 同一效果的其他路径（不走走私也能伪造入账）
1) pkey 泄露/弱 key → 直接签名任意回调；2) 完全不验签的自研实现 → 直接 POST `trade_status=TRADE_SUCCESS`；3) 只验子集的实现 → 加字段不破坏签名；4) 金额以回调为准不比对本地订单 → 改 money；5) 无幂等/无状态校验 → 重放；6) 跨网关回调错配（new-api 2026-04-24 才加 PaymentProvider 字段修复，老版本二开值得看）。

# 结论模板
- 签名域内有攻击者可控值 → 按 sub2api #7875 链打（下单塞 `?trade_status=TRADE_SUCCESS` → 回调把该键提升为顶层 → 复用下单 sign）。
- 签名域全服务端固化 → 该目标不受此链影响，转其它攻击面。
```
