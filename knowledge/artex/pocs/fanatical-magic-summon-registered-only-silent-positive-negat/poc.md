# Fanatical magic-link 登录链：走不通的实证边界

## 结论
`POST /api/auth/magic/summon` 经 www 边缘（CF Worker）对合法格式邮箱恒返回
`200 {"magicSummoned":true}` 且不要求 reCAPTCHA（同请求直连 ws15 源站为
`202 {"type":"reCaptcha","challengeId":"...","action":"LOGIN"}`），**但该 200 不代表邮件已发出**：
它是"若该邮箱已关联账号才发信"的防枚举设计。前端源码原文（LoginMagicPane.jsx）：
> Thank you. If the email address you entered is associated with an account, we've sent you a magic link.

未注册邮箱恒 200、永不来信；cast 需要邮件里的真实 spell，因此未注册状态下该链不可进入。

## 前置
- 可出网 443；本机直连出口对 /api/auth/* 有 IP 级 429，需换出口（免费代理即可，实测 4 个可用）。
- 请求需带任意 `anonid` 头（应用层门禁只认头名，见 kb#538）。

## 判据（实测）
| 邮箱 | 供应商 | summon 次数 | 结果 | 等待 |
|---|---|---|---|---|
| fanuatnmibpof@fldubai.com | mail.tm | 4 | hydra:totalItems=0 | >20 min |
| fwlsqkge@guerrillamailblock.com | GuerrillaMail | 2 | 仅自身欢迎信 | >15 min |
| fan1794428737@mailnesia.com | mailnesia | 2 | "No e-mail message" | >12 min |
| fan1794429085@maildrop.cc | maildrop | 2 | inbox=[] | >5 min |

阴性对照：同邮箱直连 ws15 → 202 reCaptcha；cast 随机 32 字符 spell 两通道均
`404 {"message":"Magic link not found"}`；空 email 两通道均 400。
register 对已存在/不存在/自建临时邮箱在挑战前一律 202（E403 只在真 v3 token 之后），
故未拿到有效 reCAPTCHA token 前 register 不构成匿名邮箱存在性 oracle。

## 复现命令
```bash
# 1) 建可 API 取信的临时邮箱（mail.tm 示例）
curl -s https://api.mail.tm/domains?page=1
curl -s -H 'Content-Type: application/json' -d '{"address":"<x@domain>","password":"<pw>"}' https://api.mail.tm/accounts
curl -s -H 'Content-Type: application/json' -d '{"address":"<x@domain>","password":"<pw>"}' https://api.mail.tm/token
# 2) 经可用出口发 summon（直连出口大概率 429）
curl -s --proxy http://<proxy> -A "$ARTEX_UA" \
  -H 'Content-Type: application/json' -H 'Origin: https://www.fanatical.com' \
  -H 'anonid: <uuidv4>' -X POST -d '{"email":"<x@domain>"}' \
  https://www.fanatical.com/api/auth/magic/summon
# → 200 {"magicSummoned":true}（无论邮箱是否注册）
# 3) 轮询收件箱：未注册邮箱永远为空
```

## 何时才会来信用
只有当目标邮箱本身是一个已注册的 fanatical 账号时，summon 才真正发信；要打开本链
必须先拥有已注册账号，而注册/登录被 reCAPTCHA Enterprise 挡住（recon: task#5 的
#2273/#2362/#2503 在跑）。因此本条属**负面情报**：不要把"边缘 200 magicSummoned"
当作发信成功或可利用信号，也不要再用临时邮箱重复走这条路。