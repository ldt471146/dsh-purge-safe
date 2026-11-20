# Wordfence 前置 Cloudflare 时客户端 IP 头不可伪造：XFF/X-Real-IP/True-Client-IP/X-Client-IP 均不被采信，CF-Connecting-IP 伪造被 CF 403 error code 1000

- **code**: wordfence-前置-cloudflare-时客户端-ip-头不可伪造-xff-x-real-ip-true-cli
- **kind**: poc
- **category**: waf
- **component**: Wordfence + Cloudflare
- **source**: self
- **verified**: 1
- **verified_note**: old.retro32.com（WP 7.1.4，Wordfence+Cloudflare）实测：交错 5-arm 对照（各 14 发）中 无头/XFF/X-Real-IP/True-Client-IP/X-Client-IP 的 503 比率齐平（9/5,9/5,8/6,8/6,10/4）；CF-Connecting-IP 伪造 → HTTP403 body "error code: 1000"。
- **tags**: wordfence,cloudflare,ip-spoof,x-forwarded-for,rate-limit,brute-force,cf-connecting-ip,negative
- **created_at**: 2026-11-11T15:47:41.999Z
- **engine**: old.retro32.com

## 描述

结论：WordPress + Wordfence 且前置 Cloudflare 时，不要指望用客户端可控 IP 头伪造「新 IP」绕过按 IP 的登录限流/锁定。Wordfence 的 IP 键取真实来源 IP（CF-Connecting-IP / REMOTE_ADDR），X-Forwarded-For 左值、X-Real-IP、True-Client-IP、X-Client-IP 均无效。且伪造 Cloudflare 保留头 CF-Connecting-IP 会被 CF 边缘直接以 403 error code 1000 拒回。

## 用法

```
判据/排除走的弯路（负面情报）：
1) 想绕过 Wordfence 按-IP 限流时，先做交错 A/B 对照：同一时间窗内轮转「无头 / XFF 每请求唯一 / X-Real-IP 唯一 / True-Client-IP 唯一 / X-Client-IP 唯一」各 N 发，比较 503 比率（200 vs 503）。若各 arm 比率齐平 → 所有这些头都未被采信，别再逐个试。
2) 不要尝试伪造 CF-Connecting-IP：CF 会以 403（body 仅 17 字节「error code: 1000」，有 cf-ray）拒绝，等于暴露自己在伪造。
3) Wordfence 两种拦截页可用页面标题区分：19399B「Your access to this site has been temporarily limited by the site owner」=限流(retry-after:3600)；20076B「You are temporarily locked out」=暴力破解锁定。二者经 CF 出口由源站 PHP 生成（x-powered-by: PHP/8.3.36）。
4) 该限流呈间歇放行（约 50-65% 请求可穿透）且约 5 分钟自解——想继续打口令面只能走慢速重试，而不是靠换 IP/换头。
一行命令样例（判 arm 是否被采信）：
for h in X-Forwarded-For X-Real-IP True-Client-IP X-Client-IP; do ... 每请求该头发唯一值，统计 200 与 503 计数 ...; done  → 比率齐平即未被采信。
```
