# Fanatical 边缘 Worker 的 magic/summon 免 reCAPTCHA 豁免不可迁移到 login/register（负面情报，dot-segment 全矩阵实测）

- **code**: fanatical-worker-magic-summon-exemption-not-migratable
- **kind**: poc
- **category**: auth-bypass
- **component**: Cloudflare Worker + Heroku (fanatical.com)
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 task#5 intent#3279 实测：www.fanatical.com 边缘（干净出口）与 ws15 源站直连（--noproxy --resolve 3.33.161.45 + Host ws15 + XFH www + 唯一 XFF）对同 payload 逐条对照 23 组 dot-segment/编码/混合归一化变体（matrix.tsv/edge_clean.tsv 落盘）：全矩阵 2xx 仅 magicSummoned 22B（etag W/"16-8O9Ukq5O+VaQJHN3DBBoVAzdA/c"），login/register 恒 202/90、202/97，零 Set-Cookie、零 atok；/api/auth/magic/summon/../login 双端 404/0（未归一化进 login）。NEL 同秒 s= 4/4 轮边缘 magic/summon 与 ws15 /api/basket 完全一致（如 s=4wmYwE… ts=1794435389），真实边缘 200 s=XcmGm… ts=1794435628 与同秒 basket 3/3 相同；同秒对照 ws15 vs admin 的 s= 不同 → 边缘该路由就是 ws15 同一 Heroku app，无独立内部 auth app。fact#3329（confirmed）与 #3248（confirmed）。
- **tags**: fanatical,cloudflare-worker,heroku,recaptcha,nel,dot-segment,negative
- **created_at**: 2026-11-11T22:23:03.811Z
- **engine**: https://www.fanatical.com/api/auth/magic/summon

## 描述

结论：边缘 /api/auth/magic/summon 的 200 {"magicSummoned":true} 是 Worker 路由专用行为（etag W/"16-8O9Ukq5O+VaQJHN3DBBoVAzdA/c"、expires:0、via:2.0 heroku-router、x-is-cf-worker:1），login/register 经边缘仍恒 202 reCaptcha；用 dot-segment/编码/大小写/尾斜杠/多重归一化变体无法构造「Worker 认 magic、源站路由到 login/register」的差异：归一化后等于 magic/summon 的路径（如 /api/auth/login/../magic/summon）只在 Edge 得 200 magicSummoned（源站同路径 404/0），其余全部边缘 404/0 或 CF WAF 403；Worker 对未命中 magic 的路径按原样回源，Express 不做 dot-segment 归一化。NEL report-to 的 s= 为 per-app 指纹（同秒同 app 相同、跨 app 不同），边缘 magic 与 ws15 /api/basket 同秒 s= 全等 → 同一 Heroku app，无独立内部 auth app。

## 用法

```
复测/复用要点：(1) 边缘需换干净出口——默认平台出口在 /api/auth/* 被源站限流 429 空体；可复用本次验证可用的 21 个免费代理（111.192.28.24:8888、111.192.30.181:8888、114.244.223.68:8888、114.249.226.92:8888、114.249.235.119:8888、114.250.195.71:8888、123.119.176.120:8888、123.119.179.34:8888、123.121.101.115:8888、123.121.121.123:8888、123.121.122.125:8888、123.121.125.220:8888、123.121.73.146:8888、123.121.99.174:8888、221.221.164.42:8888、222.128.160.142:8888、222.128.171.2:8888、222.128.178.134:8888、222.129.142.219:9000、58.33.109.114:2021、61.149.134.158:8888）。(2) 判据命令：curl -sk --path-as-is --proxy http://<IP:PORT> -A "$ARTEX_UA" -H "anonid: <UUIDv4>" -H "content-type: application/json" -H "Origin: https://www.fanatical.com" -X POST -d '{"email":"x@example.com","password":"WrongPass123!"}' -D - https://www.fanatical.com/api/auth/login/../magic/summon → 200/22 magicSummoned 即 Worker 归一化命中 magic 分支（无会话）；https://www.fanatical.com/api/auth/magic/summon/../login → 404/0。(3) 上游同一性：同秒对比 report-to 的 s= 与 ts=，边缘 magic 与 ws15 /api/basket 应完全相同；sid 是账户级不可用。
```
