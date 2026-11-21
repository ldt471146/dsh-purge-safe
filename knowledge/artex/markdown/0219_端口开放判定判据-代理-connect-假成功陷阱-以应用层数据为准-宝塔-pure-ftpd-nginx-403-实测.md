# 端口开放判定判据：代理 CONNECT 假成功陷阱 + 以应用层数据为准（宝塔 Pure-FTPd / nginx 403 实测）

- **code**: 端口开放判定判据-代理-connect-假成功陷阱-以应用层数据为准-宝塔-pure-ftpd-nginx-403-实测
- **kind**: template
- **category**: recon
- **component**: 宝塔主机端口复验（Pure-FTPd / nginx phpMyAdmin 端口）
- **severity**: info
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-06 在 203.0.113.126 实测：经 127.0.0.1:7892 —— **21 真开**（`220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------` / `No anonymous login`）、**888 真开**（nginx 403 548B，`/pma`、`/phpmyadmin/`、`/PMA/`、无斜杠、XFF 伪造全 403）、22/3306/8888/843/5432 零字节。**三项对照实验钉死结论**：① `github.com:22` 经 SOCKS5 与 HTTP CONNECT **两条通道都零字节** ⇒ 代理节点屏蔽 22，故目标 22 记"不可判定"；② `db4free.net:3306` 回 **DATA(90)** `11.8.9-MariaDB-log … mysql_native_password` ⇒ 代理能转发 3306，故目标 3306 零字节=目标侧不响应；③ 目标 `:888` 回 nginx 403 ⇒ 代理能转发高端口，故目标 8888 零字节=目标侧不响应。另：VPS 出口 203.0.113.55 直连 22/80/443/2222/8080/3389 全超时、经代理 CONNECT 假成功零字节；免费代理池 2286 候选 / 276 验活全部不可用于非标端口（Squid 回 `403 Proxy Error`）。
- **path**: pocs/端口开放判定判据-代理-connect-假成功陷阱-以应用层数据为准-宝塔-pure-ftpd-nginx-403-实测/poc.py
- **tags**: 端口复验,CONNECT假成功,应用层判据,宝塔,Pure-FTPd,phpMyAdmin,IP白名单,免费代理不可用,换出口
- **created_at**: 2026-10-06T12:13:11.323Z
- **found_by**: exploit

## 描述

经 HTTP 代理判定远端端口是否真开时，"CONNECT 200"是假判据（代理常假成功）。本条目给出"以应用层数据为准"的探针代码、宝塔 Pure-FTPd/phpMyAdmin 的坑、FTP 字典来源、以及换出口复核的正确做法。

## 用法

```
【第一步先证代理能力，再判目标端口】FOFA 说某端口开着、直连 nmap 说 filtered 时按本流程：
1) 找三个对照，先钉死"通道是否可用"：
   · 判 22 → 用 `github.com:22`（公网 SSH 必回 `SSH-2.0-` banner）；若它也零字节，说明**代理节点屏蔽 22**，目标 22 一律记"不可判定"。
   · 判 3306 → 用 `db4free.net:3306`（公开 MySQL 测试服务，必回 greeting 如 `11.8.9-MariaDB-log`）。
   · 判 8888/888 类高端口 → 用目标上任何**已知真开**的同类端口（本例 `:888` 回 nginx 403）。
2) 对照全有数据、目标端口零字节 ⇒ **目标侧不响应**（未监听/防火墙/面板 IP 白名单），换代理节点无用（墙在目标侧）。
3) 对照也零字节 ⇒ 是**我们这侧通道**的问题，别急着写"端口关闭"。
【应用层判据表】21→`220` Pure-FTPd/vsftpd banner；22→`SSH-2.0-`；3306→MySQL greeting；8888→HTTP 响应（宝塔 `Bt-Panel`/登录表单）。零字节 = 不可确认。
【宝塔实战】21 FTP 用户名枚举不可行（MySQL 虚拟用户，存在/不存在同一条 530，判据只有 230）；888 端口的 403 是真 IP 白名单（`/pma`、`/phpmyadmin/`、`/PMA/`、无斜杠、XFF 伪造全部无效，别烧包）；3306/8888 常被宝塔限制为仅本机 + 防火墙只放 80/443/21/888 ⇒ **优先从 Web 与 FTP 面找口子，别把预算压在端口爆破上**。
【本次实测终局】203.0.113.126：21 真开（12 对全 530）、888 真开（403 白名单）、3306/8888 目标侧不响应、22 不可判定（代理屏蔽）。
```

## 正文

```
## 一、核心陷阱：HTTP 代理的 CONNECT "假成功"
很多 HTTP 代理（含常见机场客户端）对**任意** `CONNECT host:port` 都回 `HTTP/1.1 200 Connection established`（SOCKS5 模式则回 `request granted`），但**实际并不转发**，表现为"连上之后零字节"。

⇒ **绝对不要用"CONNECT 成功"判定端口开放**。唯一可靠的判据是：**目标端口有没有主动吐出应用层数据**。

| 端口 | 打开时必然出现的应用层数据（无需我们发任何请求） |
|---|---|
| 21 FTP | `220 ... ` Pure-FTPd/vsftpd banner（宝塔 = `220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------`） |
| 22 SSH | `SSH-2.0-OpenSSH_x.y` banner |
| 3306 MySQL | MySQL greeting（首字节是可读协议版本 + 版本号字符串） |
| 8888 宝塔 | 需主动发 HTTP 请求，看是否回宝塔登录页 |
| 888 phpMyAdmin | 需主动发 HTTP 请求（宝塔默认配置对外返回 nginx `403 Forbidden`） |

## 二、可直接复用的探针（Python，经 HTTP 代理）
```python
import socket
def probe(host, port, http=False, proxy=("127.0.0.1",7892), timeout=12):
    s = socket.create_connection(proxy, timeout=timeout)
    s.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nProxy-Connection: Keep-Alive\r\n\r\n"
               % (host, port, host, port)).encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(1024)
        if not d: break
        buf += d
    head, _, rest = buf.partition(b"\r\n\r\n")
    if b"200" not in head.split(b"\r\n")[0]: return ("REFUSED", head[:80])
    data = rest
    if http:
        s.sendall(("GET / HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                   % (host, port)).encode())
    s.settimeout(6 if not http else timeout)
    try:
        while len(data) < 4000:
            d = s.recv(1024)
            if not d: break
            data += d
    except socket.timeout:
        pass
    return ("OPEN" if data else "NO-DATA(可能代理假成功/目标过滤)", data[:300])
```
- 判定：`OPEN` + 能读出 banner/HTTP 头 = **真开**；`NO-DATA` = **不可确认**（不要写成"关闭"）。

## 三、FTP（宝塔 Pure-FTPd）的坑
- 宝塔的 Pure-FTPd 用 **MySQL 虚拟用户**后端，**存在与不存在的用户名都回同一条 `530 Login authentication failed`** ⇒ **无法用响应差异枚举用户名**，只能直接试口令。
- 实测 12 对失败（`1113060.1113060a0.top`/同名、`1113060`、`moh6hrwx4t`、`admin`、`www1113060`、`1113060a0`、`example.com`、`8886060bdh1.shop`、`ftp`/123456、`www`/123456）；**判据只有 `230` 才算通**。
- 字典正确来源（按依据强度）：宝塔站点**根目录名**（如 `/www/wwwroot/1113060.1113060a0.top` → 账号常同名）> 域名段 > 面板/系统名。
- FTP 一旦能登且能写 web 目录 ⇒ **直接 PUT `.php` 马 = WebShell**，绕过所有 HTTP 层白名单。

## 四、888（宝塔 phpMyAdmin 端口）的坑
整站 `403 Forbidden`（nginx 的 IP 白名单）。已实测无效的绕过：`/pma`、`/phpmyadmin/`、`/PMA/`、`/pma` 无斜杠、`X-Forwarded-For/X-Real-IP/Client-IP: 127.0.0.1`。
⇒ 这类 403 是**真白名单**（nginx `allow/deny` 不看 XFF，除非配了 real_ip）。**别在这上面继续烧包**。

## 五、换出口复核的正确做法
- **免费代理池不可用**：Squid 类代理默认**禁止 CONNECT 到非 443 端口**（返回 `403 Proxy Error`），其余多为超时；实测 2286 个候选、276 个"验活"，无一能用于非标端口探测。
- 正确做法：**用自有 VPS 做出口**，优先 VPS 直连 `nmap -sT -Pn -p 21,22,80,443,3306,888,8888 <host>`；VPS SSH 不通时用 `ssh -D 1080` 建 SOCKS 或经代理建 CONNECT 隧道（ProxyCommand）。
- 复核的价值：**区分"目标侧防火墙/宝塔 IP 白名单"与"本机出口路径问题"**——同一台机器上 21 与 888 能通、3306/8888 零字节，说明代理本身能转发非标端口，则 3306/8888 更可能是**目标侧只放行特定来源**（宝塔面板默认支持"面板 IP 白名单"）。
```
