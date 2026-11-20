# MySQL 3306 对外暴露但按 IP 白名单拒绝连接：三出口交叉复现与「能连/不能登」分层判据

- **code**: mysql-3306-exposed-host-not-allowed-ip-whitelist-three-egres
- **kind**: poc
- **category**: info-leak
- **component**: MySQL 5.x/8.x（监听 3306）
- **severity**: low
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-02 于 task#613（192.0.2.11，168six 站群源站）实测：经 socks5 出口 192.0.2.12:10808 与 192.0.2.13:10808、以及本机直连出口 192.0.2.14，三条路径均收到 74 字节明文 ERR "Host '<出口IP>' is not allowed to connect to this MySQL server"；同一时刻对 80 端口 curl 返回 200 / 0.25s 作阳性对照，排除网络故障。判定成立：3306 对外暴露，但服务端按 IP 白名单在鉴权前拒绝，本阶段拿不到 version 与账号面。证据落盘 p3306.bin / p3306c.bin / p3306d.bin。
- **path**: pocs/mysql-3306-exposed-host-not-allowed-ip-whitelist-three-egres/poc.sh
- **tags**: mysql,3306,ip-whitelist,host-not-allowed,info-leak,judgement,negative,egress-ip,ssrf-pivot
- **created_at**: 2026-11-02T11:14:27.699Z
- **engine**: 192.0.2.11:3306
- **found_by**: recon

## 描述

目标 3306 从公网可达（TCP 能建连，服务端主动回 MySQL 明文 ERR 包），但服务端以内置 IP 白名单（mysql.user 的 Host 字段 + skip_name_resolve 语义）限制来源，非白名单出口一律在鉴权前被拒。可用于快速判定「这个库值不值得打」：拒绝文案里回显我方出口 IP ⇒ 通道没问题、是 ACL 拦；同时刻对同主机 Web 端口取对照可排除网络故障。判定为白名单后，直接登录/暴破的收益为零，应转向从白名单段（目标本机/内网）借 SSRF、命令执行、Web 层配置泄露回捡 3306。反向可用性：一旦拿到白名单内的出口或 SSRF，即可直连取库内业务配置（如 cdb_settings.authkey 之类）。

## 用法

```
【前置】能出网的出口（本机直连或 socks5 代理）。要证明是「白名单」而不是「假开/网络坏」，必须换 ≥2 个不同源 IP 各打一次，并在同一时刻对同主机 Web 端口取 200 阳性对照。

【Step1 原始字节收 MySQL 握手前 ERR（必须 --http0.9，否则 curl 当 HTTP 解析报错）】
curl.exe -s --http0.9 --connect-timeout 30 --max-time 25 --proxy socks5://<PROXY1>:10808 http://<TARGET>:3306/ | xxd | head

【Step2 换第二个出口】同上换 <PROXY2>。
【Step3 本机直连对照】curl.exe -s --http0.9 --noproxy "*" --connect-timeout 12 --max-time 18 http://<TARGET>:3306/
【Step4 阳性对照（必做）】同一时刻 curl -s -o /dev/null -w '%{http_code} %{time_total}\n' http://<TARGET>/

【判据（依次）】
1) 返回体是 `\xNN\x00\x00\x00...Host '<出口IP>' is not allowed to connect to this MySQL server`（约 70 余字节，明文），且引号里的 IP 就是本次出口 IP ⇒ TCP 通、服务是 MySQL、拒绝发生在鉴权前、属 IP ACL；
2) 两个出口的 IP 都被回显且都被拒 ⇒ 不是单出口临时封禁，是白名单基线；
3) Step4 对 80 正常 200 且耗时正常 ⇒ 排除我方网络/防火墙；
4) 三个不同出口全拒 ⇒ 宣布「暴露但本阶段不可登录」，停止口令尝试（暴破只会同样得 1130）。

【分层辨伪】
· 只有连接超时/零字节、无 ERR ⇒ 端口假开或被 DROP，不是本条情形；
· 返回 `Access denied for user ... (using password: YES/NO)`（1045）⇒ 白名单已放行，可以做口令/默认账号；
· 客户端报 "Can't connect to MySQL server" ⇒ 是本地客户端解析/代理问题，不是服务端；
· 不写 --http0.9 会得到 curl 的 "Received HTTP/0.9 when not allowed" 之类报错，别误判为服务异常。

【注意】
· 经 socks5 时目标看到的是代理出口 IP，想命中白名单得用白名单段内的代理；本机直连同理。
· 端口暴露本身即泄露「此处有 MySQL」，记一条资产；后续任何 SSRF/命令执行都优先回头打 127.0.0.1:3306 或内网 <db-host>:3306。
```

## 正文

```
## 现象

目标主机监听 3306，公网 TCP 可建连，服务端主动回 MySQL 明文 ERR 包：

```
74B:  46 00 00 00 3f 6a 04 "Host '192.0.2.12' is not allowed to connect to this MySQL server"
```

错误文案里直接回显我方出口 IP —— 这是 mysql 的 ERROR 1130（鉴权前 Host ACL 拒绝），
既证明服务存在，又证明通道正常。

## 复现（Windows / curl.exe，Linux 用 curl 同理）

```bash
# 出口 A（境外 socks5）
curl.exe -s --http0.9 --proxy socks5://192.0.2.12:10808 \
  --connect-timeout 30 --max-time 25 http://<TARGET>:3306/ | xxd

# 出口 B（另一条 socks5，证明不是单出口临时封）
curl.exe -s --http0.9 --proxy socks5://192.0.2.13:10808 \
  --connect-timeout 30 --max-time 25 http://<TARGET>:3306/

# 本机直连（第三出口，绕过代理）
curl.exe -s --http0.9 --noproxy "*" \
  --connect-timeout 12 --max-time 18 http://<TARGET>:3306/

# 阳性对照：同一时刻打 Web 端口
curl.exe -s --noproxy "*" -o NUL -w "%{http_code} %{time_total}\n" http://<TARGET>/
```

## 判读

| 响应 | 结论 |
|---|---|
| 明文 ERR 含 `Host '<我方出口IP>' is not allowed to connect` | TCP 通 + 服务是 MySQL + IP ACL 拒绝（本条） |
| 多出口相同、Web 端口 200 且耗时正常 | 白名单基线成立，非网络故障 |
| `Access denied for user 'x'@'y' (using password: ...)` | ACL 已过，转口令攻击（1045） |
| 超时 / 0 字节 | 端口假开或被 DROP，非本条 |
| curl 报 `HTTP/0.9` 相关错误 | 缺 `--http0.9`，不是服务异常 |

## 判定后的处置

- 本阶段放弃 mysql 客户端暴破（结果必然同样是 1130），只登记「3306 暴露」资产。
- 走迂回：找白名单段内的出口（目标同 C 段/内网），或从目标 Web 应用的 SSRF / 命令执行
  回连 `127.0.0.1:3306`、内网 DB 主机。
- 打进去后的第一目标：`mysql` 库 `user` 表（看还有哪些 Host 放行）、业务库配置表
  （如 cdb_settings 一类，内含 authkey/第三方密钥）。

## 踩坑

- 不加 `--http0.9`：curl 认为响应不是 HTTP，直接报错，容易误判成服务异常。
- 只用一个出口就下结论：无法区分「单 IP 被临时封」与「IP 白名单基线」。
- 没做阳性对照：网络抖动/代理坏掉时同样零字节，容易误报成开放端口。
- 经代理时回显的是代理出口 IP；想命中白名单必须用白名单段内的出口。

```
