# 宝塔 per-source 封禁下的新出口：免费 HTTP 代理池可 CONNECT 任意端口(含 FTP:21)绕开源级拉黑

- **code**: baota-persource-ban-free-proxy-pool-any-port-egress
- **kind**: poc
- **category**: tunnel
- **component**: 宝塔/Pure-FTPd per-source IP 封禁
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-16 在 203.0.113.89:21(宝塔 Pure-FTPd)实测：平台/VPS/HK/直连四个出口均被目标 per-source 拉黑(:22 open 但 :21/:80 filtered)；经 127.0.0.1:7892 抓 proxyscrape+TheSpeedX 免费 HTTP 代理 3227 个，pool_ftp.py 并发验证命中 43 个能 HTTP CONNECT :21 并取到 "220---------- Welcome to Pure-FTPd [privsep] [TLS]" 的全新出口；ftp_attack.py 分布式 1 对/出口，30 个真实响应全 530(hits=0)，证明通道有效而口令不对。控制主机 target418.example.com:21 同批代理正常，排除通道假阴性。
- **tags**: 宝塔,per-source封禁,出口IP,免费代理池,FTP,CONNECT任意端口,绕WAF,新出口
- **created_at**: 2026-10-15T16:45:59.777Z

## 描述

当目标(宝塔)按 socket 源 IP 拉黑 80/443(/21)并放行 22 时，用免费 HTTP 代理池取海量全新出口 IP 破封。关键：① 抓源走本机已有代理(mihomo/ziyoumao 127.0.0.1:7892)最稳，curl 抓 github 需 --ssl-no-revoke(Windows schannel 吊销检查离线会 000)；② 免费 HTTP 代理支持 CONNECT 到任意端口(含 21)，非常适合 FTP 等非 web 协议；③ 每代理约 2~5 请求即被目标拉黑，务必每 2 请求换代理、用目标自身响应验活；④ 免费代理为不可信第三方，凭据/cookie 会被其运营方看到。

## 用法

```
1) curl -sS --ssl-no-revoke -A Mozilla/5.0 -x http://127.0.0.1:7892 https://target289.example.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all -o p.txt；2) 正则取 ip:port 去重；3) 并发对每个代理发 "CONNECT TARGET:21 HTTP/1.1" 读 banner，留 startswith 220 的；4) 用命中的代理每 IP 1 对凭据分布式喷(避免再触发源级封禁)；5) web 面同理可 CONNECT :80/:443。
```
