# PHPWind 7.3.2 后台 example.com 锁定被 X-Forwarded-For 绕过（db_xforwardip=1 时）+ per-source CC 封禁才是爆破真正瓶颈

- **code**: phpwind-7.3.2-admin-lock-bypass-xff
- **kind**: poc
- **category**: weak-password
- **component**: PHPWind 7.3.2
- **severity**: medium
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-16 在 https://example.com/bbs（PHPWind 7.3.2 GBK/宝塔）经 SOCKS5 127.0.0.1:7892 实测：交替 XFF(203.0.113.27/203.0.113.128) 连发 8 次后台登录失败请求，回显恒为「密码或安全问题错误,您还可以尝试15次」(8/8)；固定同一 XFF 则 15→14→13…递减。证明计数键=服务端最近一次感知 IP 单槽、XFF 被采信(db_xforwardip=1)。附带：admin_name 无 SQLi；约 40 个 POST 后源 IP 被站点 CC/WAF 对 80/443 封禁(000)，数分钟未恢复。
- **tags**: phpwind,7.3.2,后台爆破,XFF,锁定绕过,per-source CC,db_xforwardip
- **created_at**: 2026-10-15T16:48:19.680Z

## 描述

PHPWind 7.x 后台 example.com 失败锁定(默认15次/1200s)在 db_xforwardip=1 时按 X-Forwarded-For 计"来源IP"，且为"最近一次感知IP"单槽：交替两个伪造 XFF 即把计数重置为满额，锁定形同虚设。但真正的吞吐瓶颈是站点应用层 CC/WAF 的 per-source 封禁(约40包/窗口)。

## 用法

```
1) 先探 XFF 是否被采信：POST /bbs/example.com?&verify=<页面formhash>&  body=Login_f=1&admin_name=<用户>&admin_pwd=<错>
   固定同一 XFF 连发看剩余次数是否递减；再交替两个 XFF 连发，若恒为满额(如15)即绕过成立。
2) 判定：主站须能直达；POST 返回 body 含「密码或安全问题错误,您还可以尝试N次」。
3) 关键坑：db_xforwardip=1 才成立（同产品 8.7 站群常为 0，此时 XFF 无效，见 KB id139）。凡先探。
4) 关键坑：站点 CC/WAF 按源 IP 封禁(约40包后 80/443 全 000)，XFF 无法救——要持续爆破必须多出口轮换(chrome-bridge/VPS/代理池)，单出口每窗口仅数十次。
5) 配套：前台 /bbs/login.php 用户存在性 oracle（POST step=2&pwuser=X&pwpwd=错&verify=<login页verifyhash>）：回「用户X 不存在」vs「密码错误或安全问题错误,您还可以尝试N次」→ 零成本枚举真实管理员名，喂给后台定向爆破。
```
