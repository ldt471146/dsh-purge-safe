# 代理分流造假样本：example.com 经 7892 返回伪造 502/404「hello」

- **code**: 代理分流造假样本-example.com-经-7892-返回伪造-502-404-hello
- **kind**: poc
- **category**: methodology
- **component**: http-proxy / 7892
- **severity**: info
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com 上实测：走 7892 代理返回 502/404 + body "hello"，而 --noproxy 直连及 --resolve 到 4 个解析 IP(203.0.113.101/125/46/84) 全部 conn-fail。代理伪造结论由"唯一可达路径为代理"与"占位体固定为 hello"双重印证。
- **path**: pocs/代理分流造假样本-net.firstworkgoing.art-经-7892-返回伪造-502-404-hello/poc.sh
- **tags**: 代理造假,7892,判定方法论,负结论
- **created_at**: 2026-09-28T10:08:21.611Z
- **found_by**: exploit

## 描述

识别"代理按 Host 分流并返回占位体"的判定方法。本项目已两次因此作废结论，务必先证伪代理再采信响应。判据：同一 URL 走代理有响应、而本机 --noproxy 直连 + --resolve 到全部解析 IP 均连接失败（conn-fail），则该响应是代理伪造；伪造体常为固定占位字符串（本例 "hello"）。

## 用法

```
1) 走代理: curl -s -x http://127.0.0.1:7892 -k -A '<UA>' -w '%{http_code}' https://example.com/api/v1/u/
2) 直连对照(必做): curl -s --noproxy '*' -k -A '<UA>' -w '%{http_code}|%{remote_ip}' https://example.com/api/v1/u/
3) 逐个解析 IP 复核: curl -s --noproxy '*' --resolve example.com:443:<IP> -k https://example.com/api/v1/u/
全部 IP 均 conn-fail 而步骤 1 有响应 => 步骤 1 的响应为代理伪造。
```

## 正文

```
实测记录（2026-09-28）：

# 走代理（7892）——看起来"目标有反应"
$ curl -s -x http://127.0.0.1:7892 -k -A "Mozilla/5.0" -w "\n%{http_code}" https://example.com/api/v1/u/
hello
502
$ curl -s -x http://127.0.0.1:7892 -k -A "Mozilla/5.0" -w "\n%{http_code}" https://example.com/api/v1/v/
hello
404

# 本机直连复核 —— 完全不可达
$ curl -s --noproxy '*' -k -A "Mozilla/5.0" -w "%{http_code}|%{remote_ip}" https://example.com/api/v1/u/
000|            (schannel: 无法连接)
$ curl -s --noproxy '*' --path-as-is --resolve example.com:443:203.0.113.101 -k https://example.com/api/v1/u/
conn-fail
# 203.0.113.102 / 203.0.113.103 / 203.0.113.104 三个解析 IP 同样 conn-fail

结论：example.com 本机不可达；经代理返回的 {"hello", 502/404} 是代理自身派生的伪造响应，
"hello" 即代理占位体。**该域名的任何代理响应均不可作为证据**。

★ 由此推翻的错误推论：曾据 "example.com 上 /api/v1/u/ 返回 502（上游不可达）而 /api/v1/v/ 返回 404"
推断"该 nginx 存在 location /api/v1/u/，客服端网关在这台机器上"。该推论已作废。

正确入口（经直连验证）：
- https://203.0.113.83:3493/api/v1/v/init  POST {"cid":"<key>","vid":"0"} -> 200 + tk/vid/租户配置
- 该入口 --noproxy '*' 直连可稳定成功，无需域名、无需代理

```
