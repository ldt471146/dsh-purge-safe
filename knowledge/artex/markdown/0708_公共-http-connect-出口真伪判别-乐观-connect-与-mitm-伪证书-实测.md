# 公共 HTTP CONNECT 出口真伪判别：乐观 CONNECT 与 MITM 伪证书（实测）

- **code**: 公共-http-connect-出口真伪判别-乐观-connect-与-mitm-伪证书-实测
- **kind**: methodology
- **category**: recon
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 ARTEX 对 support.shopto.net(18.130.143.97) 复核：fact#2630 的 162 条出口 + 新抓 2990 条抽样 200 条，仅 44 条通过证书级校验；78.12.136.220:30571 对 support:443 伪造 TLS+HTTP 200（Squid 4.10 自生成页、证书 OCT27-JAN25 GTS WR2）；1.10.248.226:80/49.151.187.115:8082 对 192.0.2.1:443 与关闭端口 :81 均回 CONNECT 200。
- **tags**: proxy,connect,mitm,fake-proxy,reachability,methodology
- **created_at**: 2026-11-11T21:43:44.361Z
- **engine**: support.shopto.net / 18.130.143.97

## 描述

使用公共免费 HTTP CONNECT 代理做目标可达性判断时，CONNECT 200 与 TLS 成功都可能被伪造。两把必做标尺：① 乐观 CONNECT 对照——同出口 CONNECT 192.0.2.1:443（TEST-NET 不可路由）和一个已知关闭端口，若任一返回 200 则该出口的 CONNECT 不可信；② 证书级校验——同出口 CONNECT 一个已知真实源站并完成 TLS，把拿到的证书 serial/subject/issuer/notBefore 与本地直连该源站的真实证书逐字段比对，不一致即 MITM 伪造（典型特征：为任意 CN 动态签发同模板证书、有效期完全相同，HTTP 响应是代理自身页面如 squid/4.10、Mikrotik HttpProxy 504、含 REMOTE_ADDR=代理IP）。只有通过①+②的"真出口"的阴性结果才可采信；阳性结果必须带真实内容特征（与直连基线的 body/证书一致）。

## 用法

```
真出口判定流程（Python/curl 伪代码）：1) 三目标 CONNECT 对照：192.0.2.1:443 必须失败、目标关闭端口必须失败、已知可达目标必须 200；2) 对已知可达 HTTPS 源站做 TLS，openssl x509 -noout -serial 与直连基线比对；3) 只有通过者才用于测目标；4) 伪代理特征：CONNECT 后 HTTP 响应含 'REMOTE_ADDR = <代理自身IP>'、'Server: squid'、'Mikrotik HttpProxy'、'504 Gateway Timeout'。参考产物：/opt/artex/data/tasks/4/i2959/{honesty_162.jsonl,connect_ctrl_good16.jsonl,tls_pair35.jsonl,new_exits_result.jsonl}。
```
