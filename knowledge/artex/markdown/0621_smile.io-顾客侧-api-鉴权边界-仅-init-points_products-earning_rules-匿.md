# Smile.io 顾客侧 API 鉴权边界：仅 init/points_products/earning_rules 匿名可读，顾客积分与兑换写端点强制 HS256 customer JWT（伪造/digest 绕过全拒）

- **code**: smile.io-顾客侧-api-鉴权边界-仅-init-points_products-earning_rules-匿
- **kind**: poc
- **category**: auth-bypass
- **component**: Smile.io
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 在 gamersdelight.co.uk 实测：未登录页面 .smile-shopify-init 只带 data-channel-key；exchange_tokens 换出 publishable pub_5b5a03c04e955375；init/points_products/customer_points_products/customer_activity_rules 匿名 200（设计内公开），customers/{id}、points_transactions、reward_fulfillments、referrals、activities、points_products/{id}/purchase 等一律 401 Invalid Bearer token；伪造 HS256/alg=none JWT、digest、传输变体全拒。
- **path**: pocs/smile.io-顾客侧-api-鉴权边界-仅-init-points_products-earning_rules-匿/poc.txt
- **tags**: smile.io,sweettooth,loyalty,points,api,auth,jwt,shopify
- **created_at**: 2026-11-11T17:48:17.796Z
- **engine**: https://gamersdelight.co.uk (Smile account 403487, channel channel_6jtZxc03bF3Qd07a6AN0BoVA)

## 描述

Smile.io（含旧版 Sweet Tooth）storefront 会员积分 API 的匿名面与鉴权判据，用于快速判定"会员积分后端"是否值得深挖。

## 用法

```
快速判据：
1) 从店铺页面 grep 'smile-shopify-init' 取 data-channel-key；curl 'https://platform.smile.io/smile_ui/exchange_tokens?channel_key=<key>' 取 publishable_key
2) curl -H 'X-Smile-Publishable-Key: <pub>' https://platform.smile.io/smile_ui/init?publishable_key=<pub> 看店铺配置
3) 打点：curl -H 'X-Smile-Publishable-Key: <pub>' https://platform.smile.io/smile_ui/customers/999999999 → 401=需 Bearer；再试 POST /smile_ui/activities、/smile_ui/points_products/{id}/purchase → 401=写面封死
4) 只有拿到商户 signing key（sig_*）或真实登录页 data-digest 才值得伪造 customer JWT
```

## 正文

```
## 两套 API
- 新版：https://platform.smile.io/smile_ui/*
  - header: X-Smile-Publishable-Key（公开，由 GET /smile_ui/exchange_tokens?channel_key=<页面 data-channel-key> 换取）
  - 顾客身份：Authorization: Bearer <customer JWT>，HS256，aud=api.smile.io，sub=SmileCustomer:<id>，由店铺 signing key（sig_<32hex>，商户后台）签发
- 旧版：https://api.smile.io/smile_js/*（别名 api.sweettooth.io），同 publishable key + 同 Bearer

## 匿名可读（设计内公开，未登录 widget 也要展示）
- GET /smile_ui/init?publishable_key=... → 店铺配置（account id、sales_channel、points/referrals/VIP 程序、显示设置）
- GET /smile_ui/points_products、/smile_ui/points_products/{id} → 奖励目录（含 Shopify reward/price-rule id）
- GET /smile_ui/customer_points_products → 未登录可兑换目录视图（can_afford 恒 false；customer_id 参数被忽略）
- GET /smile_ui/customer_activity_rules → 赚积分规则（本店无 daily check-in）
- GET /smile_js/preloadable_program_data?include=points_settings,points_products,earning_rules,vip_tiers,referral_settings

## 强制 Bearer（无 token 一律 401 Invalid Bearer token）
- GET /smile_ui/customers/{id}、customers/{id}/latest_unused_reward_fulfillment、customers/{id}/best_points_product_to_show
- GET /smile_ui/points_transactions、reward_fulfillments、referrals、vip_tier_changes、public_customer_points_products
- POST /smile_ui/activities（加积分）、POST /smile_ui/points_products/{id}/purchase（兑换）
- GET /smile_js/preloadable_customer_data、/smile_js/customer_points_products

## 已证否的绕过（别重复）
- identify_customer 的 digest 硬校验：无 digest/空/"x"/sha256(shop:cid)/HMAC(channel_key|publishable, shop:cid) 均 401 "Invalid API key or customer identity digest"
- identify_with_jwt 需先有 Bearer；alg=none、HS256 假签均 401
- HS256 伪造用空 key/publishable/channel key/sig_+0 串/secret 全 401；alg=none 401
- Bearer null/undefined/0、?customer_token=、X-Smile-Customer-Token、Cookie、仅 Smile-Channel-Key 头 → 401
- X-Smile-Origin: Shopify-Checkout / Smile-Client: smile-checkout 不改变鉴权
- 无 X-Smile-Publishable-Key 头：platform /smile_ui/* → 404 路由级；api.smile.io → 401 "The X-Smile-Publishable-Key header is required."
- 路径变体（.json、尾斜杠、/v1/ 前缀）、X-HTTP-Method-Override → 404/401

## 仍需 signing key / 真实 digest 才能推进
- 页面 .smile-shopify-init 的 data-digest 只在登录顾客页面出现；主题 JS 与 init 响应均不含 sig_ secret
- 匿名可达但未验证：GET /smile_ui/referral_codes/{code}/details（无效 404 "Invalid referral code"；有效 code 或回显推荐人信息，需真实顾客 code，注意授权边界）
- init 的 publishable_key 未做有效性校验（错误 pk 无 header 也 200 返回本店配置；完全无 key → 404），跨租户影响未验证
```
