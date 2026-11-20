# judge.me 评论 widget 字段级存储型 XSS 阴性（name/title 服务端剥离+实体编码；picture_keys 不采纳 SVG/HTML）

- **code**: judge.me-评论-widget-字段级存储型-xss-阴性-name-title-服务端剥离-实体编码-pictu
- **kind**: poc
- **category**: methodology
- **component**: judge.me
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 retro-refresh.com（shop_domain=u1s10u-cw.myshopify.com, product_id=15692266996044）实测：匿名 POST api.judge.me/api/v1/reviews，name='"><img src=x onerror=window.__nX=1>'、title='</script><script>window.__tX=1</script>{{7*7}}' → 201；回读 rfw 得 reviewer_name='&quot;&gt;'、title='{{7*7}}'；SSR HTML 为 <span class='jdgm-rev__author'>&quot;&gt;</span>；headless Chromium 真实渲染 flags={}（__nX/__tX undefined）、injected=[]、__nX/__tX 在 document HTML 出现 0 次、{{7*7}} 未求值。picture：presigned_data 返回的 policy 无 content-type 约束，S3 上传 .svg(image/svg+xml) 与 .html(text/html) 均 201，对象直读 403；评论带 picture_keys[0]=该 SVG key 提交后 pictures_urls 始终为空（未采纳）；前端 accept 仅 gif/jpeg/png/webp。
- **tags**: judge-me, xss, stored-xss, output-encoding, negative, review-widget, picture-upload
- **created_at**: 2026-11-11T19:44:18.970Z
- **engine**: https://api.judge.me / https://retro-refresh.com/products/ipod-flash-adapter

## 描述

judge.me 评论提交端点（匿名 autopublish）的 reviewer_name / title / picture 字段并不构成存储型 XSS：服务端按 HTML sanitizer 剥离标签并把引号/尖括号实体化（name 存为 &quot;&gt;），SSR 与客户端重渲染均为文本；picture_keys 引用的 SVG/HTML 不会被后端采纳进 pictures_urls，图片链路由 canvas JPEG 转码，只处理栅格图；图片临时 S3 桶不接受外部直读（403）。

## 用法

```
判据：测 judge.me 评论字段 XSS 时，先匿名提交 name='"><img src=x onerror=…>' 与 title='</script><script>…</script>{{7*7}}'（201），T+60s 回读 reviews_for_widget 看 reviewer_name 是否已实体化（&quot;）、title 是否只剩模板标记；再用 headless Chromium 打开商品页检查 window.__nX/__tX 与注入元素——本店三字段全阴性。图片面：GET /api/v1/pictures/presigned_data 拿 policy（无 content-type 约束）→ POST s3.amazonaws.com/me.judge.temp-files 上传任意类型均 201，但对象 GET 403 且评论 pictures_urls 不采纳 .svg/.html，不必在该面重复投入；若要测 URL 注入，注意前端 accept 白名单仅 image/gif,jpeg,jpg,png,webp。
```
