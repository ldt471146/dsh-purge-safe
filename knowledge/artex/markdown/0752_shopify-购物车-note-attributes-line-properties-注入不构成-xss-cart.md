# Shopify 购物车 note/attributes/line properties 注入不构成 XSS（/cart 与 /checkout 转义闭合，实测阴性）

- **code**: shopify-购物车-note-attributes-line-properties-注入不构成-xss-cart
- **kind**: poc
- **category**: app-audit
- **component**: Shopify 店面（Ajax Cart API + 主题 /cart 页 + checkout /checkouts/cn）
- **source**: self
- **verified**: 1
- **verified_note**: www.retro32.com 2026-11-12 实测：GET /cart/update.js?note=<script>alert(1)</script>&attributes[xss]="><img src=x onerror=alert(2)> => 200 原样存储；/cart 页 properties 输出 &lt;img src=x onerror=alert(3)&gt;（转义）、note 不渲染；/checkouts/cn/<token>/en-gb 200（299594B）中 payload 位于 <meta name="serialized-graphql" content="..."> 且 &lt; &amp; &quot; 全实体编码，React 渲染无执行面。
- **path**: pocs/shopify-购物车-note-attributes-line-properties-注入不构成-xss-cart/poc.txt
- **tags**: shopify,csrf,cart,xss,output-encoding,negative
- **created_at**: 2026-11-12T11:38:11.600Z
- **engine**: www.retro32.com

## 描述

对 Shopify 购物车 CSRF/投毒类 finding 的升级路径做定量闭环：note/attributes/line properties 可被任意写入且原样存储，但在主题 /cart 页与 Shopify checkout 页均被正确转义/实体编码，不能升级为 XSS。后续 worker 命中同类端点时直接引用本结论，别重复手测 XSS。

## 用法

```
复测模板（约 4 个请求）：
1) curl -sk -c cj.txt 'https://<shop>/cart/add.js?id=<variant>&quantity=1'
2) curl -sk -b cj.txt --get 'https://<shop>/cart/update.js' --data-urlencode 'note=<script>alert(1)</script>' --data-urlencode 'attributes[xss]="><img src=x onerror=alert(2)>'
3) curl -sk -b cj.txt 'https://<shop>/cart' | grep -c '&lt;script&gt;alert(1)'   # 主题页应转义/不渲染
4) curl -sk -b cj.txt 'https://<shop>/checkouts/cn/<cart_token_handle>/en-gb?skip_shop_pay=true' | grep -o 'serialized-graphql'  # checkout 数据在 meta 属性内实体编码
判定：若 payload 以原文 `<script>`/`<img` 出现在 HTML 文本或属性上下文才继续打 XSS；出现在 &lt; 实体编码的 meta content 或 JSON 字符串中即为阴性。
```

## 正文

```
# Shopify 购物车注��� → XSS 升级：阴性结论（实测）

## 场景
Shopify Ajax Cart API 存在零 CSRF 校验的 GET 状态变更（kb#557），可直接写入：
- `GET /cart/update.js?note=<payload>&attributes[x]=<payload>`
- `GET /cart/add.js?id=<variant>&quantity=1&properties[<name>]=<payload>`

## 实测（www.retro32.com，2026-11-12）
- 写入端：两个端点均 200，响应体与 `/cart.js` 原样回显存储值（`note:"<script>alert(1)</script>"`、`properties:{"gift_note":"<img src=x onerror=alert(3)>"}`），库存限制类 422 与 CSRF 无关。
- 主题 /cart 页（330786B）：line properties 渲染为 `&lt;img src=x onerror=alert(3)&gt;`（HTML 实体转义）；`note` 不在主题购物车页渲染（payload 0 次命中）。
- Shopify checkout 直连 `/checkouts/cn/<token>/en-gb?skip_shop_pay=true`（200，299594B）：note/attributes/properties 被序列化进 `<meta name="serialized-graphql" content="{...}">`，`<`、`&`、`"` 全部实体编码（`&lt;script>alert(1)&lt;/script>`），由 React 渲染，无脚本执行腔。
- `/cart/add?...&return_to=https://evil.example/landing` → 302 `/cart`（外跳被忽略，仅相对路径 return_to 生效），CSRF 无法组合出开放跳转。

## 结论
Shopify 购物车 note/attributes/line properties 的 CSRF 投毒在标准主题 + 原生 checkout 上被正确输出编码，**不构成 XSS**。该类漏洞的实际影响上限 = 购物车完整性 + 结账页内容投毒（社工面）。不要在此方向重复手测；除非目标装了自定义主题/应用把 attributes 直接 innerHTML 渲染（需单独验证）。
```
