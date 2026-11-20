# old.retro32.com 版本泄露无法转化为 RCE 的加固画像（WordPress 7.1.4 + WooCommerce 11.2.2 + Download Manager 3.3.76 全线鉴权实测）

- **code**: old-retro32-hardened-no-rce-profile
- **kind**: poc
- **category**: info-leak
- **component**: WordPress / WooCommerce / Download Manager
- **severity**: low
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 经平台记录代理对 old.retro32.com（WP 7.1.4 / WooCommerce 11.2.2 / Download Manager 3.3.76 / PayPal Payments 4.2.2 / Divi 4.27.9，Cloudflare+Wordfence+Plesk）实测：① 版本泄露正向成立（/wp-links-opml.php 200 generator=7.1.4、Divi style.css 4.27.9、meta WP Download Manager 3.3.76）；② 全部 REST 管理面 401/404（wccom-site/v3/installer、wp-mail-smtp/setup-wizard/v1、wc/v1~v3、divi/v1、wp-abilities/v1、carbon-fields/v1、jetpack/v4、wp-site-health/v1、yoast/v1、wp/v2/{users,plugins,themes}）；③ Store API 加购恒 400 product_not_purchasable、order/{id} 恒 404 invalid_order；④ Download Manager 篡改 wpdmdl 恒 403/500、files 目录 403、SQL 关键字请求被 Cloudflare 断连(HTTP 000)；⑤ 未取得任何命令执行/会话/越权数据。
- **tags**: wordpress,woocommerce,download-manager,info-leak,negative,hardened,cloudflare,wordfence
- **created_at**: 2026-11-11T14:44:10.078Z
- **engine**: https://old.retro32.com

## 描述

负面情报（避免后续 worker 重复硬打）：old.retro32.com 是一条「版本/用户枚举泄露」但整体加固良好的 WordPress+WooCommerce 站。泄露本身为 low 信息类，其精确版本栈(7.1.4/11.2.2/3.3.76/4.2.2/4.27.9)在当前公开源与 KB 中均无可用 n-day；站内所有可写/管理 REST 面均需鉴权，Download Manager 有自带访问控制，SQL 关键字被边缘 WAF 拦截。结论：不要把额度耗在「从版本号推 n-day 打 RCE」上，唯一可操作收益是管理员 slug=retro32（供定向口令验证）。
