# Shopify cart token 结构：24 字符 base62 = 8 字符可预测时间前缀 + 16 字符随机尾段（handle 枚举路线已证否）

- **code**: shopify-cart-token-24char-time-prefix-nonenumerable
- **kind**: script
- **category**: recon
- **component**: Shopify Storefront Cart Token（cart cookie handle / gid://shopify/Cart/<handle>）
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: thegamecollection.net 两店 26 辆自建车 + UCP create_cart 4 辆 + KB 其它 Shopify 店 12 个历史 token，共 42 个样本：全部 24 字符、V mod 256 恒等于 8；前 8 字符（V//62^16）对时间线性 rate=6.498324 ticks/s，按模型预测后实际创建的偏差 /cart/add.js 0..+1 tick、UCP +3..+4 tick；后 16 字符 42/42 唯一、KS 均匀性 0.1297<0.210、87.27bit 变化、对时间 Spearman≤0.25；伪造前缀+随机尾段/旧前缀+自有尾段/随机 24 字符均 cart:null，自有车正向返回 totalQuantity=1。
- **tags**: shopify,cart-token,handle,base62,entropy,enumeration,negative,recon
- **created_at**: 2026-11-11T17:58:17.918Z
- **engine**: www.thegamecollection.net / collect.thegamecollection.net / 通用 Shopify cart cookie

## 描述

Shopify 匿名购物车 handle（cart cookie 的 25/27 位说法不准确，实测均为 24 字符 0-9A-Za-z base62）不是全随机：它是一个按 0-9A-Za-z 字母表单调递增的大整数 V。前 8 字符 P=floor(V/62^16) 是 Shopify 全平台共享的创建时刻计数器（约 6.498 ticks/s，153.9ms/tick，跨店同一条序列，可精确反推到 ±0.15s）；后 16 字符 R=V mod 62^16 占 62^16≈2^95.27，其中低 8 bit 恒为 0x08（42/42 跨店成立），其余 87.27 bit 均匀随机、与时间无相关。因此在已知创建时刻的前提下，枚举成本仍 ≥2^80；任何“靠时间窗穷举 cart handle 读他人 cart key/PII”的路线都不可行（finding#903 类漏洞只能靠分享/结账链接/Referer/归档等外部泄漏获得 handle）。反过来说：拿到任一 handle 可反推创建时间，可用于时间关联。

## 用法

```
采样：单线程、间隔≥3s，POST https://<host>/cart/add.js 不带 cookie 每次新建车，从 Set-Cookie cart=<handle>%3Fkey%3D<32hex> 取 handle 并记录 UTC 毫秒时间；也可用 /api/ucp/mcp create_cart（profile 指向店铺 /.well-known/ucp 自绕）。分析（Python）：AL='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'；V=sum(AL.index(c)*62**(len-1-i) for i,c in enumerate(h))；P=V//62**16；对 P 与时间做线性拟合得 rate≈6.498 ticks/s；验证方法=用模型预测下一 tick 的 P 再实际创建比对（误差应 ≤1 tick）；R=V%62**16，检查 R%256 是否恒为 8（是则低 8 bit 为格式标签），对 R/62^16 做 KS 均匀性检验（n=42 时 5% 临界 0.210）；阴性对照：用“预测前缀+随机16字符”“任意旧前缀+自有尾段”“纯随机24字符”调 POST /api/graphql cart(id:"gid://shopify/Cart/<h>"){id totalQuantity} 应全部返回 cart:null。判定：只有整串可预测或尾段熵足够低才可枚举；本结构下不可行，别再把时间花在 handle 爆破上。
```
