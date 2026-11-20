# Vite SPA 资金接口静态还原 + 二维码渲染定性（含带会话的页面内 fetch 验证）

- **code**: vite-spa-资金接口静态还原-二维码渲染定性-含带会话的页面内-fetch-验证
- **kind**: script
- **category**: info-leak
- **component**: Vite 打包 SPA / Spring Boot 资金后端
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com（203.0.113.111，Spring Boot + Tomcat + Vite SPA）实测：主包 index-10-09-17-42-CL2wXCgB.js 一次 grep 得到 138 个 /api/* 接口清单；路由 grep 定位到 /mine/wallet/confirm 对应 chunk index-10-09-17-42-DHz3SnLP.js；在该 chunk 内取得订单二维码渲染代码 `{label:"充值地址",value:order.toAddress},{label:"二维码",value:order.toAddress||order.imgUrl,QRcode:!0}` 与前端 qrcode 库 import（qrcode-10-09-17-42-BJXGL8iM.js），据此判定二维码为前端本地绘制、内容 = 服务端下发的 toAddress；在下单页 chunk index-10-09-17-42-DfYj49dX.js @74578 取到 /api/getCurrencyPayUrl 的真实请求体原文，并据此在页面内 fetch 成功下单（merchantOrderId rbubit3876344000003，code 10000）。
- **path**: pocs/vite-spa-资金接口静态还原-二维码渲染定性-含带会话的页面内-fetch-验证/webpay_static_reverse.md
- **created_at**: 2026-10-10T19:24:51.211Z

## 描述

零请求从前端 Vite 打包产物还原资金接口清单、下单请求体、订单字段与二维码渲染逻辑（含判定"二维码=前端绘制 toAddress"的方法，以及浏览器页面内带会话验证的写法）。用于任何 Spring Boot + Vite SPA 博彩/资金类站点。

## 正文

```
# 通用手法：从前端打包产物做「资金接口 + 订单字段」静态还原（零请求、零痕迹）

## 1) 先拿主包地址（页面里读）
```js
// 浏览器控制台 / 无依赖 headless 均可
[...document.querySelectorAll('script[src]')].map(s=>s.src)
// 或看 performance 资源
performance.getEntriesByType('resource').map(e=>target316.example.com).filter(n=>/\.js(\?|$)/.test(n))
```

## 2) 主包 → 全站接口清单（一次 grep 拿到 138 个 /api/*）
```bash
curl -s -x http://127.0.0.1:7892 -H "User-Agent: Mozilla/5.0 ... Chrome/131" \
  -o main.js "https://TARGET/assets/<main-hash>.js"
grep -oE '"/api/[A-Za-z0-9_]+"' main.js | sort -u
```

## 3) 主包 → 按「服务注册名 + 路径」还原每个接口的调用封装
```bash
grep -oE 'bo\.post\([^)]{0,120}"\/api\/[A-Za-z0-9_]+"[^)]{0,80}\)' main.js | sort -u
# 形如：Un=e=>target308.example.com(go.BACKEND,"/api/unBindBankinfo",e)
# → 拿到「接口函数名 → 路径 → 是否 showErrorNotify/response 包装」映射
```

## 4) 主包 → 懒加载路由 → 页面 chunk（找真正的业务调用点）
```bash
grep -oE 'component:\(\)=>[a-z]+\(\(\)=>import\("\./[A-Za-z0-9_\-\.]+\.js"\)' main.js
# 形如：{path:"confirm",component:()=>de(()=>import("./index-10-09-17-42-DHz3SnLP.js"),__vite__mapDeps([...]))}
grep -oE 'import\("\./[A-Za-z0-9_\-\.]+\.js"\)' main.js | sort -u   # 全部懒加载 chunk 名
```

## 5) 在页面 chunk 里定位「下单请求体」与「订单字段消费点」
```bash
# 请求体（业务真值，比任何模糊测试都准）
grep -oE '.{450}getCurrencyPayUrl.{450}' <page-chunk>.js
#   → cl({currencyType:"USDT",protocol:...,payWay:...,device:...,amount:...,returnType:"json"})
# 字段消费点（判断哪个字段被渲染成二维码/链接）
grep -oE '.{350}(QRcode:!0|toAddress|imgUrl).{350}' <page-chunk>.js
```

## 6) 判定「二维码是前端画还是服务端给图」（投毒定性）
```js
import{ Q as Ce } from "./qrcode-<hash>.js"        // 前端 qrcode 库
{label:"充值地址",value:order.toAddress},
{label:"钱包协议",value:order.protocol},
{label:"二维码", value: order.toAddress || order.imgUrl, QRcode:!0, warning:!0}
```
→ 出现 `QRcode:!0` + 直接绑 `toAddress/imgUrl` = **前端本地绘制，二维码内容 = 服务端下发的 toAddress** ⇒ 投毒点唯一就是「toAddress 能否被客户端控制」。

## 7) 带登录态的验证（浏览器页面内同源 fetch，最省事）
```js
const post=(p,b)=>fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify(b),credentials:'include'}).then(r=>r.text());
await post('/api/getCurrencyPayUrl',{currencyType:'USDT',protocol:'TRC20',payWay:60,
  device:'PHONE',amount:100,returnType:'json'});
```
要点：页面内 fetch 自动带登录 Cookie，不必导出 JSESSIONID；但**必须指定目标标签页**，否则会打到别的页面。

## 8) 判定要点（避免假阳性）
- 注入字段是否被采纳：**只信响应里回显的字段值**；服务端每次下发新随机值（如每单不同的 TRC20 地址）时，必须与「自己传的值」逐一比对，而不是看有没有报错。
- 汇率类参数（rateType/type/rate）客户端可控 ≠ 业务可控：必须找**消费点**（谁把该结果拼进订单），并实测订单 `rate` 是否变化。
- 连续下单会被风控（`操作过于频繁`、刷单检测）挡住后续结论 → 该情形记「不可判定」，不要记「已排除」。
```
