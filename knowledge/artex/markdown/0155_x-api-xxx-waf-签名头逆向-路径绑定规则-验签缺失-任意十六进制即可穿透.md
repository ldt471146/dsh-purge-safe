# X-API-XXX WAF 签名头逆向：路径绑定规则 + 验签缺失（任意十六进制即可穿透）

- **code**: x-api-xxx-waf-签名头逆向-路径绑定规则-验签缺失-任意十六进制即可穿透
- **kind**: script
- **category**: env
- **component**: Next.js SPA + Moleculer 网关
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 https://example.com:6509 实测：① /sact/api/v1/kyc/activity/config 的 X-API-XXX 字面值="undefined" 仍返回 200（前端签名失败被服务端接受）；② /site/api/v1/configuration/preInfo 用 X-API-XXX=deadbeef*8 仍返回完整站点配置；③ 完全不带 XXX 才返回 6003。证明 WAF 层不验签值。路径绑定规则从 /site/api 的 _app chunk 模块 87802 源码还原。
- **path**: pocs/x-api-xxx-waf-签名头逆向-路径绑定规则-验签缺失-任意十六进制即可穿透/waf_sign_xxx_path_binding.md
- **tags**: waf,signature,x-api-xxx,nextjs,moleculer,replay,bypass
- **created_at**: 2026-10-02T21:54:15.441Z
- **found_by**: exploit

## 描述

还原 WAF 签名头 X-API-XXX 的生成规则（绑定 URL 前两段路径 + wasm sign），并证明该层不严格验签，可用于重放任意前缀的请求

## 用法

```
# 取某个路径的合法 XXX：在已登录页面用 chrome_network_capture 抓该接口的真实头，原样重放
# 判据：缺 XXX → 6003 非法请求；XXX 任意十六进制 → 穿透到业务层
# 对同一路径多次抓取，XXX 值稳定，可缓存复用
python runs/site_jwt.py    # runs/site_session.py 中已预置 19 组捕获到的 (路径 → XXX) 映射
```

## 正文

```
# X-API-XXX 签名头的路径绑定规则（WAF 层）

## 前端实现（模块 87802，_app.js）

```js
function TC(path) {
  if (path.includes("/component")) path = "/site/api";
  if (path.includes("/page/fd")) path = "/fd/api";
  // -> chunk 2284 动态加载 wasm -> sign(path, "prod")
}
// 调用侧（模块 15186）：
//   TC(url.match(/\/\w+\/\w+/i)?.[0] ?? "")   ← 只取 URL 前两段路径
//   headers = {"X-API-CLIENT":"web", "X-API-XXX": TC(...), "X-API-VERSION":"2.0.0", "X-API-SITE":"3001"}
```

因此 **XXX 绑定的是「服务前缀 + 控制器」两段**，不是完整路径，也不是整个 host。

## 实测：同一次页面加载的 19 个 XXX 互不相同

| 接口 | XXX（前 16 位） |
|------|----------------|
| /site/api/v1/user/member/info | d5c207ad5fdb31c3 |
| /site/api/v1/configuration/preInfo | df226988bc6597276 |
| /fd/api/v1/withdraw/editNameStatus | 473d4e44ed6bc368 |
| /act/api/v1/advertising/queryWebSponsoredImage | 04e9a4036c3b429a |
| /game/api/v1/venue/queryGameAppByType | 509c8d36124dbd71 |
| /page/fd/api/v1/resource/showV2 | 336c6a6b3312cecc |
| /sact/api/v1/kyc/activity/config | **undefined** |

## 关键发现：WAF 层并不严格验签

1. `/sact/api/v1/kyc/activity/config`、`/sact/api/v1/yuEBao/redPoint`、
   `/sact/api/v1/yuEBao/getInterestTotal` 的 XXX 字面值就是字符串
   `"undefined"`（前端 wasm 加载竞态导致签名失败），**服务端照样返回 200**。
2. 完全不带 XXX（值缺失）时会返回 `{"message":"非法请求","status_code":6003}`；
   带任意 32/64 位十六进制也会走到业务层（如 preInfo 用 `deadbeef*8`
   仍返回完整站点配置）。

⇒ **WAF 只校验「头是否存在且像签名」，不验签值本身**。
   真正的鉴权在业务层的 `X-API-TOKEN` / `X-USER-ENCY`。

## 复用签名值的两种可行做法

1. 在已登录页面里 `chrome_network_capture` 抓同路径的真实 XXX 原样重放
   （同一路径的 XXX 似乎稳定，实测多次一致）。
2. 复用页面已加载的 wasm 签名器：`performance.getEntriesByType('resource')`
   里能看到 `/_next/static/chunks/2284.e464363471c79b6a.js` 与
   `/_next/static/wasm/729ede6e9048bb61.wasm`，直接调 `sign(path,"prod")`。
```
