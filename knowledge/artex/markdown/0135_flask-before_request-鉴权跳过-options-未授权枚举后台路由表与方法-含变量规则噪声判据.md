# Flask before_request 鉴权跳过 OPTIONS ⇒ 未授权枚举后台路由表与方法（含变量规则噪声判据）

- **code**: flask-before_request-鉴权跳过-options-未授权枚举后台路由表与方法-含变量规则噪声判据
- **kind**: script
- **category**: info-leak
- **component**: Flask
- **severity**: low
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 codex-tgt4796-com 靶标 http://203.0.113.51:5050（Flask + Werkzeug 3.1.8）实测：GET/POST/PUT/DELETE/PATCH /api/config 全部 401，而 OPTIONS /api/config → 200 + `Allow: HEAD, OPTIONS, GET`；据此未授权枚举出 13 个真实路由（含 POST-only 的 /api/admin/login、/api/r2/sync），并识别出 /api/config/<x> 为变量规则噪声（全部后缀命中）。另用模块 × 子路径交叉确认唯一白名单 GET 接口是 /api/redeem/lookup。对应 vuln 59 / evidence 44。
- **path**: pocs/flask-before_request-鉴权跳过-options-未授权枚举后台路由表与方法-含变量规则噪声判据/flask_options_unauth_route_enum.md
- **tags**: flask,werkzeug,OPTIONS,before_request,未授权,路由枚举,Allow头,变量规则,噪声
- **created_at**: 2026-09-30T01:55:00.518Z
- **found_by**: exploit

## 描述

Flask/Quart 应用把鉴权写在 before_request 时，Werkzeug 自动 OPTIONS 会绕过钩子并把真实允许的方法写进 Allow 头 → 未授权即可枚举完整后台路由表（含 POST-only 隐藏接口）。附"变量规则 catch-all 噪声"的判据与交叉验证方法，以及从控制台页名反推后端模块的技巧。

## 用法

```
1) 先确认钩子被绕过：`curl -i -X OPTIONS http://T:PORT/api/config`（应 200 + Allow），同时 `curl -i http://T:PORT/api/config`（应 401）；2) 跑 `bd2_route_enum.py` 把词表套在若干父路径上，收集所有 `200 + Allow` 的路径；3) **剔除噪声**：若某父路径下全部后缀都 200 且 Allow 相同 ⇒ 是 `<x>` 变量规则，只记 1 条；4) 对命中路由逐个试 GET/POST，找出真正 200 的白名单（未授权可读的接口）；5) 把 POST-only 接口挑出来单独做参数/认证绕过测试；6) 用控制台页面名反推后端模块名能显著提高命中率。
```

## 正文

```
## 缺陷
很多 Flask/Quart 应用把鉴权写成 `@app.before_request` 钩子（`if request.path.startswith('/api/') and not logged_in: abort(401)`）。
**Werkzeug 的自动 OPTIONS 处理发生在 before_request 之后、且不会触发业务视图**，于是：
- `GET/POST/PUT/DELETE/PATCH /api/x` → **401**（钩子拦截）
- **`OPTIONS /api/x` → 200 且带 `Allow: HEAD, OPTIONS, GET`** ⇒ 钩子形同虚设，**方法清单直接白送**

## 用它能做什么：未授权路由表枚举
`Allow` 头由 Werkzeug 的 URL map 生成，因此：
- **200 + `Allow`** = 该路由**存在**，且 Allow 里就是真实允许的方法
- **404 + `text/html`（Flask 的 404 页）** = 该路由**不存在**
- 路由存在但只有 POST → `Allow: POST, OPTIONS`（能直接捞出 POST-only 的隐藏接口，如登录/同步/上传）

据此可以在**没有任何凭证**的情况下枚举出完整后台 API 面（含只开放 POST 的接口），比 ffuf 硬扫更准（不会把 401 误判成"存在"、也不会漏掉没有 GET 的接口）。

## 案例（实测，2026-09-30，codex-tgt4796-com / 203.0.113.51:5050）
`GET/POST/PUT/DELETE/PATCH /api/config` → 全部 `401 {"error":"unauthorized","message":"需要登录管理后台"}`；
`OPTIONS /api/config` → `200`，`Allow: HEAD, OPTIONS, GET`。
枚举结果（未授权）：`/api/accounts`、`/api/characters`、`/api/codes`、`/api/config`、`/api/dashboard`、`/api/db`、`/api/health`、`/api/logs`、`/api/r2`、`/api/tasks`、`/api/version`（GET/HEAD）、**`/api/admin/login`（POST-only）**、**`/api/r2/sync`（POST-only）**、`/api/characters/search`（POST）、`/api/redeem/lookup`（GET）。
——其中 `/api/characters/search`（POST）与 `/api/redeem/lookup`（GET）是白名单，未授权可读数据。

## ⚠️ 必须剔除的噪声：变量规则（catch-all）
若存在 `/api/config/<x>` 这类**变量规则**，则 **`/api/config/任意后缀` 都会命中**（OPTIONS 全 200），会被误读成"发现了 30 个接口"。
判据：同一父路径下**所有**后缀都返回 200 且 `Allow` 完全相同 ⇒ 是变量规则，只记 1 条。
反向交叉验证：把同一份后缀列表套到**另一个已知不存在的父路径**上，若也全命中，则更可疑（可能是全局 catch-all 或 404 处理器被改写）。
**更稳的做法**：对命中的路由再用 GET/POST 打一次看是否 401/405/200 —— 只有"OPTIONS 200 + 真实方法"才是路由存在的硬证据。

## 附带收益
- 命中的路径直接给出**前端页面结构与后端模块的对应关系**（本次由控制台页面 `/admin/{accounts,logs,news,proxies,redeem,register,settings,workflow}` 反推出后端 `/api/<module>`）。
- 拿到 `Allow` 后，针对 POST-only 接口单独测参数/认证绕过，比盲目扫路径高效得多。

## 复现脚本
`bd2_route_enum.py`（父路径 × 词表，输出 200+Allow 清单）
`bd2_route_enum2.py`（多级路径 + 对命中路由自动试 GET/POST 找白名单）
`bd2_whitelist_hunt.py`（模块 × 子路径全量交叉，筛出真正 200 的白名单接口）
```
