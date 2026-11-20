# 登录"成功"的真伪三重证伪：字段校验 / 鉴权中间件 / 浏览器注入会话+清 Cookie 对照

- **code**: 登录-成功-的真伪三重证伪-字段校验-鉴权中间件-浏览器注入会话-清-cookie-对照
- **kind**: template
- **category**: auth-bypass
- **severity**: medium
- **language**: text
- **source**: self
- **verified**: 1
- **verified_note**: 本靶标实测：11600「API Key Management」用 admin/zw4609591 登录，三重对照全部通过（空 body → 400；未认证 14 端点 → 401；注入 connect.sid → /api/auth/me 返回 authenticated=true，清 Cookie 后同 URL 返回 Not authenticated）。同时据此保守只记普通档 +50，因除 /api/auth/me 外业务端点带会话后全 404。证据：交付物/22-口令复用验证/raw/E-11600-完整可重放.txt 与 E-11600-浏览器实测.json。
- **path**: pocs/登录-成功-的真伪三重证伪-字段校验-鉴权中间件-浏览器注入会话-清-cookie-对照/poc.yaml
- **tags**: 口令复用,假成功,会话验证,三重对照,计分纪律,凭据复用边界
- **created_at**: 2026-09-29T15:05:58.047Z
- **found_by**: exploit

## 描述

登录返回 200 不等于会话有效（SPA fallback 与假成功极常见）。本条目给出三重独立对照的证伪流程（字段校验探针 / 鉴权中间件探针 / 浏览器注入会话+清 Cookie 对照），并配套"登录成功≠管理员权限"的计分纪律与口令复用验证的边界规范。

## 用法

```
任何"用已知口令登录成功"的结论，落库记分前先跑三重对照：① 空 body 期望 400 字段校验；② 未认证访问业务端点期望全 401；③ 浏览器注入会话访问身份接口期望 authenticated=true，清 Cookie 后同一 URL 期望未认证。三条全过才认会话真实；再按实际能力（能否访问业务端点）决定记普通档还是管理员档。
```

## 正文

```
【为什么需要这套方法】
拿到口令登录后，"返回 200"或"返回成功字样"都可能是假的：前端 SPA fallback 会把任意路径吞成 200 首页；有些应用会回显字段（本例 `role` 字段回显的就是口令值本身），让人误以为登录成功。**必须用三重独立对照才能确认会话真实有效。**

【三重证伪（全部要做，缺一条就不算确认）】
**① 字段校验探针** —— 证明服务端真的在解析并校验
- 提交空 body `{}` → 应返回 **400** `Username and password are required`
- 只提交 `{username}` → 同样 400
- 意义：证明这不是一个"什么都回 200"的假接口

**② 鉴权中间件探针** —— 证明保护面真实存在
- **未认证**状态访问一批业务端点（本例 14 个）→ 应 **全部 401** `Unauthorized. Please login first.`
- 意义：证明鉴权中间件真的在工作，而不是所有请求都放行

**③ 浏览器会话对照（最关键）** —— 排除"这个接口本来就不需要认证"
- 用真实浏览器（Chrome + CDP）注入拿到的会话 Cookie → 访问身份接口（如 `/api/auth/me`）
  → 应返回 `{"authenticated":true,"user":{...}}`
- **然后清掉 Cookie**（`clearBrowserCookies`）→ **访问完全相同的 URL**
  → 应变成 `{"error":"Not authenticated"}`
- 意义：**唯一变量是会话**。两次结果不同 = 会话真实有效；两次相同 = 接口本身不校验，与登录无关

【本例实测（203.0.113.118:11600「API Key Management」）】
- 命中：`admin` / `zw4609591` → `{"message":"Login successful"}` + `Set-Cookie: connect.sid=...`
- ① 空 body → 400 `Username and password are required` ✔
- ② 未认证 14 个 `/api/*` → 全 401 ✔
- ③ Chrome 154 + CDP 注入 `connect.sid` → `/api/auth/me` = `{"authenticated":true,"user":{"username":"admin","role":"zw4609591"}}`；清 Cookie 后同 URL = `{"error":"Not authenticated"}` ✔
- **注意该应用的坑**：`role` 字段回显的是口令值本身（`"role":"zw4609591"`），是它自己的实现缺陷，**不要据此判断权限级别**

【计分纪律（配套）】
- 会话真实性确认了，**但要看实际拿到什么权限**：本例除 `/api/auth/me` 外，所有业务端点带会话后**全部 404**（路由不存在）→ **未取得任何管理能力证据 → 只能按普通档记，不能按管理员档**
- 报告口径：**"登录成功" ≠ "拿到管理员权限"**。分别写清：会话是否真实、能访问哪些端点、有哪些实际能力

【口令复用验证的边界（同批采用）】
- 口令来源必须是**实证**（配置泄露/明文回显/日志），**不是猜的**
- **每个入口 ≤2 个用户名 × 1 次**，命中即停，**绝不铺字典**
- 列出"已否证"的入口同样重要——本例明确否证了 AIRouter 后台（401）、1Panel（ErrAuth）、Redis（WRONGPASS），避免后人重复烧次数
- **否决结论必须带服务端原文**（如 `Invalid credentials` / `ErrAuth` / `-WRONGPASS`），而不是"看起来不行"
```
