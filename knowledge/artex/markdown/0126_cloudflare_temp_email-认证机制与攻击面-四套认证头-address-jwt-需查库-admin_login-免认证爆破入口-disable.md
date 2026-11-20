# cloudflare_temp_email 认证机制与攻击面（四套认证头 / address JWT 需查库 / admin_login 免认证爆破入口 / DISABLE_ADMIN_PASSWORD_CHECK）

- **code**: cloudflare_temp_email-认证机制与攻击面-四套认证头-address-jwt-需查库-admin_login-免认证爆破入口-disable
- **kind**: script
- **category**: auth-bypass
- **component**: cloudflare_temp_email (dreamhunter2333)
- **versions**: cloudflare_temp_email（main 分支；线上 mailbackend 自报 v1.1.0、taobaomail-backend 自报 v1.5.0）
- **severity**: high
- **language**: javascript
- **source**: web
- **source_url**: https://github.com/dreamhunter2333/cloudflare_temp_email
- **verified**: 1
- **verified_note**: 在 codex-tgt4796-com 靶标的 example.com（站点「教育邮箱小铺」，22 个邮件域名）与 example.com 上验证：① 两站 /open_api/settings 返回的字段与本项目源码 commom_api.ts 逐字段一致（含 disableAdminPasswordCheck、enableAddressPassword、statusUrl、enableGlobalTurnstileCheck），且 /api/* 失败文案 "Invalid address credential" 与源码 InvalidAddressCredentialMsg 一致 → 确认为本项目（**推翻了此前按 maillab/cloud-mail 的判断**）；② 线上 GET /api/* 全 401、/open_api/settings 200、POST /api/new_address 分别 400 D1_ERROR 与 403 New address is disabled，与 worker.ts 的中间件分支一一对应；③ 线上 POST /open_api/admin_login 可达且返回 401（无验证码、无限速），taobaomail 的 enableGlobalTurnstileCheck=false；④ POST /open_api/site_login 返回 CustomAuthPasswordMsg 而 /api/* 并不报该文案 → 实测确认 PASSWORDS 未配置（源码中 PASSWORDS 为空同样返回该文案，属误判坑）；⑤ x-admin-auth 明文路径与 /admin/* 接口族（/admin/mails、/admin/address、/admin/show_password/:id、/admin/db_initialize 等）线上均 401 同文案，管理密码 42 组定向弱口令未命中。
- **path**: pocs/cloudflare_temp_email-认证机制与攻击面-四套认证头-address-jwt-需查库-admin_login-免认证爆破入口-disable/cloudflare-temp-email-auth-analysis.md
- **tags**: cloudflare_temp_email,cloudflare-workers,临时邮箱,认证机制,x-admin-auth,admin_login,爆破入口
- **created_at**: 2026-09-29T20:32:26.761Z
- **found_by**: vuln-scan

## 描述

cloudflare_temp_email（dreamhunter2333，CF Workers 临时邮箱/邮箱小铺系统）完整认证机制：四套并行认证头、/api/* 的 address JWT 需 DB 二次校验、/admin/* 四种放行途径（含 DISABLE_ADMIN_PASSWORD_CHECK 总开关）、三个免认证 open_api 登录端点（admin_login 需提交 sha256 且不在限速白名单）。用于快速识别项目、判断 JWT 伪造可行性、定位管理密码爆破入口与免认证路径。

## 用法

```
1) 识别：GET /open_api/settings，字段含 disableAdminPasswordCheck/enableAddressPassword 即本项目；
2) 读配置拿全域名面与开关（needAuth、enableUserCreateEmail、disableAdminPasswordCheck、enableGlobalTurnstileCheck）；
3) 管理权限路线优先级：DISABLE_ADMIN_PASSWORD_CHECK 是否为 true > ADMIN_API_IP_WHITELIST 是否绕过 > x-admin-auth 明文爆破 > /open_api/admin_login（提交 sha256，无限速无验证码）；
4) 邮箱数据路线：/api/new_address 匿名建号（若 enableUserCreateEmail 且 DB schema 完整）→ 拿 address+address_id → 若同时拿到 JWT_SECRET 即可签发可用 token 读 /api/mails；
5) /admin/address、/admin/mails、/admin/show_password/:id 是拿全站邮箱与明文密码的高价值端点（需管理权限）。
```

## 正文

```
// cloudflare_temp_email（CF Workers 临时邮箱系统）认证机制 —— 源码定性（worker/src/worker.ts + address_auth.ts + open_api/auth.ts + utils.ts）
//
// ===== 0. 项目识别特征（比 cloud-mail 更容易混）=====
// GET /open_api/settings 免认证返回：announcement / prefix / addressRegex / defaultDomains /
//   needAuth / enableUserCreateEmail / disableAnonymousUserCreateEmail / enableAddressPassword /
//   showGithub / disableAdminPasswordCheck / statusUrl / enableGlobalTurnstileCheck / version
// 出现 disableAdminPasswordCheck 或 enableAddressPassword 即为本项目（maillab/cloud-mail 没有这些字段）
// 认证失败文案：/api/* → "Invalid address credential"
//
// ===== 1. 四套独立认证（CLAUDE.md 官方表）=====
//  | 路径          | 认证头               | 凭据                                   |
//  | /api/*        | Authorization        | Address (mailbox) credential（JWT）    |
//  | /user_api/*   | x-user-token         | 用户账号 JWT                            |
//  | /admin/*      | x-admin-auth         | 管理密码（明文）                          |
//  | (any)         | x-user-access-token  | 角色访问令牌（JWT）                        |
//  | (any)         | x-custom-auth        | 可选站点全局密码                          |
//
// ===== 2. /api/* 的 address JWT：验签 + DB 二次校验 =====
// worker/src/address_auth.ts
//   validateAddressPayload(c, payload):
//     const { address, address_id } = payload;
//     ...类型/正整数校验...
//     SELECT id FROM address WHERE id=? AND name=?   ← ★ 必须真实命中 address 表
//   addressJwtAuth: jwt({secret:c.env.JWT_SECRET, alg:'HS256'}) → 再 validateAddressPayload
//   payload = { address, address_id }（address=邮箱地址字符串, address_id=address 表自增 id）
//   ⇒ 伪造 JWT 需要 env.JWT_SECRET **且** 一组真实存在的 (address_id, name)；缺一不可
//
// ===== 3. /admin/* 的四种放行途径（worker/src/worker.ts）=====
//   ① ADMIN_API_IP_WHITELIST 配置了且 cf-connecting-ip 在列表内（否则 403 AdminApiIpNotAllowedMsg）
//   ② checkIsAdmin(c)：utils.ts → c.req.header("x-admin-auth") ∈ getAdminPasswords(c)（**明文 includes**）
//   ③ x-user-access-token + ADMIN_USER_ROLE 匹配；其中若 token 已过期且 DISABLE_ADMIN_PASSWORD_CHECK=true → 直接放行
//   ④ DISABLE_ADMIN_PASSWORD_CHECK 为 true → 直接放行（**总开关，一开就无鉴权**）
//   否则 401 NeedAdminPasswordMsg
//
// ===== 4. 三个免认证 open_api 登录端点（爆破/枚举入口，worker/src/open_api/auth.ts）=====
//   POST /open_api/site_login        {password, cf_token}         站点密码；未配置 PASSWORDS 时也返回 CustomAuthPasswordMsg（**易误判为已启用**）
//   POST /open_api/admin_login       {password, cf_token}         ★ 管理密码入口
//   POST /open_api/credential_login  {credential, cf_token}        校验 address JWT 是否有效
//   ★ admin_login 的实现要点：
//       const hashedPasswords = await Promise.all(getAdminPasswords(c).map(p => hashPassword(p)));
//       if (!hashedPasswords.length || !password || !hashedPasswords.includes(password)) → 401
//       hashPassword = crypto.subtle.digest('SHA-256', 明文) 的 hex（**无 salt、确定性**）
//       ⇒ 客户端须提交 **sha256(明文密码) 的 hex**，而不是明文！
//   ★ 这两个端点**不在** worker.ts 的速率限制白名单里（白名单仅 /api/new_address、/api/send_mail、
//      /external/api/send_mail、/user_api/address/*/send_mail、/user_api/register、/user_api/verify_code、/redeem_api/）
//      ⇒ 未启用 enableGlobalTurnstileCheck 时，管理密码可无限速无验证码在线爆破
//
// ===== 5. 免认证路径与旁路 ====≠
//   /open_api/* 与 /telegram/* 跳过 x-custom-auth 站点密码中间件 → /open_api/settings 永远可读
//   /api/new_address：只做可选 checkUserPayload，不做 addressJwtAuth ⇒ 匿名可达（建号入口）
//   /api/address_login：直接 next() ⇒ 免认证登录端点
//   全局中间件里未配 DB / JWT_SECRET / 域名时直接报错回显（可探测部署状态）
//
// ===== 6. 常见误判坑 ====
//   - 把本项目当成 maillab/cloud-mail：后者是 KV auth-uid:<userId> 双校验、文案不同，结论会全错
//   - /open_api/site_login 返回 "You have enabled the private site password..." **不代表**真的启用了站点密码
//     （PASSWORDS 为空时同样返回该文案）；判断站点密码是否启用应看 /api/* 是否先报 CustomAuthPasswordMsg
//   - x-admin-auth 是**明文**比较（includes），而 /open_api/admin_login 是 **sha256** 比较，同一密码两条路提交格式不同
```
