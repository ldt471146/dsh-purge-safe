# cloudflare_temp_email example.com 鉴权模型与匿名端点 oracle（地址存在性枚举）

- **code**: cloudflare_temp_email-example.com-鉴权模型与匿名端点-oracle-地址存在性枚举
- **kind**: template
- **category**: unauthorized
- **component**: cloudflare_temp_email
- **versions**: &lt;= v1.1.0（v1.5.0 已改为 addressJwtAuth 具名中间件，白名单收敛为三处，同名 oracle 需重测）
- **severity**: medium
- **language**: http
- **source**: self
- **source_url**: https://github.com/dreamhunter2333/cloudflare_temp_email/blob/v1.1.0/worker/src/worker.ts
- **verified**: 1
- **verified_note**: 在 example.com（203.0.113.22，cloudflare_temp_email example.com）实测确认：/api/* 前缀级 401 一致性、白名单仅 /api/new_address 与 /api/address_login、address_login 401/404 oracle 可用并成功枚举出 user@example.com / user@example.com / user@example.com，new_address 回 D1_ERROR no such column: password 且地址经 oracle 复核确实落库。鉴权侧证伪项：JWT_SECRET 字典 169 候选与 ADMIN_PASSWORDS 字典 89 候选均未命中，/telegram/* 未部署 bot，/user_api 注册禁用且 OAuth2 未配置。
- **tags**: cloudflare_temp_email,临时邮箱,未授权,用户枚举,版本差异分析
- **created_at**: 2026-09-27T20:04:26.562Z
- **found_by**: exploit

## 描述

cloudflare_temp_email example.com 版本的鉴权模型与两个匿名白名单端点的判定手法。example.com 的 worker.ts 第147行起对 /api/* 挂了全局地址 JWT 中间件 jwt({secret: JWT_SECRET, alg:"HS256"})，因此任意 /api/* 路径（哪怕不存在）在无 Authorization 头时都统一回 401 "Invalid address credential"——这点可反向用于版本指纹判定：若某路径回 401 而非 404，说明它落在这层前缀级全局鉴权下。该中间件内仅有两处匿名例外，均用 startsWith 前缀匹配：/api/new_address（只调 checkUserPayload 读可选 x-user-token，失败不阻断）与 /api/address_login（直接 next()）。据此可定：匿名可打的就只有这两个端点。/api/address_login 是纯查询零副作用的存在性 oracle（404=不存在，401=存在），且不在 RATE_LIMITER/checkAccessControl 限流名单内（该名单仅含 new_address、send_mail、external/api/send_mail、user_api/register、user_api/verify_code），可无凭据无限速枚举。/api/new_address 受 ENABLE_USER_CREATE_EMAIL / DISABLE_ANONYMOUS_USER_CREATE_EMAIL / DISABLE_CUSTOM_ADDRESS_NAME 与 Turnstile（/open_api/settings 是否返回 cfTurnstileSiteKey 字段）共同控制，注意 example.com 源码 common.ts 的 INSERT 语句不含 password 列，若目标 D1 缺少该列（老 schema 未迁移），地址会被真实写入但 generatePasswordForAddress 抛错，导致 400 与 JWT 永不返回——此时 /api/new_address 变成一个"能占位但拿不到凭据"的畸形端点，同时使 address_login 的明文比对（address.password !== password）恒为 true，空口令/明文绕过同样不成立。同类实例判定要点：先 GET /open_api/settings 读 version 与 enable/disable 开关，再对照同 tag 源码的 worker.ts 鉴权中间件与路由表，最后逐条实测 401/404 差异。

## 用法

```
1) 指纹与配置：curl -sS -x $PROXY -A "$UA" https://TARGET/open_api/settings —— 读 version / needAuth / enableUserCreateEmail / disableCustomAddressName / enableAddressPassword / disableAdminPasswordCheck / domains / 有无 cfTurnstileSiteKey。2) 判版本鉴权：对 /api/mails、/api/settings 打无凭据请求，回 401 "Invalid address credential" 即落到 v1.1.x 式前缀级全局地址 JWT 中间件。3) 枚举地址：./cloudflare_temp_email_v110_unauth_addr_enum.sh https://TARGET （401=存在 / 404=不存在）。4) 建址探针：curl -X POST https://TARGET/api/new_address -H 'Content-Type: application/json' --data-binary '{"name":"probe1","domain":"<domains[0]>"}' —— 回 D1_ERROR 说明 schema 旧且地址已落库。5) 读邮件需要地址 JWT：仅 /api/new_address（本实例因缺列不可用）、/api/address_login（需密码）、/admin/show_password/:id（需 ADMIN_PASSWORDS）、/user_api/bind_address_jwt/:address_id（需已绑定 user）四个签发点，务必逐一确认可达性再投入。
```
