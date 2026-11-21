# cloud-mail 认证机制与探测要点（JWT + KV 双校验 / /init secret 预言机 / KV 键名规律）

- **code**: cloud-mail-认证机制与探测要点-jwt-kv-双校验-init-secret-预言机-kv-键名规律
- **kind**: script
- **category**: auth-bypass
- **component**: cloud-mail (maillab/cloud-mail)
- **versions**: cloud-mail v1.1.0 与 v1.5.0（认证逻辑一致）
- **severity**: medium
- **language**: javascript
- **source**: web
- **source_url**: https://github.com/maillab/cloud-mail
- **verified_note**: 【项目识别有误 —— 本条不适用于 codex-miaomiaocode-com 靶标，保留供对比参考】本条描述的 maillab/cloud-mail（JWT 验签 + KV auth-uid:<userId> 双校验、/init secret 预言机、KV 键名规律）是真实存在的另一套 CF Workers 邮箱系统，但**不是**本靶标 example.com / example.com 实际使用的系统 —— 后者的 /open_api/settings 字段（disableAdminPasswordCheck / enableAddressPassword / statusUrl / enableGlobalTurnstileCheck）、官方认证头（x-admin-auth / x-user-token）与失败文案（"Invalid address credential"）全部对应 dreamhunter2333/cloudflare_temp_email，其 /api/* 走 address JWT + `SELECT id FROM address WHERE id=? AND name=?` 查库二次校验，与 KV 完全无关。因此本条中"两条路拿 uuid 均不通"的结论建立在错误源码上，不可用于本靶标。本靶标的正确分析见知识库条目 cloudflare_temp_email 认证机制与攻击面。教训：仅凭"CF Workers 邮箱系统 + 单账号管理面板 + /open_api/settings"就把开源项目认错，会让整套否定结论失效；定项目必须逐字段比对 /open_api/settings 返回值或官方文档里的认证文案。
- **path**: pocs/cloud-mail-认证机制与探测要点-jwt-kv-双校验-init-secret-预言机-kv-键名规律/cloud-mail-auth-analysis.md
- **tags**: cloud-mail,cloudflare-workers,jwt,kv,认证机制,预判否定
- **created_at**: 2026-09-29T20:19:08.467Z
- **found_by**: vuln-scan

## 描述

cloud-mail（maillab/cloud-mail，CF Workers 邮箱系统，2 万+ fork）完整认证机制分析：JWT(HS256,裸 token 无 Bearer 前缀) + KV auth-uid:<userId>.tokens 双校验；附带 /init/<secret> 预言机、/open_api/settings 泄露点、KV 键名规律与三条常见误判坑。用于判断"弱 jwt_secret 伪造 token"是否可行、以及快速定位部署配置泄露。

## 用法

```
1) 先 GET /open_api/settings 确认是 cloud-mail 及版本与域名面；
2) 判断能否伪造 token：需同时具备 (a) env.jwt_secret、(b) KV auth-uid:<userId> 中在册 uuid 二者缺一不可 —— 只有 (a) 时不要浪费轮次爆破；
3) 想确认 jwt_secret 时用 /init/<secret> 作预言机（注意会触发 DB 迁移，生产谨慎）；
4) 有暴露的 KV 读取端点时，用 auth-uid:<n> / setting: / send_day_count:<n> 精确探；
5) 发 Authorization 时必须是裸 JWT，切勿加 "Bearer " 前缀。
```

## 正文

```
// cloud-mail 认证机制（源码定性，含关键判定点与两条可复用探测原语）
//
// === 1. 鉴权中间件 mail-worker/src/security/security.js ===
// app.use('*', async (c, next) => {
//   const path = c.req.path;
//   if (path.startsWith('/test')) return await next();          // ★ 无认证放行
//   if (exclude.some(i => path.startsWith(i))) return await next();
//   const jwt = c.req.header(constant.TOKEN_HEADER);            // 'Authorization'
//   const result = await jwtUtils.verifyToken(c, jwt);
//   if (!result) throw new BizError('authExpired', 401);
//   const { userId, token } = result;
//   const authInfo = await c.env.kv.get('auth-uid:' + userId, { type: 'json' }); // ★ 二次校验
//   if (!authInfo) throw new BizError('authExpired', 401);
//   if (!authInfo.tokens.includes(token)) throw new BizError('authExpired', 401);
//   ... requirePerms 权限判定（authInfo.user.email === c.env.admin 直接放行）
//   c.set('user', authInfo.user);
//   return await next();
// });
//
// ★ 判定结论：仅拿到 env.jwt_secret **不足以**伪造可用 token ——
//   JWT 里的 token 字段必须命中 KV auth-uid:<userId>.tokens 数组，而该 uuid
//   只在 login-service.login() 成功时由服务端 uuidv4() 生成写入。
//
// === 2. token 格式 mail-worker/src/utils/jwt-utils.js ===
// verifyToken(c, token) { const [h,p,s] = token.split('.'); ... }   // ★ 直接 split
//   → Authorization 头必须是**裸 JWT**，写成 "Bearer <jwt>" 会使 h="Bearer eyJ..." 验签失败
// HS256 / 密钥 c.env.jwt_secret / 仅校验 payload.exp（无 exp 也通过）
// payload 结构：{ userId, token, iat [, exp] }   TOKEN_EXPIRE = 60*60*24*30
//
// === 3. 可复用探测原语 ===
// (a) /init/<secret> —— jwt_secret 预言机（源码：init/init.js）
//     const secret = c.req.param('secret');
//     if (secret !== c.env.jwt_secret) return c.text('jwt_secret 不匹配');
//     await this.intDB(c); ... v1_1DB..v1_5DB; return c.text(t('initSuccess'));
//     ⚠ 命中即执行 DB 迁移（ALTER TABLE / UPDATE perm / settingService.refresh），
//       有业务影响且 CREATE TABLE IF NOT EXISTS 对已存在表跳过（修不了缺列），
//       谨慎使用；默认值线索：wrangler-dev.toml / wrangler-test.toml 里写死
//       jwt_secret = "b7f29a1d-18e2-4d3b-941f-f6b2c97c02fd"
// (b) /open_api/settings —— 免认证泄露部署配置（defaultDomains 全量邮件域名、
//     version、needAuth、enableUserCreateEmail、disableAdminPasswordCheck 等）
//
// === 4. KV 键名规律 mail-worker/src/const/kv-const.js ===
//   AUTH_INFO: 'auth-uid:'   → auth-uid:<userId> = {tokens:[uuid...], user:{...}, refreshTime}
//   SETTING:   'setting:'
//   SEND_DAY_COUNT: 'send_day_count:'
//   → 若目标另有暴露的 KV 读取端点（如本项目遇到的 /get?key=），用这些 key 精确打
//
// === 5. 常见坑 ===
// - exclude 用 path.startsWith()，而线上路由统一挂 /api 前缀时 exclude 全部失效
//   （表现为 /api/login 也被自身中间件拦成 401 "Invalid address credential"，
//    即 authExpired 的英文文案）→ 登录功能不可用，但也不是绕过
// - /api/new_address 是少数能过中间件的写入端点，可用它判断站点是否允许匿名建邮箱
//   （403 New address is disabled / 400 D1_ERROR no such column: password 等）
// - 报错文案 "Invalid address credential" 即 authExpired，**验签失败与 KV 无记录不可区分**
//   → 不要用它当作 jwt_secret 是否正确的判据
```
