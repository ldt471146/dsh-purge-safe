# GMG 新登录栈（2026-11 实测）

## 现象
- `POST https://www.greenmangaming.com/api/v2/sign_in` 现返回 **403** `{"Message":"This login method is no longer available. Please use the new sign-in."}`（旧配方全部失效）。
- 任意账号/匿名都会触发；`GMGSettings.signInUrl='/sign-in/'`。

## 链路
1. `GET https://www.greenmangaming.com/sign-in/` → 302 `/Account/UtherLogin`
2. `GET /Account/UtherLogin` → 302 `https://account.greenmangaming.com/oauth/authorize/?client_id=episerver&redirect_uri=https%3A%2F%2Fwww.greenmangaming.com%2Fauth%2Faccount%2Fcallback&response_type=code&scope=openid+email+profile&state=...&code_challenge=...&code_challenge_method=S256`
   - 同时下发 `.AspNet.Correlation.Uther`（state 绑定 cookie，必须全程带同一 cookie jar）
3. account.greenmangaming.com 未登录 → 302 `/login/`（Django-allauth 表单、uvicorn、Fastly、CSP `script-src 'self' nonce ... strict-dynamic`）
4. `POST https://account.greenmangaming.com/login/`（`application/x-www-form-urlencoded`，带同一 jar 的 csrftoken/sessionid）
   - 字段：`csrfmiddlewaretoken`、`email`、`password`、`fingerprint_event_id=`（可空）、`submit_token`（页面隐藏域，必须原样取）、`submit=Sign In`
   - 成功 → 302 回 `https://www.greenmangaming.com/auth/account/callback?code=...&state=...`
5. `GET /auth/account/callback?code&state`（带 www 侧 cookie）→ 下发 `.AspNet.ApplicationCookie`，302 到 `/Account/UtherLoginCallback?authEvent=sign_in&authOptIn=false&authMethod=email`
6. **Green Guard**：新设备/IP 首次访问 `GET /api/v2/user_info` 返回 **403 `{"Message":"Green Guard Check"}`**（匿名同 URL 200，可作判据）
   - `GET /api/v2/green_guard/resend_code`（GET，不是 POST；POST 会 405）→ 204，向注册邮箱发 "Green Guard" 验证码（短字母数字，如 TWOR）
   - `POST /api/v2/green_guard/verify` body `{"code":"<码>"}` + `X-XSRF-TOKEN` → `true`
   - 之后 `GET /api/v2/user_info` → 200

## 会话内调用 API 的通用要求
- 每次先 `GET /api/v2/user_info`（会把 XSRF-TOKEN 轮换 92→135 字节），再从 jar 取最新 `XSRF-TOKEN` 作为 `X-XSRF-TOKEN`。
- 带 `Accept: application/json, text/plain, */*`、`X-Requested-With: XMLHttpRequest`、`Gmg-Accept-Language: en`、`Origin/Referer: https://www.greenmangaming.com`。
- 邮箱收信可用 api.mail.tm（本任务自建邮箱；凭据见平台会话/trace，不写库）。

## 失效/旁证
- 旧手机链端点在新栈一律 403：`validate_phone_number_and_send_verification_code` / `set_phone_number` → "Your account details are managed in your GMG account."；`resend_confirmation_code_phone` / `password/forgotten/cognito/sms` → "This login method is no longer available. Please use the new sign-in."
- 新账户中心 `https://account.greenmangaming.com/my-account/` 仅有 change-email / change-password / linked-accounts / marketing；`/authn/forgot-password/` 为邮箱 6 位码；无手机/短信面。
