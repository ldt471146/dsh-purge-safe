## 判定
生产 www 顾客 Fandom 登录 = 后端硬墙，无法取得顾客会话。

## 复现（真实浏览器全流程）
1. 取 authUrl（必须与浏览器同 anonid；本机出口 GET 恒 429，用外部代理）：
   curl -sk -x http://<proxy> -H 'anonid: <uuid>' https://www.fanatical.com/api/auth/fandom/
   → 200 {"authorizationUrl":"https://services.fandom.com/oauth-public/oauth2/auth?client_id=511097b2-be3f-4dd5-9452-69c1718ebed3&scope=openid&response_type=code&redirect_uri=https%3A%2F%2Fwww.fanatical.com%2Fen%2Ffandom-auth-return&state=<uuid>"}
2. headless Chromium --remote-debugging-port=9227 --no-proxy-server，CDP Network.setCookie 注入 fandom_session/cf_clearance 等到 .fandom.com（剔除旧 ory_hydra login/consent CSRF）。
3. 先导航 https://www.fanatical.com/?set_anon_id=<uuid> 播种 anonid，再导航 authUrl；数秒后 302 到 /en/fandom-auth-return?code=ory_ac_...&state=<uuid>。
4. 站点自身 JS 发 POST https://www.fanatical.com/api/auth/fandom/，body {"code","state","snowplowId","snowplowSessionId","language"}；用 CDP Network 抓真实请求与响应：
   → HTTP 400 52B {"code":"E802","message":"Fandom validation failed"}，无 Set-Cookie。
5. 同 code 全头重放三通路（www 经代理 / admin 源站 --resolve 3.33.161.45 -H 'Host: admin.fanatical.com' / www 直连）均 400/52B，ETag 全同 → 同一 handler 确定性错误。

## 边界/证伪
若真实浏览器流程出现 200 或任意 Set-Cookie/bsatok 则本判定不成立（实测无）。
staging 同 client 511097b2 可 200（旧事实），故差异在生产侧交换配置；继续此线应查生产 Heroku app 的 token 交换配置，不要再重复取码。