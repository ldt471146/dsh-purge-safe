# New API Token Quota 面板 /token-quota.config.json 配置泄露 + 令牌状态判别法（unavailable=存在但禁用）

- **code**: token-quota-panel-config-leak-and-token-status-judgement
- **kind**: poc
- **category**: info-leak
- **component**: New API (modelsell 定制分支) / 自建 Token Quota 面板
- **versions**: modelsell-2026.08.24（New API 定制分支）
- **severity**: medium
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-18 实测 203.0.113.26:8088 与 example.com：config.json 均 200 公开；泄露令牌对 example.com（Via:1.1 Caddy, X-New-Api-Version: example.com）及 4 个同实例 vhost 的 /api/usage/token/ 全部 401 {"message":"This token status is unavailable"}，/v1/models 全部"无效的令牌"——两种文案区分证明令牌存在但禁用，本轮无权限/数据转化。
- **path**: pocs/token-quota-panel-config-leak-and-token-status-judgement/poc.txt
- **tags**: new-api,token-quota,config-leak,sk-token,验活判据,unavailable,modelsell
- **created_at**: 2026-10-17T19:09:50.095Z

## 用法

```
1) curl http://<面板>/token-quota.config.json 拿 sk- 令牌；2) grep 面板 JS（/static/js/main.*.js）找 REACT_APP_BASE_URL 确定真实后端；3) curl -H "Authorization: Bearer <token>" https://<后端>/api/usage/token/ → 401 "This token status is unavailable"=存在但禁用（与"无效的令牌"区分）；4) /v1/models 只作 relay 侧消费能力验证。
```

## 正文

```
## 判据
- sk- 令牌 Bearer 打 `/api/usage/token/`：
  - 401 `{"message":"This token status is unavailable","success":false}` → **令牌在库中存在但被禁用/过期**（禁用令牌走 tokenAuthPrefix 校验，库里有记录所以是"状态不可用"而非"不存在"）。
  - 401 `{"error":{"message":"无效的令牌 ...","type":"new_api_error"}}`（`/v1/*` relay 路径）→ 令牌不存在/已删除。
- 注意：**禁用令牌在 /v1/* relay 路径报"无效的令牌"**——只用 /v1/models 验活会把"存在但禁用"误判成"已删除"。判定状态必须用 /api/usage/token/（或 /api/log/token）。
- /api/log/token 在部分 vhost（api.modelsp.com）404，/api/usage/token/ 全 vhost 一致，优先用后者。

## 背景（ModelSell 自建 Token Quota 面板）
- 面板是 CRA 静态站，nginx 纯托管。**真实后端不在面板所在主机**，由构建期环境变量注入：JS 内 `REACT_APP_BASE_URL='{"server1": "https://example.com"}'`，请求 `S+"/api/usage/token/"` 与 `S+"/api/log/token"`，`Authorization: Bearer <sk-token>`。
- 面板配置文件 `/token-quota.config.json` 随站点公开，明文返回 `{"tokens":{"sk-...":{"discount":4}}}`（8088 与 example.com 两处部署同 hash main.acf0e149.js、同配置）。验活时先 grep 面板 JS 的 REACT_APP_BASE_URL 找真实后端，别只测面板主机上的端口。

## 本次实测
- 目标 203.0.113.26:8088 /token-quota.config.json → 200（nginx/1.19.0，无鉴权）。
- 泄露令牌对 example.com / example.com / www.modelsell.cc / api.lovtokens.com / api.modelsp.com 全部：/api/usage/token/ → 401 unavailable；/v1/models → 401 无效的令牌。结论：存在但禁用，不可利用。
- example.com 与 example.com 同实例（X-New-Api-Version 一致，Via: 1.1 Caddy；--resolve 直连源站 Host 被接受）。
```
