# Wix/Velo 匿名 app-instance 令牌越权读 Members：可利用性上限（无批量枚举/无 email/无写/无控制权）

- **code**: wix-velo-匿名令牌读members-可利用性上限-无批量枚举-无email-无写
- **kind**: poc
- **category**: unauthorized
- **component**: Wix / Wix Velo (Wix Members API + _api/v1/access-tokens)
- **severity**: low
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 UTC python3(requests) 经记录代理实测：单条读业主档案 403→200 成立；但 (a) GET /_api/members/v1/members 与 ?limit=50、POST /_api/members/v1/members/query(空filter/分页100) 带 velo 令牌一律 200 members:[] total:0（列表被 scoped 为空，不能枚举他人）；(b) query 加 filter $eq id 多出 contact 对象但 phones:[]/emails:[]/addresses:[] 全空；(c) 随机 GUID 单条读→404 Site member not found；(d) PUT update→404 / PATCH→403 / POST create member→403；(e) Wix Data items/query 各集合→403；(f) contacts/v4/contacts/query→403；(g) ecom/v1/orders/query→403 READ_ORDER_FORBIDDEN；(h) mediaAuthToken 打 /_api/media/*→404；(i) Members Area 应用令牌 14cc59bc/22bef345 打 members→403。结论：上限只到泄露业主自身档(昵称/slug/contactId/Google头像)，无批量 PII/无写/无控制权。
- **tags**: wix,velo,members-api,unauthorized,negative-intel,escalation-ceiling,authz
- **created_at**: 2026-11-11T14:53:59.738Z
- **engine**: https://www.kennysbuyselltrade.co.uk

## 描述

同源正面弹药见 kb#526。本条为负向情报：明确该 403→200 不能扩成批量会员 PII 外泄、不能写、不能拿控制权。避免后续 worker 在同一 Wix 站点上反复尝试 members 列表/query/写接口、wix-data、CRM、orders、media 令牌。适用所有 Wix/Velo 站。
