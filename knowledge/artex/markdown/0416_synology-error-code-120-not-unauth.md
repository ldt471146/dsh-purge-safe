# 群晖 DSM code 120 判读纠错 —— 参数校验先于权限，不可误判为未授权

- **code**: synology-error-code-120-not-unauth
- **kind**: script
- **category**: methodology
- **component**: Synology DSM 错误码
- **severity**: low
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.39（群晖 DS918+ DSM 7.2.x）实测验证：SYNO.FotoTeam.Browse.Item 首次返回 code 120（缺 offset），补 offset 后返回 code 120（缺 limit），补 offset+limit 后返回 code 801（权限不足）。同时确认 SYNO.Foto.Setting.Guest 返回 200 + 真实配置数据（真未授权），FileStation 全系列返回 119。据此确立"参数校验先于权限校验"的判读规则。
- **path**: pocs/synology-error-code-120-not-unauth/dsm_error_code_120_reading.md
- **tags**: 群晖,DSM,错误码,判读,未授权,误报,参数校验,测试方法论
- **created_at**: 2026-10-15T21:36:31.971Z
- **found_by**: vuln-scan

## 描述

群晖 DSM 错误码判读的实战纠错：code 120（缺参数）的校验先于权限校验，导致任何 API 在参数不全时都返回 120，看起来像未授权可访问；补全参数后才暴露真实的 801（权限不足）/103（需认证）。附完整错误码对照表与正确测试姿势，避免把需认证接口误报成未授权漏洞。该模式在 Spring Security / DRF 等框架中同样存在。

## 用法

```
看到群晖 API 返回 code 120 时：
1) 读 target447.example.com 找出缺的参数，循环补齐（往往补 2-3 轮）
2) 只有最终返回 200 且 data 非空，才判定为未授权
3) 补齐后返回 801 = 权限不足；103 = 需认证 → 都不是未授权
对照表：120=缺参数 / 119=API不存在 / 102=参数错 / 103=需认证 / 801=权限不足 / 200+data=真未授权
```

## 正文

```
# 群晖 DSM 错误码判读经验 —— code 120 会伪装成"未授权可访问"，必须补全参数再判定

## 事故场景（差点误报）
```
GET /webapi/entry.cgi?api=SYNO.FotoTeam.Browse.Item&version=1&method=list
→ {"error":{"code":120,"errors":{"name":"offset","reason":"required"}},"success":false}
```
看到 `120`（缺参数）而**不是** `103`（需认证），容易误判为"该 API 未授权可访问"。

## 实际是三层校验，顺序为：参数 → 认证 → 权限
```
第一次请求（无参）        → code 120  {"name":"offset","reason":"required"}
补 offset=0              → code 120  {"name":"limit","reason":"required"}
补 offset=0&limit=100    → code 801  ← 权限不足（真实结论）
```
→ **群晖的【参数格式校验先于权限校验】**。因此只要参数不全，任何 API 都会返回 120，
   看起来像"未授权"，补齐参数后才暴露真实的 801/103。

## 判读规则（务必遵守）
| 错误码 | 含义 | 是否代表"未授权可访问" |
|---|---|---|
| **120** | 缺少必填参数（`target447.example.com` 指明缺哪个） | **否** — 必须补全参数再测 |
| **119** | API 不存在 或 method/version 不匹配 | 否 |
| **102** | 参数错误 / 方法不支持 | 否 |
| **103** | 需要认证 | 否（需凭据） |
| **400** | 登录时：账号不存在 | — |
| **801** | 权限不足（参数齐了但没权限） | 否 |
| **200 + 真实 data** | 真未授权 | **是** |

## 正确姿势
```bash
# 1) 第一次返回 120 时，看 target447.example.com 指的缺哪个参数，循环补齐
curl -s "$B/webapi/entry.cgi?api=$API&version=1&method=$M"            # 缺 offset
curl -s "$B/webapi/entry.cgi?api=$API&version=1&method=$M&offset=0"   # 缺 limit
curl -s "$B/webapi/entry.cgi?api=$API&version=1&method=$M&offset=0&limit=100"  # 801 = 结论
# 2) 只有返回 200 且 data 非空，才算真未授权
```

## 本次实测对照
- `SYNO.FotoTeam.Browse.Item` → 120 → 120 → **801**（需认证，非未授权）
- `SYNO.Foto.Setting.Guest`    → **200 + 真实 data**（真未授权，但仅泄露访客配置，低价值）
- `SYNO.FileStation.*` v1/v2 全系列 → **119**（API 路径/版本不匹配）
- `SYNO.Foto.Browse.*` 系列    → **119**
- `SYNO.Foto.Search.Search` / `Sharing.Passphrase` / `Download` → **103**（需认证）

## 同源经验（通用）
这个"参数校验先于权限"的模式在很多系统中都存在（Spring Security 过滤器链、
Django REST Framework 的 serializer 校验等）。**看到"缺参数"类错误时，
不能判定为未授权 —— 必须补全参数，否则会把大量需要认证的接口误报成未授权漏洞。**

```
