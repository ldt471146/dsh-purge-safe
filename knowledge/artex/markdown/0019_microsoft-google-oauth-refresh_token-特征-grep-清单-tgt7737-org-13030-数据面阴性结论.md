# Microsoft/Google OAuth refresh_token 特征 grep 清单 + tgt7737-org 13030 数据面阴性结论

- **code**: microsoft-google-oauth-refresh_token-特征-grep-清单-tgt7737-org-13030-数据面阴性结论
- **kind**: script
- **category**: info-leak
- **language**: bash
- **source**: self
- **verified_note**: 阴性结论：在 tgt7737-org 靶标 13030 面板的全量数据面（3 份 105 渠道备份含 3466 个 sk- 密钥、10144 条生成记录、104388 条请求日志、7 个前端 bundle）中，`1//0`/`0.AX`/`M.C5`/`graph.microsoft.com`/`login.microsoftonline.com`/`outlook.office`/`refresh_token` 全部未命中；仅 `rt_`（渠道名子串）与 `EWU`（base64 图片数据）为噪声命中。故该数据面无可用的 Microsoft OAuth refresh_token。
- **path**: pocs/microsoft-google-oauth-refresh_token-特征-grep-清单-tgt7737-org-13030-数据面阴性结论/ms-oauth-token-grep.md
- **tags**: oauth,refresh_token,microsoft,outlook,grep,negative-result
- **created_at**: 2026-09-27T20:05:49.670Z
- **found_by**: exploit

## 描述

在泄漏数据面中检索 Microsoft/Google OAuth refresh_token 的特征串清单与假阳性提醒，并记录 tgt7737-org 13030 数据面的阴性结论（避免后人重复投入）。

## 用法

```
对泄漏的数据文件/前端 bundle 跑正文里的 grep 命令；命中 `1//0` 等语义化前缀后再人工看上下文确认归属（MS 还是 Google）。短串 `rt_`/`EWU` 属噪声，勿作判据。
```

## 正文

```
# 目的
在泄漏的数据面里快速判定有没有可直接使用的 **Microsoft OAuth refresh_token** —— 用于喂给某些未鉴权的 OAuth 兑换代理（例如把 refresh_token 转发给 Azure AD 换取 access_token，再配合同域未鉴权的 IMAP/Graph 邮件读取接口读信）。

# 特征串清单（grep，覆盖 refresh_token 的两种常见形态）
```
1//0            # MS refresh token 最常见前缀（1//0gWZU4MGs9GORCgYIARAAGBAS...）
1//             # 宽松形式
0.AX            # AAD 授权码/令牌流常见片段
M.C5            # 常见 client_id/secret 前缀
graph.microsoft.com
login.microsoftonline.com
outlook.office
refresh_token
refreshToken
```
（Google 侧同理：`1//0g...` 也是 Google refresh_token 前缀，两者都以 `1//` 开头，需结合 `graph.microsoft.com`/`outlook` 之类的旁证区分；纯 `1//` 命中要人工看上下文。）

# 一行式 grep（Windows PowerShell / Linux 通用思路）
```bash
# Linux
grep -rInE '1//0|0\.AX|M\.C5|graph\.microsoft\.com|login\.microsoftonline\.com|outlook\.office|refresh_?[Tt]oken' runs/ --include='*.json' --include='*.js' --include='*.html'
# Windows PowerShell
Get-ChildItem -Recurse -File runs -Include *.json,*.js,*.html | Select-String -Pattern '1//0','0\.AX','M\.C5','graph\.microsoft\.com','login\.microsoftonline\.com','outlook\.office','refresh_token'
```
**假阳性提醒**：`rt_`、`EWU`、`DQV` 这类短串噪声极大（`rt_` 会命中渠道名如 `rtprobe1` 的子串；`EWU` 会命中 base64 图片数据）。**不要把这些短串当凭据判据**，只用上面的语义化前缀。

# tgt7737-org 靶标的实测结论（阴性，记录以免后人重走）
对 `runs/exploit-r2/**` 全量（含 3 份 105 渠道全量备份、3466 个 `sk-` 密钥、10144 条生成记录样本、104388 条请求日志样本、管理前端 7 个 JS bundle）执行上述 grep：
- `1//0`、`0.AX`、`M.C5`、`graph.microsoft.com`、`login.microsoftonline.com`、`outlook.office`、`refresh_token` —— **全部 miss**。
- 仅 `rt_`（渠道名 `rtprobe1` 子串）与 `EWU`（gen_p*.json 中 base64 图片数据的巧合）命中，**均非凭据**。
→ **该靶标已泄漏的数据面里不存在 Microsoft/Google OAuth refresh_token**，不要为这条路径继续投入（除非出现新的数据面）。
（注：同 target 的 9089 GCP 面板确实泄漏过 Google OAuth `refreshToken`（`1//0gWZU...`）与 `clientSecret`，那是**另一个资产的服务端响应**，不在 13030 的面板数据面里。）
```
