# 前台会员登录弱口令 test/test 且无验证码无频控，可被在线口令爆破

- **code**: 前台会员登录弱口令-test-test-且无验证码无频控-可被在线口令爆破
- **kind**: poc
- **category**: weak-password
- **severity**: medium
- **source**: manual
- **tags**: weak-password
- **created_at**: 2026-10-28T19:41:01.837Z

## 描述

目标 SomCNS 站群前台登录接口 /Home/Index/login 无验证码、无锁定/频控，实测 test/test 直接登录成功（返回「登录成功」），可带会话读取会员中心用户信息（用户名/余额/等级），并将爆破风险延伸至后台同构登录页模板（username/password 无验证码）。
