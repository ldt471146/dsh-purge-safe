# 若依系前台登录「请求加密守卫」绕过（isEncrypt/AES-ECB + RSA encrypt-key，前端硬编码密钥对）

- **code**: ruoyi-vueplus-frontend-encrypt-guard-bypass
- **kind**: script
- **category**: auth-bypass
- **component**: RuoYi-Vue-Plus / 若依系（dromara）前后端分离后台
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com（203.0.113.121，深蓝云 203.0.113.120/24）实测：明文 body → 200 {"code":403,"msg":"没有访问权限，请联系管理员授权"}；加密 body → 200 {"code":500,"msg":"Sorry, your account: zzqarepro0001 does not exist"}。RSA 公钥/私钥、AES 模式（ECB/PKCS7）、clientId=e5cd7e4891bf95d1d19206ce24a7b32e、grantType=password 均从 /assets/index-Bigtxz2h.js 静态提取，复现客户端见 runs/zfclient.py，原始报文见 runs/zf-bypass-raw-request.txt。
- **created_at**: 2026-10-02T15:01:55.228Z
- **found_by**: exploit

## 描述

若依系（dromara/RuoYi-Vue-Plus 及其大量二次开发衍生后台）的登录接口常带「请求必须加密」的前置守卫：明文 JSON body 会被判为非法请求并返回 403（形如 {"code":403,"msg":"没有访问权限，请联系管理员授权"}），极易被误判成 IP 白名单/来源访问控制而放弃。实际只需按前端真实契约加密即可放行。

原理：前端 bundle 里登录函数带 headers:{isToken:!1, isEncrypt:!0}，Axios 请求拦截器在 isEncrypt 为真时：
  · 生成 32 位随机 hex 字符串作为 AES key
  · body = base64(AES-ECB/PKCS7(JSON.stringify(data)))
  · 请求头 encrypt-key = base64(RSA_PKCS1v15(base64(aesKey)))（用前端硬编码 RSA 公钥）
  · 响应若带 encrypt-key 头则用**前端硬编码 RSA 私钥**解密响应
即 RSA 密钥对（公钥与私钥）都静态写在前端里，加密形同虚设，可离线完整复现。

绕过收益：403 守卫被绕过 → 登录接口恢复真实业务语义（返回"账号不存在"/"密码错误 N 次"），从而获得账号存在性枚举与受限的口令尝试能力。注意不少实现带口令失败计数器（RuoYi 默认 5 次锁定，且锁为时间窗，实测窗口过后计数归零）。

## 用法

```
1) 下载入口 bundle（通常 /assets/index-<hash>.js），grep 关键字：`isEncrypt`、`encrypt-key`、`url:\`/auth/login\``、`AES.encrypt`、`setPublicKey`、`setPrivateKey`，提取 RSA 公钥/私钥 Base64 与 AES 参数。
2) 用 runs/zfclient.py 作为模板：Z.call('/prod-api/auth/login','POST',{username,password,clientId,grantType:'password'},encrypted=True)。
3) 若返回 "does not exist" 即守卫已绕过且存在账号枚举；若返回 "Password input error N times" 说明账号真实存在并带计数，须严格控次。
4) 同时用同一 clientId 与请求头 `clientid: <clientId>`（缺 clientId 会返回 "Auth clientid cannot be blank"）。
```
