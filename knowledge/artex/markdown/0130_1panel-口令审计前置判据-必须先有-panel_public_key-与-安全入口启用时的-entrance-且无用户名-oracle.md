# 1Panel 口令审计前置判据：必须先有 panel_public_key 与（安全入口启用时的）entrance，且无用户名 oracle

- **code**: 1panel-口令审计前置判据-必须先有-panel_public_key-与-安全入口启用时的-entrance-且无用户名-oracle
- **kind**: script
- **category**: weak-password
- **component**: 1Panel
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 codex-miaomiaocode-com 靶标实测：① ddddocr 对 203.0.113.51:9527 的 1Panel v2 验证码 11/12 通过（92%），用登录响应 ErrAuth/ErrCaptchaCode 做 ground truth；② 203.0.113.109:9527（1Panel v1）对 13 条路由 dump 响应头**无任何 panel_public_key**，而 v1.10.28-LTS 的 DecryptPassword 强制三段式 ⇒ 该面板口令审计不可进行（vuln 53 / evidence 40）；③ 203.0.113.51:9527 有安全入口，匿名 passkey 路由回 "安全入口信息错误"；④ 用正确验证码 + 畸形密文在 v2 仍得 ErrAuth ⇒ 无用户名 oracle；⑤ 41 个候选用户名在 v1 全部 ErrAuth ⇒ 用户名非默认。
- **path**: pocs/1panel-口令审计前置判据-必须先有-panel_public_key-与-安全入口启用时的-entrance-且无用户名-oracle/1panel_password_audit_preconditions.md
- **tags**: 1panel,口令审计,前置条件,panel_public_key,RSA三段式,安全入口,ddddocr,验证码,用户名oracle
- **created_at**: 2026-09-30T01:01:40.730Z
- **found_by**: exploit

## 描述

1Panel 口令审计的三个隐形前置：① 必须拿到 panel_public_key（部分实例不下发，缺它则密文无法构造，审计在密码学上不可进行）；② 安全入口启用时口令正确也只得 ErrEntrance；③ 无用户名 oracle（v2 的 ErrAuth 同时覆盖用户名错与解密失败）。并给出 ddddocr 92% 自动过验证码 + 用登录响应做 ground truth 验准确率的方法。

## 用法

```
1) 判能不能打：`curl -s -D - -o NUL http://T:9527/api/v1/dashboard/base/os`（v1）/ `/api/v2/core/auth/captcha`（v2）看有没有 `Set-Cookie: panel_public_key` —— **没有就别投字典**；2) 判安全入口：`curl -s http://T:9527/` 返回 200.html/"Access Temporarily Unavailable" 即启用，此时即使口令正确也只能得 ErrEntrance，先想办法拿 entrance；3) 拆验证码：`pip install ddddocr`，用 ddddocr_accuracy.py 的「取图→识别→提交→按 ErrAuth/ErrCaptchaCode 判对错」自测准确率（1Panel 实测 92%）；4) 只有「无安全入口 + 下发公钥」才投字典，且要整体猜 (用户名, 口令)。
```

## 正文

```
# 1Panel 口令审计的三个隐形前置（不满足则整条路在密码学上走不通）

前序知识库条目（`1panel-login-password-encryption-rsa-aes-3seg` 等）只讲了「三段式加密格式」，实战还有三个坑，踩了会白跑：

## 前置 0：验证码门槛已可自动化拆掉
- `pip install ddddocr`（自带 onnx 模型）对 1Panel 的 120×50 四位验证码 **实测 11/12 通过（92%）**。
- **准确率用登录响应做 ground truth，不需要人工验图**：每轮「取图 → ddddocr → POST login(ignoreCaptcha:false) → 看响应」：
  - `ErrAuth` = 验证码通过（口令阶段被判错）
  - `ErrCaptchaCode` = 识别错
  脚本：`ddddocr_accuracy.py`（12 轮 0.6s 间隔，无 429）。
- 所以「每次尝试要人工识图」不再是瓶颈；自动速率≈1.1 请求/次尝试。

## 前置 1（最致命）：必须有 `panel_public_key`，否则密文根本构造不出来
服务端解密是硬要求（v1.10.28-LTS `backend/utils/encrypt/encrypt.go`）：
```go
func DecryptPassword(encryptedData string, privateKey *rsa.PrivateKey) (string, error) {
	parts := strings.Split(encryptedData, ":"); if len(parts) != 3 { return "", errors.New("encrypted data format error") }
	encryptedAESKey, _ := base64.StdEncoding.DecodeString(parts[0])
	aesKey, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptedAESKey)   // ← 必须有公钥才能构造
	...
}
```
- 公钥通过 **`Set-Cookie: panel_public_key`**（base64 的 PEM）下发，**但并非每台面板都下发**：
  - ✅ 会下发：如 203.0.113.110:9527、203.0.113.117:9527、203.0.113.51:9527（v2 的 `/api/v2/core/auth/captcha`）
  - ❌ 不下发：如 **203.0.113.109:9527**（对 `/`、`/api/v1/auth/captcha`、`/api/v1/dashboard/base/os`、`/api/v1/settings/search`、`/api/v1/containers/list`、`/api/v1/files/search` … 共 13 条路由逐个 dump 响应头，**全无该 cookie**）
- **不下发 = 该面板口令审计不可进行**（除非面板版本老到接受明文，可用「明文口令 → 若用户名正确会返回 raw 解密错误而非 ErrAuth」来反推，见下）。
- 判据脚本：`panel52_cookiehunt.py`（对一组路由 dump 响应头找 `Set-Cookie`）。

## 前置 2：安全入口启用时，口令正确也登录不了
`Login()` 里入口校验在口令校验**之后**：
```go
if nameSetting.Value != info.Name { return nil, constant.ErrAuth }
if err = checkPassword(info.Password); err != nil { return nil, err }
if len(entranceSetting.Value) != 0 && entranceSetting.Value != entrance { return nil, buserr.New(constant.ErrEntrance) }
```
⇒ 安全入口启用（且没有 entrance）的面板，**即使猜到正确口令也只能拿到 `ErrEntrance`**，拿不到会话；entrance 只能 `1pctl user-info`（SSH）看。
（旁证：v2 的匿名 `POST /api/v2/core/auth/passkey/begin` 也返回 `{"code":401,"message":"安全入口信息错误，请检查后重试！"}`）

## 前置 3：没有用户名 oracle，用户名和口令得同时猜
`Login()` 先比用户名再验口令。理论上「错用户名→ErrAuth、对用户名+畸形密文→raw 解密错误」可当 oracle，**但 v2 实测不成立**：用**正确验证码** + 畸形密文 `AQ==:AAAA:AAAA`（1 字节 RSA 段）提交，仍返回 `ErrAuth` ⇒ 无法区分「用户名错」与「解密失败」。
因此实战只能整体猜 (用户名, 口令) 组合；实测 41 个常见用户名（1panel/admin/root/zwluoqi/miaomiaocode/blueseek/pockgo/example/bd2/tangguosheng…）+ 垃圾口令全部 ErrAuth，**该运营者的面板用户名非默认**。
（v1 源码里 `checkPassword` 的报错是 `errors.New(...)` 而非 `constant.ErrAuth`，所以在 v1 上 oracle 理论上成立；但 v1 那台恰恰没有公钥，走不通。）

## 结论判据（先判能不能打，再动手）
1. `curl -s -D - -o NUL http://T:9527/api/v1/dashboard/base/os`（v1）或 `curl -s -D - -o NUL http://T:9527/api/v2/core/auth/captcha`（v2）→ **有 `panel_public_key` 才继续**。
2. 有安全入口（返回 200.html / "Access Temporarily Unavailable"）→ **先确认能不能拿到 entrance**，否则口令审计的收益只是 `ErrEntrance`，不产生会话。
3. 只有「无安全入口 + 下发公钥」的面板才值得投字典。

```
