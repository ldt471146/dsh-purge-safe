# PHPWind 后台登录判据纠正 —— 失败态=14540B+页内计数文案；失败也下发 cookie；必须带 cookie 复访验证

- **code**: phpwind-后台登录判据纠正-失败态-14540b-页内计数文案-失败也下发-cookie-必须带-cookie-复访验证
- **kind**: script
- **category**: auth-bypass
- **component**: PHPWind
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.86/bbs/example.com（Host: example.com，PHPWind 7.3.2 GBK）实测验证：admin/admin 返回 200/14540B 且下发 604b2_AdminUser cookie，初判像成功；带该 cookie 复访 5 个后台页（example.com、?adminjob=main/config/user/db）均返回 3958-3979 字节且 loginform=True，页内明文「密码或安全问题错误,您还可以尝试14次」→ 证实为失败态，避免了一次误报。同时确认失败态尺寸 14540B ≠ 前序记录的 3980B（后者是 CSRF 态）。
- **path**: pocs/phpwind-后台登录判据纠正-失败态-14540b-页内计数文案-失败也下发-cookie-必须带-cookie-复访验证/phpwind_admin_login_judgement.md
- **tags**: phpwind,后台,登录判据,假阳性,gbk,尝试计数器
- **created_at**: 2026-10-15T20:43:42.591Z
- **found_by**: recon

## 描述

PHPWind 后台登录的失败态/成功态正确判据，纠正"3980字节=失败态"与"cookie非deleted=成功"两个流行误判；含 GBK 编码与同源 Referer 要求、尝试计数器发现

## 用法

```
用途：打任何 PHPWind 后台（/example.com）时判定登录成败，避免误报与盲爆破烧光尝试次数。
步骤：
1) GET /example.com → 正则取 verify token；确认页面含 admin_name/admin_pwd
2) POST /example.com?&verify=<t>& ，data = Login_f=1&admin_name=<u>&admin_pwd=<p>&submit=<s>&verify=<t>
   - 中文用户名走 GBK: u.encode('gbk').decode('latin-1') 后 urlencode；整体 data 以 latin-1 编码发送
   - 头必须带 Referer: <同源>/example.com
3) 判成败：先看页内是否含「密码或安全问题错误,您还可以尝试N次」→ 失败；**记录 N 并优先确认它是否重置**
4) 判定成功必须复访：带 Set-Cookie 里的 AdminUser 访问 /example.com 与 ?adminjob=main|config|user|db，若仍含 admin_name/admin_pwd 则是登录表单 → 未认证
需要替换: 目标 URL、Host 头、admin_name/admin_pwd 的值。
```

## 正文

```
## PHPWind 后台登录失败态的正确判据（纠正流传的错误判据）

### 错误判据（勿再使用）
- ❌ "失败态 = 3980 字节" —— 这是**未提交 / CSRF(verify) 校验失败**的纯表单重绘，**根本没走到口令校验**
- ❌ "响应头下发了 AdminUser cookie（非 deleted）就是登录成功" —— **PHPWind 登录失败同样会下发 `AdminUser` cookie** 用于记录尝试状态

### 正确判据（实测确认）
| 状态 | 判定 |
| --- | --- |
| 口令错误 | **HTTP 200, 约 14540 字节**，页内明文 `<p class="b">密码或安全问题错误,您还可以尝试N次</p>` + 「返 回 继 续 操 作」 |
| CSRF/未提交 | HTTP 200, 约 3980 字节，纯登录表单重绘 |
| **真成功** | 必须做**带 cookie 复访**验证：`GET /bbs/example.com`、`?adminjob=main|config|user|db` **不再返回登录表单**（表单特征：页内同时含 `admin_name` 与 `admin_pwd`） |

### 可靠复访验证代码
```python
islogin = ('admin_name' in body) and ('admin_pwd' in body)
# 任一个后台页 islogin=True → 未认证（失败态）
```

### 关键参数（实测）
- 表单字段：`Login_f=1` / **`admin_name`** / **`admin_pwd`**（⚠ 不是 `password`）/ `submit` / `verify`
- URL：`POST /bbs/example.com?&verify=<token>&`
- `verify` 是一次性 token，须先从 `GET /bbs/example.com` 抓取（正则 `admin\.php\?(?:&)?verify=([0-9a-f]+)`）
- 必须带**同源 Referer**（PHPWind `PostCheck()` 要求 Referer host 严格等于 HTTP_HOST）
- GBK 站点：中文用户名须 `s.encode('gbk').decode('latin-1')` 再 urlencode，且 data 以 `latin-1` 编码发送

### ★ 尝试计数器（重要）
失败响应透露剩余次数：「您还可以尝试 **14** 次」→ 存在硬上限（约 15 次）。
**爆破前必须先判断该计数是"总上限"还是"会重置"** —— 若为总上限，盲爆破会把唯一管理员入口永久锁死（不可逆）。
判据：连续发 2 次错误口令，看 N 是否递减；隔一段时间再发，看是否重置。

### 连带发现（方法论）
后台登录页源码里的**绝对 URL**（如 `<img src="http://example.com:1031/...">`）会泄露**自动生成的 vhost**——前缀带随机后缀（`655590com-9hrrz`）的域名**字典爆破永远查不到**，但页面源码里有。见另一条知识库条目。
```
