# PHPWind 7.5 SP3 反序列化判死：全站 0 个魔术方法（无链起点）+ 无 cookie/请求参数来源

- **code**: phpwind-7.5-sp3-反序列化判死-全站-0-个魔术方法-无链起点-无-cookie-请求参数来源
- **kind**: script
- **category**: deserialization
- **component**: PHPWind 7.5 SP3 unserialize 全量 + POP chain 可用性
- **severity**: info
- **language**: php
- **source**: self
- **source_url**: https://www.cnblogs.com/fr09/p/18241189
- **verified_note**: 7.5 SP3 全站 grep 确证（魔术方法 0 命中、Wind 框架符号 0 命中、unserialize 来源逐类核对）。7.3.2 未逐行验证，但 7.3.2 比 7.5 更早、Wind 框架更不可能存在，外推概率极高。公开情报的版本错位已核（该文对应 9.x）。
- **path**: pocs/phpwind-7.5-sp3-反序列化判死-全站-0-个魔术方法-无链起点-无-cookie-请求参数来源/poc.php
- **tags**: phpwind,反序列化,unserialize,POP chain,魔术方法,判死,版本错位
- **created_at**: 2026-10-06T11:59:59.236Z

## 描述

PHPWind 7.5 SP3 反序列化全量审计判死。核心判据：全站 grep 'function __(destruct|wakeup|toString|call|callStatic|get|set|isset|unset|invoke|set_state|clone)' 命中 0 处，只有 __construct（且 unserialize 不调用 __construct），因此对象注入没有链的起点——unserialize 一个对象字符串只会构造普通对象，不会执行任何用户代码。第二判据：329 处 unserialize 的数据来源全部是数据库字段、缓存文件内容、远程响应（需 SSRF/后台）或已 404 的 API 请求体，没有一处来自 $_COOKIE 或直接透传的请求参数。第三：公开的 PHPWind 反序列化 POP chain（PwDelayRun 的 __destruct + call_user_func_array，配 Wind::autoLoad 的 spl_autoload_register）属于 9.x 的 Wind 框架，在 7.5 SP3 里 grep PwDelayRun/spl_autoload_register/Wind::/beforeAction 全部 0 命中，对目标不适用。另附 PHP 5.5.38 上 CVE-2016-7124 与畸形序列化技巧的适用性说明（受影响但无可打目标）。

## 用法

```
证否类结论，不需对目标发包。复用要点：
1) 判任何 CMS 的反序列化，第一步先 grep 魔术方法：`function __(destruct|wakeup|toString|call|get|set|invoke)\(`
   —— 命中 0 就不必再看 unserialize 有多少处，直接结案（链的起点不存在）。
2) 第二步看数据来源：只有 $_COOKIE / $_GET / $_POST / $_FILES 直接透传或可从外部写入的字段才算入口；
   纯 DB 字段 + 缓存文件不算（除非有 SQL 写入或文件写权限）。
3) 见到 PHPWind 反序列化文章先确认版本：带 PwDelayRun / Wind:: / spl_autoload_register / beforeAction
   的是 9.x 的 Wind 框架；7.x 没有这套东西，链与入口都不成立。
```

## 正文

```
// ============================================================================
// 结论：PHPWind 7.5 SP3 反序列化对象注入【彻底不成立】——不是"找不到链"，
//       而是【全站没有任何魔术方法定义】，链的起点不存在。
// ============================================================================
//
// 【一】全站魔术方法普查（grep 结果）
//   grep 'function __(destruct|wakeup|toString|call|callStatic|get|set|isset|unset|invoke|set_state|clone)\s*\('
//   → 【0 命中】
//   grep 'function __(getKeyPrefix|construct)' 之类：
//   · __construct 共 9 处（uc_client/model/{user,notify,credit,app}.php:9、uc_client/control/{user,credit}.php、
//     lang/step/stopicupdator.php:17、uc_client/class_core.php:31、lib/xml.class.php:16、
//     require/postexample.com:16/229、lib/datanalyse.class.php:18）
//   · lib/memcache.class.php:190 的 __getKeyPrefix 是【普通方法】，不是 __get 魔术方法
//   ★ 关键：unserialize() 只触发 __wakeup()，【不调用 __construct】。全站没有 __wakeup，
//     也没有任何其它反序列化相关魔术方法 → unserialize 一个对象字符串只会构造出普通对象，不会执行任何用户代码。
//
// 【二】unserialize( 全量（329 处命中，抽样全核）——数据来源分类
//   A. 数据库字段（绝大多数）：
//      pw_config.db_value（admin/cache.php:563、admin/seoset.php:54、admin/rebang.php:9、lang/step/nav.php:41 等）
//      pw_forums.forumset / creditset（example.com:362-364、m/wap_global.php:22/44、apps/stopic/example.com:31-33）
//      pw_threads.aid（forumcp.php:1491/1506、admin/superdel.php:201/220/435、require/template.php:296、apps/diary/example.com:181/236/545/600）
//      pw_tools.conditions（hack/toolcenter/example.com:150/279/428、require/tool.php:13）
//      pw_tradeinfo / pw_upgrade / pw_rightset / pw_advert.config 等
//   B. 缓存文件内容：admin/setbwd.php:841-847（wordsfb_progress.php）、lib/filterutil.class.php:575（wordsfb.php）
//   C. 远程响应（需 SSRF/中间人，且多为后台功能）：
//      admin/app.php:181/211/248（app.phpwind.net）、lib/appclient.class.php:436、
//      uc_client/model/app.php:132、uc_client/model/notify.php:77/80/101
//   D. API 请求体：api/class_base.php:98 unserialize($request['params'])  ← API 入口在目标上 404（已知情报）
//   ★ 【没有任何一处来源是 $_COOKIE】——cookie 全程只走 StrCode 的异或解密，不进 unserialize
//   ★ 也没有一处来源是 $_GET / $_POST 直接透传（唯一沾边的是 admin/pushdata.php:11
//     unserialize(base64_decode($query))，但那是后台且 $query 来自 DB）
//
// 【三】公开情报的版本错位（重要）
//   博客园《PHP wind反序列化分析》(https://www.cnblogs.com/fr09/p/18241189) 给出的 POP chain 为：
//     class PwDelayRun { private $_callback; private $_args;
//                        public function __destruct() { foreach($this->_callback as $k=>$v) call_user_func_array($v, $this->_args[$k]); } }
//     配合 Wind::autoLoad 的 spl_autoload_register 做类加载，入口是某控制器的 beforeAction 里 unserialize($this->getInput('var'))
//   ★ 这些全部属于【PHPWind 9.x 的 Wind 框架】（namespace src\library\...、WIND_PATH、spl_autoload_register）
//   ★ 在 7.5 SP3 里 grep 'PwDelayRun' / 'spl_autoload_register' / 'Wind::' / 'beforeAction' → 【全部 0 命中】
//   → 该公开链对目标（7.3.2，比 7.5 更早）不适用。不要照抄。
//
// 【四】结论
//   ① 魔术方法 0 → 无 POP chain 起点 → 死（语言层，与版本/清洗/权限无关）
//   ② 数据来源里没有 cookie / 没有直接请求参数 → 即使有链也没有入口 → 死
//   ③ 若 7.3.2 存在 7.5 没有的魔术方法类，需重审；但 7.3.2 更早，Wind 框架尚不存在，概率极低
//
// 【五】PHP 5.5.38 相关技巧说明（供参考，本次无用武之地）
//   · CVE-2016-7124（__wakeup 绕过，属性数大于实际数）影响 PHP 5.6.25 之前 / 7.0.10 之前 → 5.5.38 受影响
//     但本项目【没有任何 __wakeup】，该技巧无目标可打
//   · O:4:"Name":N:{} 的属性名可控（含 \0 前缀的 private/protected 属性名）+ 对象类型混淆在 PHP 5 可用
//     → 同样是"有链才能用"，本项目无链
```
