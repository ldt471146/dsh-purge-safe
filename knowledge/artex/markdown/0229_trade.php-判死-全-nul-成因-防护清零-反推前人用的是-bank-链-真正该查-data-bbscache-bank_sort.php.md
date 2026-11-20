# trade.php 判死 + 全 NUL 成因（防护清零）+ 反推前人用的是 bank 链（真正该查 data/bbscache/bank_sort.php）

- **code**: trade.php-判死-全-nul-成因-防护清零-反推前人用的是-bank-链-真正该查-data-bbscache-bank_sort.php
- **kind**: script
- **category**: app-audit
- **component**: PHPWind trade.php 与全 NUL 文件成因
- **severity**: info
- **language**: php
- **source**: self
- **verified_note**: 7.5 SP3 逐行确证（trade.php 前 110 行 + 全文 grep；全站 98 处 writeover 目标全集；writeover 实现 target105.example.com:231-241；8.7 根目录清单对照）。"全 NUL 由防护工具产生"属技术推断（PHPWind 侧已排除，外部工具无法从源码验证）；7.3.2 是否也有标准 trade.php 未直接验证，但 7.5 与 8.7 均有，外推概率极高。
- **path**: pocs/trade.php-判死-全-nul-成因-防护清零-反推前人用的是-bank-链-真正该查-data-bbscache-bank_sort.php/poc.php
- **tags**: phpwind,trade.php,全NUL,查杀清零,写码点,反推前人payload,bank_sort
- **created_at**: 2026-10-06T12:14:29.401Z

## 描述

trade.php 是 PHPWind 7.5 SP3 与 8.7 都有的标准文件（商品交易中心，pw_trade / pw_tradeorder），action 为 buy/order/pay/pcalipay，buy 需登录（target240.example.com:12）、order 需是买卖双方（:77）、pay 需是买家（:94），全文只操作数据库与两处固定路径 include，没有任何文件写入代码。全站 98 处 writeover(...*.php...) 的目标全是 data/ 下的缓存/配置/风格/分表文件，无一处写根目录 .php，因此没有代码在写 trade.php。关于"7428 字节全 0x00"：writeover 的实现（require/target105.example.com:231-241）是 fwrite + ftruncate(strlen($data))，空数据只会把文件截断成 0 字节，无法产生"保留大小、内容全 NUL"的结果——这是安全防护工具（宝塔木马查杀/安全狗/D盾等）对可疑 PHP 文件的典型处置特征。由此推出最有价值的结论：trade.php 的 NUL 状态是前人落马后被清零的痕迹，说明本站历史上存在过可写 web 目录的 RCE 点；结合前人注册的 ${@eval($a)} / ${@eval($_)} 用户名，可反推其使用的正是 hack/bank 的 savearray 链，真正的写入产物在 data/bbscache/bank_sort.php，应优先观察该文件。

## 用法

```
源码侧答案已给出，目标侧按下列顺序核对（均为只读观察）：
1) 丢弃"trade.php 被写入"的假设 —— 没有任何 PHPWind 代码写根目录 .php。
2) 立刻看 data/bbscache/bank_sort.php：
   - 若有内容且含 "${@eval($a)}" 之类 → 前人 payload 就在文件里，直接按第一轮给的 1 包判定
     `GET /bbs/example.com?H_name=bank&a=echo%20123%3B` 确认 $a 是否可装载。
   - 若该文件的 mtime 很新 → 说明有人（或某个循环任务）在反复重写它。
   - 同时横向比对 data/bbscache/ 下 level.php / wordsfb.php / olcache.php / forumcache.php 的 mtime 是否也异常新。
3) trade.php 的 mtime 与 HTTP 响应：GET /bbs/trade.php 若返回空且 Content-Length 为 0 左右（全 NUL 被解析为空），
   与"防护清零"的判断一致；再试 GET /bbs/trade.php?action=buy 看是否仍是空（若原始文件被替换过，签名/大小会与标准 7.5 的 12600 字节附近不同）。
4) 确认防护类型：观察有无宝塔面板指纹（/pma/、8888 端口、/login 页）、waf 拦截页、文件是否被回滚 —— 这决定后续落马策略。
5) 不要尝试"利用 trade.php"：它是只读 DB 的标准文件，当前内容被清零，无任何攻击面。
```

## 正文

```
// ============================================================================
// 结论：trade.php 是 PHPWind 标准文件、纯数据库操作、【不写任何文件】；
//       全站 98 处 writeover(...*.php...) 无一处写根目录 .php；
//       "7428 字节全 NUL" 用 PHPWind 的代码路径【产生不了】→ 是外部工具清零的痕迹。
// ============================================================================
//
// 【一】trade.php 是什么（7.5 SP3 标准文件，根目录 51 个 php 之一；8.7 也有）
// trade.php:1-3   define('SCR','trade'); require_once('global.php');
// :5              InitGP(array('action'));
// :7  action=buy  商品下单 → :12 if (empty($winduid)) Showmsg('not_login');   ★ 需登录
//                 :19 if ($trade['uid'] == $winduid) Showmsg('onlinepay_goodsbuy');  ★ 不能买自己的
//                 :22-23 InitGP(array('address','consignee','tel','descrip')); InitGP(array('quantity','zip','transport'),2);
//                 :48-65 INSERT INTO pw_tradeorder SET ...（订单编号 :46 '1'+str_pad($winduid,10)+YmdHis+num_rand(5)）
// :71 action=order 查看订单 → :77 if (empty($order) || !in_array($winduid,array($order['buyer'],$order['seller']))) Showmsg('data_error');
// :88 action=pay   付款 → :94 if (empty($order) || $order['buyer'] <> $winduid) Showmsg('data_error');
// 另有 action=pcalipay（被 pw_example.com:1706 / :1881 生成链接引用）
// ★ 涉及的表：pw_trade（商品）、pw_tradeorder（订单）、pw_memberinfo（卖家收款信息，:92）
// ★ 全文 315 行只有 3 处「非 DB」动作：:97 与 :271 的 unserialize($order['tradeinfo'])（来源是 DB 字段），
//   :139/:282 的 include_once(D_P.'data/bbscache/ol_config.php')（固定路径）
// ★ 【没有任何 writeover / fopen / fwrite / move_uploaded_file / include 变量 / eval】→ 不是写入点
//
// 【二】谁在写它 —— 【没有任何代码写根目录 .php】（全站 98 处 writeover 目标全集）
//   · data/bbscache/*.php（绝大多数：forumcache/forum_cache/forumlist_cache/forum_appinfo/forum_typecache/
//     admin_cache/level/gp_right/wordsfb/postcache/bk_config/c_config/cn_config/inv_config/ol_config/md_config/
//     medaldb/mail_config/ftp_config/customfield/setform/help_cache/shortcutforum_cache/topic_config/
//     postcate_config/cache_index/cache_thread/cache_read/cache_post/mode_stamp/mode_block/optimize_*/tagdb/
//     sm_config/ystat/medals_list/myshow_default/hitsort_judge/usersort_judge/replysort_judge_*/feed_cache/
//     member_sort/member_tmp/forum_sort/article_sort/article_tmp/team_sort/favor_sort/admin_sort_*/dblog/ip_cache/
//     commonforum/specialforum/newinfo_config/schwait_cache/set_cache/fcache_*/bank_sort/mode_o_mosort/
//     wordsfb_progress/area_haveused_tpl/mode_index_forum_* 等）
//   · data/forums/fid_N.php（admin/target117.example.com:188）
//   · data/groupdb/group_N.php（admin/target117.example.com:408）
//   · data/style/*.php（admin/target117.example.com:647）
//   · data/sql_config.php（require/target149.example.com:82）
//   ★ 根目录的 trade.php（以及任何根目录 .php）【不在任何一处写入目标里】
//
// 【三】为什么它会全 NUL —— PHPWind 产生不了
// require/target105.example.com:231-241 writeover 实现：
231: function writeover($filename,$data,$method='rb+',$iflock=1,$check=1,$chmod=1){
234: 	touch($filename);
235: 	$handle = fopen($filename,$method);           // 默认 'rb+'
237: 	fwrite($handle,$data);
238: 	$method=='rb+' && ftruncate($handle,strlen($data));   // ★ 截断到 strlen($data)
240: 	$chmod && @chmod($filename,0777);
// → 全站唯一的"清空"写法是 require/target210.example.com:164  writeover(D_P.'data/bbscache/schwait_cache.php','');
//   它的效果是 fwrite('') + ftruncate($handle,0) → 【文件变成 0 字节】，不是"保留大小填 NUL"。
// → 因此"7428 字节全 0x00"不可能由 PHPWind 的 writeover 产生。
//
// 最可能的三种外部成因（按可能性排序）：
// 1) 【安全防护工具的标准处置】宝塔面板「木马查杀」/安全狗/D盾/云锁等，对判定为可疑的 PHP 文件常用做法是
//    「保留文件大小、内容全部填 0x00」——既不删文件（避免站点 500）又让恶意代码失效。
//    特征完全吻合：体积不变、内容全 NUL、HTTP 200 且响应体为空（PHP 解析全 NUL 文件只输出空白）。
// 2) 文件系统/同步损坏（宝塔文件管理、云盘同步、异常断电、ext4 稀疏文件）
// 3) 某代马自身的自清除逻辑
//
// 【四】★ 由此得出的最有价值推论（行动建议）
// trade.php 全 NUL 是【前人落马后被清零的痕迹】，说明本站历史上确实存在过"能写 web 目录 PHP 文件"的 RCE 点。
// 结合已知事实——前人在 pw_members.username 里注册了 ${@eval($a)}(uid=8916) 与 ${@eval($_)} (uid=8913)，
// 而 username 唯二会进 .php 缓存的地方就是 hack/bank/example.com:74 的 savearray → data/bbscache/bank_sort.php——
// 可以反推：前人使用的正是 bank 这条链，他们触发的产物在【data/bbscache/bank_sort.php】。
// ★ 所以真正值得查的是 data/bbscache/bank_sort.php 的内容与 mtime，而不是 trade.php。
//   （另可一并观察 data/bbscache/level.php、wordsfb.php、olcache.php 等同族文件的 mtime 是否异常新）
//
// 【五】战术情报（重要）
// 若 trade.php 确系防护工具清零，则说明本站【存在主动查杀】，任何落地到 web 目录的 PHP 马都有被同样清零的风险。
// 建议：① 落地前先确认防护类型（观察宝塔面板特征、waf 拦截页、文件是否被回滚）；
//       ② 优先使用"不落 PHP 文件"的通道（suo5 隧道走已有 WebShell、或内存马）；
//       ③ 若必须落文件，选择查杀未必覆盖的路径（如 attachment/ 下的图片后缀 + 解析依赖）并立即验证存活。
```
