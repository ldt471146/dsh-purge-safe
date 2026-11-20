# SomCNS 站群 CMS 零凭证渲染文章内容：/Home/Index/bbs 可未授权遍历读取 article 表数据（IDOR/未授权访问）

- **code**: somcns-站群-cms-零凭证渲染文章内容-home-index-bbs-可未授权遍历读取-article-表数据
- **kind**: poc
- **category**: unauthorized
- **severity**: medium
- **source**: manual
- **tags**: unauthorized
- **created_at**: 2026-10-28T19:41:01.824Z

## 描述

前台 /Home/Index/bbs 的 post 参数（query 形式 ?post=<id> 与 PATH_INFO 形式 /bbs/post/<id> 均可）不做任何身份校验，游客态直接渲染 article 表中该 id 的记录并输出到页面正文。实测 id=1~1000 返回 25996B 空模板，id=2000/5000/8000/9999/10000/15000 分别返回 27921/42644/125023/27563/27659/187540B 的真实文章正文（id=8000 正文含多条会员发帖「今晚的直接给大家大中了…」「成功收米！」等），说明可无凭据枚举 id 批量拖取全站文章内容；该渲染点未执行任何登录/购买校验（本样本帖价格字段为空，付费绕过未单独坐实）。
