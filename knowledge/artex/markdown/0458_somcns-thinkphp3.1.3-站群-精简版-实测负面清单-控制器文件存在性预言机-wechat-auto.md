# SomCNS/ThinkPHP3.1.3 站群「精简版」实测负面清单 + 控制器文件存在性预言机（Wechat/Autoart 脱队控制器不存在、Admin 闸门与 Host 无关）

- **code**: somcns-thinkphp3.1.3-站群-精简版-实测负面清单-控制器文件存在性预言机-wechat-auto
- **kind**: exp
- **category**: auth-bypass
- **component**: SomCNS 六合彩/聚宝阁站群 CMS（ThinkPHP 3.1.3）
- **severity**: medium
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-28 在 192.0.2.1:80（Host: target475.example.com）实测：① GET /index.php?g=Admin&m=Wechat&a=index_1 与 a=index(echostr=MK_WECHAT_ORACLE)、m=Autoart&a=kjer 全部稳定 404/146B（CDN 192.0.2.3/.84 同）；② 控制器文件预言机 GET /App/Lib/Action/Admin/<X>Action.class.php/x：User/Index/Main/System/Admin/Block/Article/Payorder=200 且 "Fatal error: Class 'CommonAction' not found in /www/wwwroot/thisthbweb_com/App/Lib/Action/Admin/UserAction.class.php"，Wechat/Autoart/Api/Order/Notice 等 33 个候选=404；③ /App/Tpl/Admin/Wechat_index.html、Autoart_kjer.html 等均 404，而 User_index.html/Index_login.html=200；④ /Admin/Index/login 在随机 Host、空 Host、20 个 *.target477.example.com 候选下一律 302 Location: /（仅 Host=IP 时 nginx 403），同批 / 与 /Home/Index 均 200/336622B；⑤ 192.0.2.2 为纯静态落地页（/List/ 200，/index.php 稳定 500），非站群应用。curl --noproxy '*' 复核结果一致。
- **path**: pocs/somcns-thinkphp3.1.3-站群-精简版-实测负面清单-控制器文件存在性预言机-wechat-auto/poc.md
- **tags**: thinkphp3.1.3,站群,somcns,负面情报,控制器枚举,鉴权闸门,Host白名单证否
- **created_at**: 2026-10-28T18:11:05.664Z
- **engine**: 192.0.2.1 / target475.example.com / target479.example.com

## 描述

对同族但不同安装的 SomCNS TP3.1.3 站群做攻击前的判否依据：不是每台都装了 Wechat/Autoart 这类 extends Action 的脱队控制器；本靶标是"菜单式精简版"，Admin 组只有 8 个控制器且全部 extends CommonAction。同时给出两个更可靠的判定工具：控制器文件存在性预言机 + 「302 是否与 Host 相关」的对照实验。

## 正文

```
## 1) 控制器文件存在性预言机（比 ?g=&m= 的 404/302 二分精确得多）
```
GET /App/Lib/Action/<Group>/<Name>Action.class.php/<任意尾段>
```
- 文件存在 → 被 PHP-FPM 直接执行（PATH_INFO 绕过），display_errors=On 时回显
  `Fatal error: Class 'CommonAction' not found in /www/wwwroot/<项目>/App/Lib/Action/Admin/<Name>Action.class.php on line N`（200）
- **父类名直接暴露鉴权继承关系**：报 `Class 'CommonAction' not found` = 走后台闸门；
  报 `Class 'Action' not found` = extends Action，**脱队控制器**（这正是要找的目标）。
- 文件不存在 → nginx 404 146B。
- 校准：Admin/UserAction→EXISTS(CommonAction)，Admin/WechatAction→404，Home/OrderAction→EXISTS(Action)。

## 2) 本靶标实测结果（176 = 192.0.2.1，域名 target475.example.com / *.target476.example.com）
- Admin 组控制器全集：Index / User / Main / System / Admin / Block / Article / Payorder（8 个，**全部 extends CommonAction**）。
- Wechat / Autoart / Api / Order / Notice / Message / News / Upload / Member / Config / Coupon / Pay / Payment / Ad / Link / Sms / Tool / Db / Backup / Cron / Task / File / Log / Kj / Open / Service / Set / Setup / Menu / Group / Role / Report / Finance / Withdraw / Deposit / Charge / Bonus / Activity / Share / Agent = **全部 404（文件不存在）**。
- 模板面交叉验证：/App/Tpl/Admin/Wechat_index.html、Wechat_index_1.html、Autoart_index.html、Autoart_kjer.html、Api_index.html、Order_index.html、Notice_index.html 全 404；User/Main/System/Payorder/Index_login 模板 200。
  ⇒ **KB 372 的 Wechat::index_1 签名绕过 / Autoart::kjer 打法在这类"精简版"主机上没有落点，攻击前必须先跑预言机。**
- Home 组：Index / Order / Article / List 存在，其中 **Home/Order 报 'Action' not found（脱队）**，但只有 get_html1、downapp 两个 action 存活，且 url/ename/id/path/tpl 参数全惰性（get_html1 恒回 58B JSON `{"ok":1,"msg":"成功请刷新"}`、downapp 恒回 `0`）；Home/Article 22 个 action 全回 13B `502`。⇒ 无可控写/读原语。

## 3) 「302 与 Host 无关」对照实验（判定后台闸门类型）
对 /Admin/Index/login 依次用：真实域名、白名单式 abrdns 候选（品牌 55/66 等）、**随机不存在域名**、**空 Host**。
- 若"真实域名/白名单候选 = 200 登录页（1086B），其它 = 302" → HTTP_HOST 白名单，继续枚举。
- 若**连随机域名/空 Host 也一律 302**，仅 Host=IP 时 nginx 403，而同一批 / 与 /Home/Index 无论 Host 都 200 → 闸门比较的不是可伪造的 HTTP_HOST（多半 SERVER_NAME 或固定配置/整组禁用），**Host 头字典爆破在该机上拿不到后台登录页**，立刻换路（读 config/落 webshell 取凭据、DB 侧、基础设施侧）。
本靶标属于后者：20 个 `*.target477.example.com` 候选 + 随机 Host + 空 Host 全部 302。

## 4) 其它证否
- 192.0.2.2（target475.example.com 的另一台）：/List/ = 200 纯静态落地页（395B + js/index.js 4.9KB 开奖数据模板），/ 403，/index.php 与 /index.php?g=Admin&m=Index&a=login 稳定 500（PHP 后端异常），其它 Host 回 200「Sorry, the website has been stopped」宝塔停站页 ⇒ 不是站群实例。
- CDN 192.0.2.3/.84 上 Host=target475.example.com、target478.example.com → 530「域名未配置」，只有 csnsg36j8n 系域名回源，无独立攻击面。

```
