# PHPWind 7.x/8.x 版本指纹识别（robots.txt + meta generator + 路径特征）

- **code**: phpwind-7.x-8.x-版本指纹识别-robots.txt-meta-generator-路径特征
- **kind**: poc
- **category**: info-leak
- **component**: PHPWind
- **versions**: 7.0 - 8.x
- **severity**: low
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.86（example.com/bbs）实测验证：robots.txt 返回 "# robots.txt for PHPWIND BOARD / # Version 7.x"；/bbs/example.com footer 显示 "PHPwind 7.3.2"；首页 meta generator=7.3.2。三条独立证据互相印证。
- **path**: pocs/phpwind-7.x-8.x-版本指纹识别-robots.txt-meta-generator-路径特征/poc.sh
- **created_at**: 2026-10-15T15:43:38.448Z

## 描述

PHPWind 是国内老牌论坛 CMS（phpwind.net）。多站点会伪装成 Discuz，需靠特征区分。识别点：①robots.txt 头部注释直接声明 "for PHPWIND BOARD" 与 Version；②任意页面 meta name="generator" 常带精确版本；③后台 /example.com 页面 footer 硬编码版本号；④模板目录 images/wind/（wind 是 PHPWind 默认模板）；⑤JS 文件 js/pw_ajax.js、js/Deploy.js、js/global.js；⑥CSRF token 变量名 verifyhash；⑦Cookie 前缀为 <table_prefix>_（如 604b2_lastvisit），AdminUser cookie 名带同一前缀；⑧路径风格：example.com?fid=N、read.php?tid=N、u.php?action=show、simple/ 静态归档、wap/ 移动版。

## 用法

```
# 1) 最直接的版本证据
curl -sk https://TARGET/robots.txt | head -5
curl -sk https://TARGET/example.com | grep -oE 'PHPwind [0-9.]+'
curl -sk https://TARGET/ | grep -oE 'name="generator" content="[^"]+"'

# 2) 判定是否 PHPWind（vs Discuz）
curl -sk https://TARGET/ | grep -Eo 'pw_ajax\.js|images/wind/|verifyhash|fid=[0-9]'
#  命中 = PHPWind；若命中 forum.php/home.php/static/js/_saltkey = Discuz

# 3) 后台与功能入口
for p in example.com login.php register.php example.com require/ style/ attachment/ simple/ wap/; do
  printf '%-16s ' "$p"; curl -sk -o /dev/null -w '%{http_code}\n' "https://TARGET/$p"
done
```

## 正文

```
#!/usr/bin/env bash
# phpwind-fingerprint.sh — PHPWind 版本与类型识别
# 用法: ./phpwind-fingerprint.sh https://example.com/bbs
set -u
B="${1:?usage: $0 <base-url>}"
say(){ printf '\n=== %s ===\n' "$*"; }

say "robots.txt（自带版本声明）"
curl -sk --max-time 15 "$B/robots.txt" | head -8

say "meta generator"
curl -sk --max-time 15 "$B/" | grep -oiE '<meta[^>]*generator[^>]*>' | head -3

say "example.com footer 版本（后台页面）"
curl -sk --max-time 15 "$B/example.com" | grep -oiE 'PHPwind[^<]{0,20}' | head -3

say "PHPWind 类型特征计数"
BODY=$(curl -sk --max-time 15 "$B/")
for k in pw_ajax.js 'images/wind' verifyhash 'fid=' 'read.php' 'u.php' ; do
  printf '%-14s %s\n' "$k" "$(printf '%s' "$BODY" | grep -oF "$k" | wc -l)"
done

say "Discuz 特征（应为 0，用于区分）"
for k in forum.php home.php '_saltkey' 'static/js' ; do
  printf '%-14s %s\n' "$k" "$(printf '%s' "$BODY" | grep -oF "$k" | wc -l)"
done

say "关键路径状态码"
for p in example.com login.php register.php example.com require/ style/ attachment/ simple/ wap/ uc_server/ install/ config/ data/ api/ ; do
  printf '%-14s %s\n' "$p" "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "$B/$p")"
done

say "Cookie 前缀（泄露表前缀）"
curl -sk -D- -o /dev/null --max-time 15 "$B/" | grep -i '^set-cookie' | sed 's/;.*//'
```
