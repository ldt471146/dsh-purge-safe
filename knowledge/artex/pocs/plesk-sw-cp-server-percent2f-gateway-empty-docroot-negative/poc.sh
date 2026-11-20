适用范围：Plesk Obsidian sw-cp-server 前端（本例 18.0.82.2，443 与 8443 同型），针对 kb#631 记录的『唯一异常 /admin%2Freseller%2Fgenerate-secret → 404/268B Apache 风格』的扩展判定。

实测结论（2026-11-11，goffsgames.co.uk / 88.208.224.249）：
1) 该 %2F 旁路确实穿过 sw-cp-server 会话门，落到一个真实的 Apache 默认 404（Server: Apache, Content-Length: 268, Content-Type: text/html; charset=iso-8859-1, 无 ETag；响应头仅 Date/Server/Content-Length/Content-Type）。
2) 内层 docroot 为空/无 handler：10 条标准 Apache 目标路径全部同字节 404（md5 47ccf52d…），包括 /%2F、/index.html%2F、/index.html%2F..%2Findex.html、/error_docs%2F、/server-status%2F、/server-info%2F、/icons%2F、/manual%2F、/cgi-bin%2F、/plesk-stat%2F；/login_up.php%2F（面板真实文件名）与 /index.php%2F（Roundcube 类真实文件名）也为 404，证明该 docroot 既不镜像 Plesk 面板也不镜像 webmail；/..%2F..%2F..%2F..%2Fetc%2Fpasswd 同 404（无穿越）。
3) %252F 双重编码是反向对照：/admin%252Freseller%252Fgenerate-secret → 303 sw-cp-server 会话门（Location 中 success_redirect_url=%2Fadmin%25252F…）；/%252F → 404/990B Plesk 自身 404。即该旁路严格依赖单次解码后的斜杠形态，双重编码不构成变体。
4) 内层 Apache 做严格 SNI/Host 一致性校验：/index.php%2F 携带 Host: webmail.goffsgames.co.uk（SNI 仍为 mail.goffsgames.co.uk）→ 421 Misdirected Request / 397B / Server: Apache。跨 vhost 的 Host 路由无分叉，选别的 vhost 等价于直接访问该 vhost。
5) 无 200/401/403 出现，无目录清单、无 server-status 表格、无文件读取。

判据提醒：若出现 200/401/403 且 Server: Apache 或正文非默认 404，才说明该旁路推翻『内层 docroot 为空』并可继续深挖；本目标未出现，故该路由旁线封口。仅测了只读 GET；写方法未测（遵守只读约束）。