# Plesk Obsidian 18.0.82.2 login_up.php login_name 输出编码阴性：script-JSON 上下文 json_encode 转义、404 路径与 locale 参数不回显

- **code**: plesk-18-0-82-login-name-output-encoding-script-json-negativ
- **kind**: payload
- **category**: frontend-reverse
- **component**: Plesk Obsidian 18.0.82.2（sw-cp-server）login_up.php
- **severity**: low
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 22:06-22:10 UTC 直连 88.208.224.249:443（issuer=Let's Encrypt CN=YR1，--noproxy '*' + --resolve，排除记录代理 MITM）：5 发 POST /login_up.php（1 基线+4 闭合载荷，均不存在用户名+随机错口令，间隔 6s）全部 200/103926–103948B 含 'Incorrect username or password'，无锁定文案；回显唯一出现在 '<script>Plesk.run(...)</script>' 的 "data":{"values":{"login_name":"..."}}：`"><svg onload=alert(9)>`→`\"><svg onload=alert(9)>`、`</script><script>alert(9)</script>`→`<\/script><script>alert(9)<\/script>`、`" autofocus onfocus=alert(9) x="`→`\" autofocus onfocus=alert(9) x=\"`，无闭合逃逸；.php 404=16B 'File not found.'（随机与载荷路径同 md5 4845f01e…，无回显）；无扩展名 404=990B md5 09295dfbf56aa728aa13dd7224a1f177（静态，grep svg/zz9/alert 0 命中）；?locale= 与 ?locale_id= 两发均 200/103798B，lang="en" 与 "locale_id":"default" 不变、无反射。
- **path**: pocs/plesk-18-0-82-login-name-output-encoding-script-json-negativ/poc.txt
- **tags**: plesk,xss,output-encoding,login_up,negative
- **created_at**: 2026-11-11T22:10:14.536Z
- **engine**: mail.goffsgames.co.uk (88.208.224.249:443)

## 描述

Plesk Obsidian 18.0.82.2 登录页 login_name 的唯一回显点在 <script> 内 Plesk.run(...) 的 JSON 字符串 data.values.login_name，服务端用 json_encode（"→\"、\→\\、/→\/），无法闭合 JS 字符串或提前终止 script 元素；<、>、' 虽保留但处于 JS 字符串内为惰性文本。.php 404 为 16B 静态 'File not found.'，990B Plesk 404 仅出现在无扩展名路径且为静态页；?locale/?locale_id GET 参数不进入渲染。结论：该预认证反射 XSS 输出面封口。

## 用法

```
判据（后人不重复走）：
1) 不要用「< 是否被实体编码」判 Plesk 登录页：正确判据是「能否逃出 JS 双引号字符串 / 提前终止 script」。该页回显在 <script>//<![CDATA[ Plesk.run({...}) //]]></script> 的 "data":{"values":{"login_name":"..."}}。
2) 实测编码为 PHP json_encode：`"><svg onload=alert(9)>`→`\"><svg onload=alert(9)>`；`</script><script>alert(9)</script>`→`<\/script><script>alert(9)<\/script>`；`" autofocus onfocus=alert(9) x="`→`\" autofocus onfocus=alert(9) x=\"`。无裸 `</script`、无字符串闭合，不可利用。
3) 404 形态：`.php` 路径 → 404/16B `File not found.\n`（md5 4845f01eaa8068384625e302e9a4eb05，路径不回显）；无扩展名路径 → 404/990B 静态页（md5 09295dfbf56aa728aa13dd7224a1f177，同样不回显路径）。
4) `?locale=` / `?locale_id=` GET 参数被忽略：响应恒 200/103798B，`<html lang="en">` 与 `"locale_id":"default"` 不变。
5) 预算：Plesk 同 IP 连续失败第 6 次锁 ~300s，5 发失败 POST 安全；务必用不同不存在用户名。
复现（直连，避开记录代理）：
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
curl -sk --noproxy '*' --resolve mail.goffsgames.co.uk:443:88.208.224.249 -A "$ARTEX_UA" \
  --data-urlencode 'login_name="><svg onload=alert(9)>' --data-urlencode 'passwd=Zz9Wrong_x' \
  --data-urlencode 'locale_id=default' --data-urlencode 'success_redirect_url=/' \
  https://mail.goffsgames.co.uk/login_up.php | grep -o '"login_name":"[^"]*"'
```

## 正文

```
# Plesk 18.0.82.2 login_up.php 输出编码面（2026-11-11 直连实测，阴性）

- 目标：mail.goffsgames.co.uk:443（88.208.224.249，Plesk Obsidian 18.0.82.2，sw-cp-server + php-fpm）
- 前置校验：TLS issuer = Let's Encrypt CN=YR1，subject CN=server2.visionhost.co.uk；必须 unset *_proxy + --noproxy '*' + --resolve
- 请求预算：10 发（5 失败 POST + 5 只读 GET），单线程、间隔 5–6s；Plesk 第 6 次连续失败登录锁 ~300s，本测试未触发

## 结果
1. login_name 回显：仅 1 处，位于 `<script>//<![CDATA[ Plesk.run({"config":...,"data":{"status":[...],"values":{"login_name":"..."}}}) //]]></script>` 的 JS 双引号字符串；json_encode 语义（`"`→`\"`、`\`→`\\`、`/`→`\/`），`</script>`→`<\/script>`；`<`/`>`/`'` 保留但为惰性文本。无逃逸。
2. 404：`.php` 路径 404/16B `File not found.\n`（md5 4845f01eaa8068384625e302e9a4eb05）；无扩展名路径 404/990B（md5 09295dfbf56aa728aa13dd7224a1f177）。两者均不回显请求路径。
3. locale：`?locale=`、`?locale_id=` 均被忽略，响应 200/103798B 不变（lang="en"、"locale_id":"default"）。
4. 结论：Plesk 登录页预认证反射 XSS 输出面封口；残留仅为前端若以 innerHTML 消费 values.login_name 的 DOM 级风险（未做浏览器验证，页面由 plesk-ui-library 渲染，通常绑定 input.value）。
```
