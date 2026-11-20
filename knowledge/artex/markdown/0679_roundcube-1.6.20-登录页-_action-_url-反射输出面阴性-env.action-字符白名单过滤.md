# Roundcube 1.6.20 登录页 _action/_url 反射输出面阴性：env.action 字符白名单过滤 + _url 隐藏域 htmlspecialchars(ENT_QUOTES)，无反射 XSS / 未认证开放重定向

- **code**: roundcube-1.6.20-登录页-_action-_url-反射输出面阴性-env.action-字符白名单过滤
- **kind**: payload
- **category**: frontend-reverse
- **component**: Roundcube Webmail 1.6.20
- **versions**: 1.6.20
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: webmail.goffsgames.co.uk（Roundcube 1.6.20，88.208.224.249:443，直连 LE 证书）：15 发只读 GET（curl --noproxy 14 发 + python 原生 socket 复核 1 发），`_action=</script><script>alert(9)</script>` → rcmail.set_env 中 "action":"alert9"；原始 `"`+`<>` 进 query → _url 隐藏域 value 中 &quot;/&lt;/&gt; 实体化；全部响应裸 `<script>alert(9)` 零命中。fact#2754 confirmed。
- **path**: pocs/roundcube-1.6.20-登录页-_action-_url-反射输出面阴性-env.action-字符白名单过滤/poc.sh
- **tags**: roundcube,reflected-xss,output-encoding,login-page,negative
- **created_at**: 2026-11-11T20:35:18.131Z
- **engine**: webmail.goffsgames.co.uk

## 用法

```
判据（后人不重复走）：① `GET /?_task=login&_action=<payload>` 的 payload 只会进入 rcmail.set_env 的 "action" 字段与 body class action-*，服务端先删非 [A-Za-z0-9_.-] 字符（`</script><script>alert(9)</script>`→`alert9`、`\u003c/script\u003e`→`u003cscriptu003e`），JSON/属性上下文无注入字符；② `_url` 隐藏域值 = URL 编码后的整个 query string 再 htmlspecialchars（&→&amp; "→&quot; <→&lt; >→&gt;，单引号不转义但属性为双引号），属性逃逸不可行；③ env 中无 "url" 字段、comm_path 恒 /?_task=login，_url=javascript:/ //evil 未认证下不产生任何跳转（200/401，无 Location）。仅当版本不同或出现裸 `</script>` 时重开。
```

## 正文

```
目标: https://webmail.goffsgames.co.uk（Roundcube 1.6.20 / PHP 8.3.36 / Apache，88.208.224.249:443）

结论: 登录页两个未验证输出上下文（rcmail.set_env JSON 中的 action、_url 隐藏域、body class action-*）转义与过滤正确，无可利用反射 XSS；未认证下 _url 不驱动任何跳转。

实测（全部 --noproxy '*' 直连，间隔 3.2s，只读 GET）:
1) 基线 GET /?_task=login → 200/5337B
   rcmail.set_env({...,"action":"","comm_path":"/?_task=login",...,"request_token":"..."});
   <input type="hidden" name="_action" value="login">
   <input type="hidden" name="_url" id="rcmloginurl" value="_task=login">
   body class="task-login action-none"    （env 中无 "url" 字段）
2) _action 反射矩阵（env.action / body class）:
   foo                              -> "action":"foo"      class action-foo
   </script><script>alert(9)</script> -> "action":"alert9"
   </script>                        -> "action":""
   "/><script>alert(9)</script>     -> "action":"alert9"
   \u003c/script\u003e              -> "action":"u003cscriptu003e"
   %3C%2Fscript%3E（双重编码）       -> "action":"3C2Fscript3E"
   => 白名单 [A-Za-z0-9_.-]，其余字符（< > " ' / \ ( ) % 空格）一律删除；json_encode 输出。
3) _url 隐藏域:
   ?_task=login&_action=</script><script>alert(9)</script>
     -> value="_task=login&amp;_action=%3c%2fscript%3e%3cscript%3ealert%289%29%3c%2fscript%3e"
   ?_task=login&_url=abc"><script>alert(9)</script>（query 内为原始字符）
     -> value="_task=login&amp;_url=abc&quot;&gt;&lt;script&gt;alert(9)&lt;/script&gt;"
   ?_task=login&_url=abc'><img/src=x/onerror=alert(9)>
     -> value="_task=login&amp;_url=abc'&gt;&lt;img/src=x/onerror=alert(9)&gt;"  （' 保留但属性双引号包裹）
   => 值 = URL 编码后的 query string + htmlspecialchars(ENT_QUOTES)，属性逃逸不可行。
4) _url 参数面: javascript:alert(9) / //evil.example/x / "><script> 均为 200、无 Location，仅作隐藏域值回显；未认证无开放重定向。
5) 交叉: ?_task=</script><script>alert(9)</script>&_action=login → 401（_task 归一化为 login 并进入登录 handler，体仍登录页）；
   ?_task=login&_action=login&_url=javascript:alert(9) → 401 + Set-Cookie roundcube_sessauth=-del- ×2。
6) 决定性: 15 个响应 grep 裸 "<script>alert(9)" / "</script><script>alert" 零命中；python 原生 socket 复核 1 发同结论（"action":"alert9"，RAW_HITS: NONE）。

残留线索（需凭据，未认证不可达）: 登录成功后 Roundcube 如何使用 _url（是否 urldecode 后作为 Location、是否接受 javascript: 伪协议）未验证；另 GET ?_action=login 会进入登录 handler 返回 401，可作为登录失败语义观测点。
```
