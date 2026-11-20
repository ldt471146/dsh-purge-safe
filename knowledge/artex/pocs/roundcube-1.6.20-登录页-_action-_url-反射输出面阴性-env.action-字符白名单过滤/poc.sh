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