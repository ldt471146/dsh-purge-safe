# Roundcube 1.6.20 未认证插件/核心 action 面阴性：15 插件 action + utils/password/oauth + HTTP Basic 通道全部回落标准登录页，无会话铸造无文件读取

- **code**: roundcube-1.6.20-未认证插件-核心-action-面阴性-15-插件-action-utils-pa
- **kind**: poc
- **category**: auth-bypass
- **component**: Roundcube Webmail
- **versions**: 1.6.20
- **source**: self
- **verified**: 1
- **verified_note**: 40 发直连 curl（--resolve 至 88.208.224.249，unset *_proxy，间隔 3s）实测：插件主文件 15 个 500/0B、new_user/squirrelmail_usercopy 404/271B；13 个 ?_action=plugin.<name> + ?_task=utils&_action=spell|text2html|kill_session|error + ?_task=login&_action=oauth + Basic(info@goffsgames.co.uk:wrongpass) 全部 200 标准登录页（5337B 基线，差异仅 env.action/_url 反射 3×len+9），Set-Cookie 仅 roundcube_sessid，无 roundcube_sessauth、无 Location/401/WWW-Authenticate。
- **path**: pocs/roundcube-1.6.20-未认证插件-核心-action-面阴性-15-插件-action-utils-pa/poc.txt
- **created_at**: 2026-11-12T01:53:03.748Z
- **engine**: webmail.goffsgames.co.uk

## 描述

Roundcube 1.6.20 的预认证插件 action 面与核心匿名 action（password/utils/oauth）在直连实测中一律渲染 task=login 标准登录页；http_authentication 插件的 PHP_AUTH_USER(Basic) 通道不发 401 challenge、不触发 IMAP 认证。判据：页面长度增量严格等于 3×action名长度+9（env.action、body class、_url 三处反射），无 sessauth、无跳转即阴性。

## 用法

```
复用：对 Roundcube 1.6.20 不必再逐插件跑 ?_action=plugin.<name> 或 utils/password/oauth 匿名 action；一次基线 + 按 3×len+9 公式比对即可判阴性。只有出现非登录页形态（3xx、500带正文、非 roundcube_sessid、无登录表单）才继续深挖。若需 config.inc.php 面，另派 ≤15 发小预算（存在时通常 200/0B 无内容）。
```

## 正文

```
判据（后人不重复走）：
1) 基线：GET /?_task=login → 200/5337B；GET /plugins/<不存在>/<不存在>.php → 404/271B；GET /plugins/<不存在>/ → 403/274B（该 vhost 任意目录形态路径恒 403，403 不携带存在性语义）。
2) 插件主文件：存在且被 PHP 解析 = 500/0B（空体 md5=d41d8cd98f00b204e9800998ecf8427e）；不存在 = 404/271B。
3) 插件 action：GET /?_task=login&_action=plugin.<name> 若为未启用/无未认证分支插件，返回 200 标准登录页，长度 = 5337 + 3×len(action) + 9，差异仅 env JSON action、<body class="action-plugin-…">、_url 隐藏域（&amp; 转义），每次 request_token 随机。出现 3xx / 500带正文 / 非 roundcube_sessid 会话 / 无登录表单，才算异常。
4) 核心：?_task=password、?_task=utils&_action=spell|text2html|kill_session|error、?_task=login&_action=oauth 同样全落登录页（password 仅 _url 反射 +3B）。
5) HTTP Basic：Authorization: Basic base64(user:wrongpass) 不产生 401/WWW-Authenticate，也不产生 "Login failed"；http_authentication 插件不在预认证认证路径。
注意：本靶标 Roundcube 为裁剪发行（new_user、squirrelmail_usercopy 目录不存在）。
```
