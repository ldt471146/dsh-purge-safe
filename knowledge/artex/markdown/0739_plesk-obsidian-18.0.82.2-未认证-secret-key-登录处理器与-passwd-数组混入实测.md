# Plesk Obsidian 18.0.82.2 未认证 secret-key 登录处理器与 passwd 数组混入实测全阴性（封口）

- **code**: plesk-obsidian-18.0.82.2-未认证-secret-key-登录处理器与-passwd-数组混入实测
- **kind**: poc
- **category**: auth-bypass
- **component**: Plesk Obsidian 18.0.82.2 / sw-cp-server
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-12 02:14-02:17 UTC 直连实测 19 发（unset *_proxy、--resolve 88.208.224.249、SNI/Host 锁定）：login.php 的 secret=<随机32hex/空/0/true/[]=x/%00/随机64hex> 与 POST body secret 全部 303/0B、Location 逐字节等于基线 login_up.php，无 /cp/ 落地、无 plesk-* cookie；login_up.php?secret=<随机> 200 与基线归一化后仅随机 forgery_protection_token 差异、secret 不回显；passwd=wrongpass / passwd[]=x / passwd[x]=x 三条 200 正文归一化后逐字节相同且均为 'Incorrect username or password'，无 500/异常分支。回显落盘 /opt/artex/data/tasks/11/i3616/raw/，fact#3623。
- **created_at**: 2026-11-12T02:18:09.468Z
- **engine**: mail.goffsgames.co.uk:443/8443 (88.208.224.249)

## 描述

Plesk 面板 secret 式免密登录入口（/login.php?secret=）与登录表单 passwd 字段数组混入的实测封口记录：两种参数族均未出现会话铸造或非基线错误态，后续 worker 不必重复。

## 用法

```
复现（直连，勿走记录代理）：
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
curl -sk --noproxy '*' --resolve mail.goffsgames.co.uk:443:88.208.224.249 -A "$ARTEX_UA" -D - -o /dev/null 'https://mail.goffsgames.co.uk/login.php?secret=<32hex>'
curl -sk --noproxy '*' --resolve mail.goffsgames.co.uk:443:88.208.224.249 -A "$ARTEX_UA" -D - -o /dev/null -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data-binary 'login_name=zz9nosuch%40example.com&passwd%5B%5D=x' 'https://mail.goffsgames.co.uk/login_up.php'
判据：403/303 到 /cp/ 或 /admin/、200 面板 SPA、Set-Cookie plesk-* 为阳性；本例全落 303→login_up.php 与 200 'Incorrect username or password' 基线。
```
