# 宝塔 Pure-FTPd 口令面判据：存在/不存在用户同一条 530（无法枚举），只有 230 算通；字典来源与 PUT 马战术

- **code**: 宝塔-pure-ftpd-口令面判据-存在-不存在用户同一条-530-无法枚举-只有-230-算通-字典来源与-put-马战术
- **kind**: script
- **category**: weak-password
- **component**: 宝塔面板 Pure-FTPd（MySQL 虚拟用户后端）
- **severity**: info
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-06 在 203.0.113.126:21 实测：Pure-FTPd banner `220-This is a private system - No anonymous login`；两批共 12 对凭据（含宝塔站点目录名 `1113060.1113060a0.top`、域名段 `1113060`/`1113060a0`/`www1113060`/`8886060bdh1.shop`、随机子域 `moh6hrwx4t`、系统名 `admin`/`www`/`ftp`，密码含同名与 123456）**全部返回完全一致的 `530 Login authentication failed`** ⇒ 证实无法用户名枚举、且这 12 对不在字典内。
- **path**: pocs/宝塔-pure-ftpd-口令面判据-存在-不存在用户同一条-530-无法枚举-只有-230-算通-字典来源与-put-马战术/poc.py
- **tags**: 宝塔,Pure-FTPd,MySQL虚拟用户,530,用户名枚举不可行,230判据,FTP字典,上传webshell
- **created_at**: 2026-10-06T12:13:36.487Z
- **found_by**: exploit

## 描述

宝塔的 Pure-FTPd 用 MySQL 虚拟用户后端，用户名存在与否都回同一条 530 Login authentication failed，无法做用户名枚举；给出实测 12 对字典、正确字典来源与"命中即 PUT php 马"的战术要点。

## 用法

```
碰到开放的 21 端口且 banner 是 `220---------- Welcome to Pure-FTPd [privsep] [TLS]` 时：① 别试匿名（banner 会写 No anonymous login）；② 别指望用响应差异枚举用户名（全同一条 530）；③ 账号优先取宝塔站点根目录名（从 phpinfo DOCUMENT_ROOT 读）；④ 判据只有 `230`；⑤ 命中后直接 PUT .php 到 web 根 = WebShell。
```

## 正文

```
## 现象
宝塔服务器上的 FTP 是 `pure-ftpd` + `pure-ftpd-mysql`（`-l mysql:/etc/pure-ftpd/db/mysql.conf`），用户表在面板数据库里。

**对任意用户名，密码错误都回同一条：**
```
530 Login authentication failed
```
（不是 vsftpd 的 `530 Login incorrect.`，也不是"用户不存在"的独立文案。）

⇒ **不存在"响应差异枚举用户名"这条路**。要么直接猜口令（判据只有 `230`），要么从别处拿账号（面板数据库 / 站点目录名 / 面板 FTP 页）。

## 实测字典与结果（12 对，全 530）
| 用户名 | 密码 | 结果 |
|---|---|---|
| `1113060.1113060a0.top`（= 宝塔站点根目录名，从 phpinfo 的 DOCUMENT_ROOT 得到） | 同名 / `123456` | 530 |
| `1113060` | `1113060` / `123456` | 530 |
| `moh6hrwx4t`（站点的随机子域名） | `123456` | 530 |
| `admin` | `123456` | 530 |
| `www1113060` | 同名 | 530 |
| `1113060a0` | 同名 | 530 |
| `example.com` | 同名 | 530 |
| `8886060bdh1.shop` | 同名 | 530 |
| `ftp` / `www` | `123456` | 530 |

## 字典的正确来源（按依据强度排序）
1. **宝塔站点根目录名**（最准）：宝塔"添加站点"时目录名默认 = 域名（或 `站点名_随机`），而"添加 FTP"时账号默认填**站点名**。站点名可从 phpinfo 的 `DOCUMENT_ROOT=/www/wwwroot/<站点名>` 直接读出，或从 nginx 报错页/备份文件泄露的路径推。
2. **面板数据表**：FTP 账号存在面板 MySQL 的 `ftps` 表（有 `name`/`password`），拿到面板或数据库即一次性拿全。
3. **域名段 / 站点编号**（如 `1113060`、`1113060a0`、`8886060`）：站长常用固定编号做账号。
4. 面板/系统名（`www`、`ftp`、`test`、`bt`）。

## 战术要点
- FTP 一旦命中，**直接 PUT 一个 `.php` 到 web 根目录 = WebShell**，完全绕过 HTTP 层的一切上传白名单与内容校验（这条比任何 HTTP 上传点都干净）。
- 宝塔默认**关闭匿名**（banner 里会写明 `No anonymous login`），不要浪费包试 `anonymous`。
- 限速：FTP 无验证码但有 fail2ban/日志告警风险，建议 ≤6 对/批、间隔 2s，并先确认目标是否有 `pam_abl`/fail2ban（连续 530 后观察是否直接断开）。
- 手工验证（经 HTTP 代理，Python，无 ftplib 代理支持时自己实现 USER/PASS 命令流）：
```python
# CONNECT 隧道 → 读 220 → USER x → 330/331 → PASS y → 判定 r.startswith("230")
```

```
