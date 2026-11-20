# Apache mod_negotiation(MultiViews) 的 Alternates 头做目录文件存在性枚举与静态资源泄露

- **code**: apache-mod_negotiation-multiviews-的-alternates-头做目录文件存在性枚举与
- **kind**: template
- **category**: recon
- **component**: Apache httpd mod_negotiation
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: shopto.net 源站 3.8.196.174 实测：GET /dc/admin/admin（Host: cp.shopto.net, Accept: text/plain）→ HTTP 406 + `Alternates: {"admin.js" 1 {type application/javascript} {length 17981}}, {"admin.php" 1 {type text/html}}`；据此直接 GET /dc/admin/admin.js 拿到 200/17981B 后台 JS。同目录不存在名字则回落应用登录页 2367B，判据清晰。
- **path**: pocs/apache-mod_negotiation-multiviews-的-alternates-头做目录文件存在性枚举与/poc.sh
- **tags**: apache,mod_negotiation,multiviews,alternates,recon,file-existence,source-leak
- **created_at**: 2026-11-11T17:50:36.831Z
- **engine**: 3.8.196.174

## 用法

```
1) 先确认 MultiViews 开启：请求 /path/name（无扩展名）看响应头是否有 `Content-Location:`（指向真实文件如 help.php）+ `Vary: negotiate` + `TCN: choice`。
2) 枚举：对每个候选 name 发 `curl -sk --http1.0 -H 'Host: <vhost>' -H 'Accept: text/plain' -D - https://IP/path/name`。
   - 命中：HTTP **406** + `Alternates:` 头（或 300/TCN: list 正文 `Available variants:`），头里直接给出真实文件名、MIME 与**字节长度**。
   - 未命中：回落应用默认页（本例 2367B 登录页）。
   可用 ffuf 批量：`ffuf -u https://IP/dc/admin/FUZZ -w dir-common.txt -H 'Host: x' -H 'Accept: text/plain' -mc 406,403,404`
   **注意**：字典中含 `/` 的条目（如 admin/config.php）会产生 406 假命中，因为 `/dc/admin/admin/xxx` 里的 `admin` 段被协商成 admin.php 后忽略后续路径——必须过滤掉带 `/` 的 FUZZ 值。
3) 若 Alternates 里出现 .js/.css/.html/.txt 变体，直接用 `Content-Location` 或文件名 GET 下载（非 PHP 扩展名不会被解析执行）；.php 变体只能确认存在，无法读源码（会执行）。
4) 顺带：若目标用 MultiViews 且某 PHP 文件 fatal（500/0），`Accept: text/plain` 得到的 406/Alternates 可告诉你该目录下是否还有别的扩展名副本（.bak/.txt/.phps）可读，这是常见的源码泄露缺口。
```

## 正文

```
# 原理
Apache 开启 `Options +MultiViews` 时，`mod_negotiation` 对「无扩展名的请求路径」做内容协商，选中 `name.<ext>` 后返回 `Content-Location: name.php`、`Vary: negotiate`、`TCN: choice`。当客户端 `Accept` 头无法接受任何候选变体时返回 406（或 300+Tcn: list），并在响应头 `Alternates:`（或正文 `Available variants:`）中**列出该 basename 的所有真实变体：文件名、MIME 类型、字节长度**。

## 利用点
1. **文件存在性 + 文件清单 oracle**：不必猜扩展名，服务端直接告诉你。
2. **静态资源匿名下载**：`.js/.css/.html/.txt` 变体不会被 PHP 执行，可直接读；这些文件常泄露真实后端端点、参数名、CSRF 字段名（本例从 admin.js 提取到 `/dc/admin/edit_language_ajax.php`、`/dc/admin/edit_login_ajax.php` 与 `layout_admin_csrf`）。
3. **源码泄露缺口**：PHP 文件 fatal 时（500 空体），若目录里还留有 `.txt/.bak/.phps` 等同名副本，协商会把它列出来并可直接下载。

## 实测样例（shopto.net 源站 3.8.196.174，2026-11-11）
```
$ curl -sk --http1.0 --noproxy '*' -H 'Host: cp.shopto.net' -H 'Accept: text/plain' -D - \
    https://3.8.196.174/dc/admin/admin
HTTP/1.1 406 Not Acceptable
Content-Location: admin
Vary: negotiate
TCN: list
Alternates: {"admin.js" 1 {type application/javascript} {length 17981}}, {"admin.php" 1 {type text/html}}

$ curl -sk ... https://3.8.196.174/dc/admin/admin.js     # → 200, 17981B, application/javascript
```
对照：`/dc/admin/zzznotexist` → 200/2367（应用登录页回落）；`/dc/admin/logs` → 403。

## 判据小结
- 406 + Alternates / 300 + Available variants = **存在且有多变体**
- 200 + Content-Location: xxx.php + TCN: choice = 存在单变体（PHP 已执行）
- 应用默认页 / 真实 404 = 不存在
- 403 = 被全局 deny 规则命中（README/LICENSE/CHANGELOG/dotfile 等），**不能据此断定文件存在**

## 常见坑
- 字典里带 `/` 的条目会命中「前缀目录被协商成文件」的假阳性（如 `/dc/admin/admin/config.php` 的 406 只是 `admin` 段协商的结果），必须剔除。
- 大小写敏感（Linux 文件系统）：`HELP` 不匹配 `help.php`。
- 仅对最后一段路径做协商；`PathInfo` 会被忽略。
```
