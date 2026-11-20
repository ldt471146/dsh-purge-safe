# PHPWind 7.x 入口 × action 全量枚举方法论（251 个 action + 10 类危险标记）+ 写点判死结论集（pw_var_export 转义 / Pcv 封穿越 / uploadicon 数学不可能 / mutiupload 三重锁）

- **code**: phpwind-7.x-入口-action-全量枚举方法论-251-个-action-10-类危险标记-写点判死结论集-pw_var_export-转义-pcv
- **kind**: script
- **category**: path-traversal
- **component**: PHPWind 7.x（7.3.2 / 7.5 SP3）
- **severity**: info
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10 在 203.0.113.126 双站（六合王 example.com/bbs、主站 example.com/bbs，均 PHPWind 7.3.2）实测 206 项 action 存在性：六合王 example.com 23 项（基准 example.com?action=preview&tid=1 四次全 2490B）、pw_example.com 52 项（基准 showface 八次全 826B）、其余入口 56 项、主站对照 75 项；全程零 000、零封禁。判死结论集全部为 7.5 SP3 源码逐行确证：pw_var_export(require/target105.example.com:456-459)、Pcv(target105.example.com:372-380)、readover(target105.example.com:221)/writeover(target105.example.com:231-241)、uploadicon(require/profile/target50.example.com:23,27)、FaceUpload(lib/upload/target275.example.com:20-24,32)、upload 基类(lib/target52.example.com:31,30,152)、example.com:8-13、target212.example.com:36,42,58、selectMode(target116.example.com:300-317)、app_route.php:88-95、target107.example.com:78、target117.example.com:644,647、target188.example.com:136-155,178-187。六合王实测 mutiupload 返回 <filetype> 白名单非空（gif/png/zip/rar/jpg/txt，174B）而主站为空（121B），仍不可武器化（三重锁）。
- **path**: pocs/phpwind-7.x-入口-action-全量枚举方法论-251-个-action-10-类危险标记-写点判死结论集-pw_var_export-转义-pcv/pw-action-enum.py
- **tags**: phpwind,action枚举,攻击面测绘,写点判死,pw_var_export,Pcv,P_unlink,uploadicon,mutiupload,路径穿越,bank_sort,判据,Char_cv,CheckVar,Sql_cv,data目录
- **created_at**: 2026-10-06T19:57:11.269Z
- **found_by**: vuln-scan

## 描述

PHPWind 入口 × action 全量提取脚本 + 写点判死结论集。给出 251 个 action 的提取方法、10 类危险标记、以及 7 条源码级判死结论（pw_var_export 转义、Pcv 封死穿越、uploadicon 数学不可能、mutiupload 三重锁、路由无 LFI、子目录守卫完备、/e 与 eval 点），并留下唯一候选（setstyles SQL 注入但内容不可控）。

## 用法

```
1) 建表（零发包）：`python 06-build-action-table.py <源码根> <输出目录>` → 产出 action-table.md（人读）+ action-table.json（机读）；本机 7.5 SP3 源码在 runs/pw-src-732/pw75sp3。
2) 只对带 FILE_WRITE/UPLOAD/EXPORT/CODE_EXEC/SQL_WRITE/INCLUDE/PERM/PATH_JOIN 标记的 action 发包，其余不花包。
3) 探测必须遵守 CC 防护四规范（见知识库另一条「pwDefendCc 0 字节假阴性」）：-b jar -c jar 同文件读写 / 间隔≥10s / 每 8-10 项夹已知存在基准 / size 用文件字节数。
4) 发包引擎骨架：`pwsh 12-probe-actions.ps1 -Base <站点> -Jar <jar> -ListFile <列表> -OutDir <目录> -BenchPath pw_example.com -BenchAction showface -BenchEvery 10 -SleepSec 10`；列表每行 `entry|label|query`；写语义 action 一律用无效 tid=999999 探存在性，避免误改数据。
5) 判据：非 0 字节 + 非通用提示（非法操作/未安装/已关闭/404）= 存在；0 字节且同轮基准正常 = 不存在；基准异常则该轮作废。
6) 动手前先读「三、写点判死结论集」——7 条已判死的路不要再花包。
```

## 正文

```
【增补 2026-10 · 写点汇点全量分类（不按 action 分派，按调用点扫）】
全源码扫 1830 处写/删/包含汇点（writeover/file_put_contents/fwrite/fopen写模式/unlink/P_unlink/rmdir/mkdir/chmod/move_uploaded_file/include/require）：类A（路径含请求变量）39 处、类B（内容含请求变量）18 处、类C（参数是文件名）0 处、类D 1773 处。

★★ 核心判据（第三条防线，此前未记录）：**`P_unlink` 也是 `@unlink(Pcv($filename))`**（target105.example.com:209-211）。加上 `writeover`(:231) 与 `readover`(:221) 内部的 `Pcv`，**PHPWind 三道文件操作统一防线全部内建 `Pcv`（拦 `://`/NUL/`..`）** → 类A 39 处路径穿越**全部判死**，连「任意文件删除」都不存在。这解释了为何历史上所有路径穿越尝试（setstyles 的 $sid、bakup 的 $pre、sort.php 的 $month、thread.php 的 $fid/$page、level.php 的 $delid/$gid、guestfunc.php 的 $page）全部失败。

★ 唯一例外：**`hack/bank/example.com` L362-373 `savearray()` 不走 `pw_var_export`** —— 它用 `'"'.addslashes($value2).'"'` 拼数组，而 `addslashes` **不转义 `$ { } [ ] ( )`** → 双引号字符串里的 `${...}` 会被 PHP 求值。写入 `data/bbscache/bank_sort.php` 后由 L76 `include` 同作用域执行 → 构成代码执行链（数据源为 `pw_members.username`，需先污染 DB）。

【增补 · 字符过滤规则速查】
- `Char_cv`(target105.example.com:646-665)：实体化 `" ' < >`，去 NUL/`%00`/`\r`，**不过滤 `$ { } [ ] ( )`**
- `CheckVar`(target105.example.com:667-679)：把 `.. ) < =` 实体化 —— **但对 `$_POST['pwuser']`/`pwpwd`/`atc_content`/`atc_title`/`prosign` 豁免**（target116.example.com:53-57 白名单）
- `Sql_cv`(target105.example.com:441-448)：**不做任何过滤**，只是 INSERT 到 pw_sqlcv 再 SELECT 回来的往返测试
- `Pcv`(target105.example.com:372-380)：拦 `://`、NUL、`..`（默认 $ifcheck=1）；**不拦 `/`**
- `changename.php` 的用户名黑名单：`& ' " / * , < > \r \t \n #` —— **不含 `$ { } [ ] ( )`**；长度上限 `$rg_regmaxname` 来自后台配置 `data/bbscache/dbreg.php` 的 `$rg_namelen`

【增补 · data/ 目录可读性判据】
`.php` 缓存文件一律被 nginx 交给 PHP 执行 → **200/0B（存在但无输出，无源码泄露）**；而 **`.htm`/`.js`/`.css` 不经 PHP handler → 内容原文返回**。实测 `data/style/wind_css.htm` = 14279B 可读（含 `<?php` 片段，`<!--css-->` 分隔符 2 次），`data/bbscache/face.js` = 639B 可读，`data/tmp/` = 403。**注意**：`wind_css.htm` 虽是 `updatecache_sy` 的 `eval("\$style_css = \"$style_css\";")` 输入源，但全文 `${...}` 结构 **0 命中**（只有 `$linkcolor`/`$tplpath` 等普通 `$var`）→ 只做变量插值，**eval 链判死**。
```
