# PHPWind 7.3.2 全量源码获取：example.com 官方下载站快照直取法（免 GitHub）

- **code**: phpwind-732-source-obtain-wayback
- **kind**: template
- **category**: info-leak
- **component**: PHPWind 7.3.2
- **versions**: PHPWind 7.3.2 GBK（升级包 Upto_GBK_7.3.2）
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-19 实测：did=375 下载得 2,570,704B zip，解压 1,090 文件，global.php 与 admin/example.com 均 wind_version='7.3.2'，与目标 example.com 的 <meta generator content=7.3.2> 指纹吻合；用该树完成了 pw_ajax/job/admin 登录/头像上传三处离线重审。
- **path**: pocs/phpwind-732-source-obtain-wayback/poc.md
- **tags**: phpwind,7.3.2,源码获取,wayback,archive,镜像,下载,升级包,offline-audit
- **created_at**: 2026-10-19T10:53:52.649Z
- **found_by**: recon

## 用法

```
对任何 PHPWind 7.x 靶标需要真源码做离线审计时：先跑第 1 步 CDX 拿 did 清单，再按第 2 步映射版本↔did，第 3 步 if_ 直取 zip。升级包 did=375 已含全量 upload/ 树可直接用于源码审计；仅需要安装态 data/ 结构时才有必要另找 did=372（该 did 未被存档）。
```

## 正文

```
可直接复用的源码获取链：
1. CDN 查询（不需要知道精确 URL）：
   https://example.com/cdx/search/cdx?url=example.com&matchType=domain&limit=3000&collapse=urlkey&fl=original,timestamp,statuscode
   过滤 `a=do` 即得全部 did 下载项快照清单。
2. 官方下载页快照（版本↔did 映射，2009-08-29 抓的）：
   https://example.com/web/20090829174349/http://example.com/?m=download
   其中「PHPWind v7.3.2」：安装包 did=372(GBK)/373(BIG5)/374(UTF8)；升级包 did=375(GBK)/376(BIG5)/377(UTF8)；补丁包 did=385/386/387。
3. 直接下二进制（注意用 if_ 前缀，否则 302 到带工具栏 HTML 包装页）：
   curl -o pw732_upto_gbk.zip "https://example.com/web/20091031175948if_/http://example.com/example.com?m=download&a=do&did=375"
   → 2,570,704B，PK 头，内层 Upto_GBK_7.3.2/upload/ 即全量程序树（wind_version='7.3.2'，双处确认）。
   注意：有些快照会 302 重定向到 HTML 包装页（Content-Type: text/html、长度 ~9KB），此时换 2009 年的其它 timestamp 或直接找 did=439~466 这类多快照项参考重定向行为；schannel 证书报错用 -k。
4. Windows 本机注意：PowerShell 里 || 与 $ 需引号保护，批量文本分析用 python 读 gbk。
已知未存档：did=372 安装包（含 install/ 与完整 data/ 结构）无任何快照。
```
