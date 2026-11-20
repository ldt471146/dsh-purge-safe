# Apache .htaccess 全局名称黑名单判据：config.json/readme.txt/logs.* 在任意存在目录恒 403（≠文件存在）

- **code**: apache-.htaccess-全局名称黑名单判据-config.json-readme.txt-logs.-在任意
- **kind**: template
- **category**: info-leak
- **component**: Apache httpd 2.4.6 + .htaccess FilesMatch 名称黑名单
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 直连 3.8.196.174（shopto.net 源站，curl -k --http1.0 --noproxy '*'，Host: cp.shopto.net）实测：/userdata/dcshop/config.json=403/229，而同目录 myconfig.json=404、不存在目录 /zzq-random-2438/config.json=应用 404/1883；readme.txt/README.txt/logs.png 在 /、/dc/、/module/dcshop/、/userdata/、/userdata/files/、/layout/admin/img/2015/ 等任意存在目录均 403，近似名 Readme.txt/zzqlogs.png/log.png 均 404；16 种绕过变体（//、./、%2e、尾斜杠、::$DATA、%20、%00、大小写、;.txt、?x=1、Accept: text/plain、Host 切换）全 403 无绕过。
- **path**: pocs/apache-.htaccess-全局名称黑名单判据-config.json-readme.txt-logs.-在任意/poc.md
- **tags**: apache,htaccess,403,oracle,false-positive,backup-discovery
- **created_at**: 2026-11-11T20:21:40.411Z
- **engine**: https://3.8.196.174
- **found_by**: recon

## 描述

在 Apache 站点做备份/配置文件名发现时，「精确文件名 → 403」极易被误判成「文件存在但被保护」。若该 403 是全局名称黑名单（.htaccess <FilesMatch> 或 RedirectMatch 403），它在任意目录对同名路径都 403，完全不携带存在性信息。必须做跨目录同名对照才能定性。

## 用法

```
【判据三步】
1) 命中 403 的名字，换到**不存在的目录**下再请求：若返回应用 404（前端控制器页，本例 404/1883B）或 Apache 404，说明 403 是名称规则而非文件存在。

# 例（shopto 源站）
curl -sk --http1.0 --noproxy '*' -H 'Host: cp.shopto.net' -o /dev/null -w '%{http_code} %{size_download}\n' https://3.8.196.174/userdata/dcshop/config.json      # 403/229
curl -sk --http1.0 --noproxy '*' -H 'Host: cp.shopto.net' -o /dev/null -w '%{http_code} %{size_download}\n' https://3.8.196.174/zzq-random-2438/config.json   # 404/1883  ← 规则型
curl -sk --http1.0 --noproxy '*' -H 'Host: cp.shopto.net' -o /dev/null -w '%{http_code} %{size_download}\n' https://3.8.196.174/userdata/dcshop/myconfig.json  # 404       ← 精确名匹配

2) 在 ≥3 个**已知存在**的目录（/、/dc/、/userdata/、某个 200 的静态目录）下重复同名请求：全部 403 且仅字节数随路径长度变化 ⇒ 全局黑名单。
3) 只有「同名在存在目录 403、在不存在目录 404」且「近似名 404」同时成立时，才能怀疑该文件真实存在；此时仍需再用编码绕过（//、./、%2e、尾斜杠、::$DATA、%20、%00、大小写、;x、?x、Accept: text/plain 协商、换 Host）确认是否可读，全 403 则该文件即使存在也不可读。

【结论口径】403 = 「路径被规则拒绝」，不是「文件存在」；不要把 403 计入备份/配置发现命中。
```

## 正文

```
# 全局名称黑名单 403 的识别与处置

## 现象
对 `config.json`、`readme.txt`、`README.txt`、`logs.png` 等常见敏感名做探测时，在目标站点的多个目录下都返回 403，看起来像"到处都藏了敏感文件且被保护"。

## 实测判据（2026-11-11，3.8.196.174 / shopto.net 源站）
| 请求 | 状态 | 说明 |
|---|---|---|
| /userdata/dcshop/config.json | 403 / 229B | 疑似命中 |
| /userdata/dcshop/myconfig.json | 404 | 近似名不命中 ⇒ 精确名规则 |
| /zzq-random-2438/config.json | 404 / 1883B | **不存在目录** ⇒ 403 与目录内容无关 |
| /config.json、/dc/config.json、/module/dcshop/config.json、/userdata/config.json、/layout/admin/img/2015/config.json | 全 403 / 213~235B | 跨目录一致 ⇒ 全局黑名单 |
| readme.txt / README.txt / logs.png 在 /、/dc/、/userdata/files/、/layout/admin/img/2015/ | 全 403 | 同上 |
| Readme.txt、zzqlogs.png、log.png、my-logs.png | 404 | 大小写/近似名不命中 |

16 种绕过（//、./、%2e、尾斜杠、`config.json::$DATA`、%20、%00、`config.json;.txt`、`?x=1`、Accept: text/plain 协商、Host 切 localhost、大小写）全部仍 403，无可读通道。

## 结论
- `.htaccess <FilesMatch>` 把一组名字做了全局拒绝：命中 403 只说明"你请求了黑名单里的名字"，**不说明任何目录里存在该文件**。
- 在备份/配置发现流程中，403 必须做"跨目录同名对照 + 不存在目录对照"两步才能定性；只凭 403 记"文件存在"会污染结论。
- 若确实需要读这类文件，唯一路径是绕过规则本身（编码/协商/换 vhost），全部失败即判定该面不可读。
```
