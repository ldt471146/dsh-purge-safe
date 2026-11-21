# 站群同源判定：多 vhost 是否指向同一 DOCUMENT_ROOT（body diff 相似度 + 尺寸 = 4×主机名长度差）

- **code**: 站群同源判定-多-vhost-是否指向同一-document_root-body-diff-相似度-尺寸-4-主机名长度差
- **kind**: template
- **category**: recon
- **component**: 多 vhost 站群（PHPWind/nginx/宝塔）
- **severity**: info
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-06 在 203.0.113.126（白小姐站群，PHPWind 7.3.2 / GBK / nginx 1.30.4 / 宝塔）实测：`example.com/bbs/` 与 `example.com/bbs/` 完整响应体相似度 **0.9998**，19 行差异全部为主机名字符串（archives / rss.php / example.com?fid= / u.php 四个绝对链接）；尺寸 67528B vs 67544B，差 16B = 4×4；主目标 `example.com` 67556B 与 67528B 差 **28B = 4×7**（主机名长度差 7）。另 6 个 vhost 全部 generator=7.3.2、Set-Cookie 前缀同为 `752fb_`。该判定直接推翻了"站群内存在未加固独立实例"的假设。
- **path**: pocs/站群同源判定-多-vhost-是否指向同一-document_root-body-diff-相似度-尺寸-4-主机名长度差/poc.py
- **tags**: 站群,同源判定,body,diff,DOCUMENT_ROOT,Cookie前缀,判据,负面情报
- **created_at**: 2026-10-06T12:13:11.236Z
- **found_by**: vuln-scan

## 描述

判断同 IP 上多个 vhost/域名是否指向同一个 DOCUMENT_ROOT（即"站群别名"还是"独立部署"）。用完整响应体 diff + 尺寸字节差，2 个包给出数学级结论，用于决定"站群横向"是否值得投入。

## 用法

```
打同 IP 站群前先花 2 个包做本判定：若相似度 ≈0.9998 且差异行全是主机名、尺寸差正好等于 4×主机名长度差 → 判定为"同一站的域名别名"，立即放弃在该族内找"未加固实例"的想法（省整批额度）。只有当 Cookie 前缀 / generator 版本 / 标题**不同**时，才是另一套部署，才值得单独立案。
```

## 正文

```
## 方法（3 步，通常只需 2 发包）

### 1) 取两个不同 vhost 的完整响应体
```python
import ssl, urllib.request, difflib
CTX = ssl.create_default_context(); CTX.check_hostname=False; CTX.verify_mode=ssl.CERT_NONE
OP = urllib.request.build_opener(
    urllib.request.ProxyHandler({"http":"http://127.0.0.1:7892","https":"http://127.0.0.1:7892"}),
    urllib.request.HTTPSHandler(context=CTX))
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/203.0.113.36 Safari/537.36"
def get(u):
    r = OP.open(urllib.request.Request(u, headers={"User-Agent":UA,"Accept":"text/html,*/*;q=0.8"}), timeout=25)
    return r.read()
a, b = get("https://www.EXAMPLE-DOMAIN/bbs/"), get("https://sub.EXAMPLE-DOMAIN/bbs/")
print(len(a), len(b), difflib.SequenceMatcher(None, a.decode("gbk","replace"), b.decode("gbk","replace")).ratio())
for l in difflib.unified_diff(a.decode("gbk","replace").splitlines(),
                              b.decode("gbk","replace").splitlines(), lineterm="", n=1):
    print(l[:200])
```

### 2) 三档判据（按强度递增）
| 现象 | 判定 |
|---|---|
| 相似度 ≈ 0.999x，差异行**全部是主机名字符串**（绝对链接/JS 跳转/archives/rss） | **同一 DOCUMENT_ROOT、同一数据库** = 同一个站，域名只是别名 |
| 尺寸差 = **4 × 主机名长度差** | 同一份文件（首页里主机名出现 4 次）⇒ 数学证据，比"看起来一样"硬 |
| 版块/帖子数/在线人数等**动态数据不同** | 不同实例（不同库） |

### 3) 战术含义（这条判据存在的意义）
- 站群横向（想在同源站群里找"没加固的实例"）**成立的前提是各 vhost 是独立部署**。用本判据先证伪，可省下整批额度。
- 本次实测：6 个 vhost 全部 `generator=7.3.2` + Cookie 前缀同一个 `752fb_`，其中两个 vhost 首页相似度 **0.9998**，19 行差异全是主机名，尺寸 67528 vs 67544（16 = 4×4）；主目标 67556 与 67528 差 **28 = 4×7** ⇒ 主目标与全族是同一个站 ⇒ **站群别名横向 = 0 收益**，加固是"部署模板级"而非逐站手工。
- 辅助判据：Cookie 前缀（PHPWind 的 `xxxx_` 前缀）、`<meta name=generator>` 版本、首页 `title`，任一项不同才说明是**另一套部署**，才值得单独立案。

### 4) 注意
- GBK 站用 `decode("gbk","replace")` 再 diff，否则编码错误会污染相似度。
- 一定要带正常浏览器 UA + Referer（本站首页），并按 1 req/2s 限速。
```
