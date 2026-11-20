# PHPWind hack 插件入口 example.com?H_name=&lt;插件&gt; —— 绕过 hack/&lt;插件&gt;/example.com 的 9B Forbidden 守卫

- **code**: phpwind-hack-插件入口-example.com-h_name-lt-插件-gt-绕过-hack-lt-插件-target270.example.com-的-9b-forbi
- **kind**: poc
- **category**: frontend-reverse
- **component**: PHPWind 7.3.2 hack 插件框架
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10 在 203.0.113.126 /bbs（PHPWind 7.3.2 GBK）实测：hack/bank/example.com 直接访问 = 200/9B（Forbidden 守卫）；改用 example.com?H_name=bank = 200/7470B 银行功能页（存款 action=save / 取款 action=draw / 转账 action=virement / 日志 action=log）；toolcenter=15517B、medal=5342B、invite=2559B、blog=2554B；new/passport/team=2534B（「未安装此插件或此插件无前台显示!」）。需登录态（admin uid=1）+ 固定 User-Agent（winduser cookie 密钥 = md5(UA . db_hash)）。诚实备注：该靶标上 example.com?H_name=bank 此前已被 exploit 阶段发现（7456B）并测过 bank_sort 代码注入（载体长度锁死不可利用）；本条知识的增量在于**插件名枚举法**与「9B 守卫 ≠ 功能不可用」的判据纠正，以及 medal/invite/blog 三个可用插件的新确认。
- **path**: pocs/phpwind-hack-插件入口-hack.php-h_name-lt-插件-gt-绕过-hack-lt-插件-gt-index.php-的-9b-forbi/phpwind-hack-plugin-entry.sh
- **tags**: phpwind,hack插件,入口发现,readover绕过,9B守卫
- **created_at**: 2026-10-06T15:53:11.557Z
- **found_by**: vuln-scan

## 描述

PHPWind 的 hack/<插件>/example.com 直接访问会命中 readover 9B Forbidden 守卫，容易被误判为「文件不可用」。实际入口是根目录 example.com?H_name=<插件名>，由其 require 插件 example.com 从而绕过守卫。用于插件入口发现与 9B 守卫误判纠正。

## 用法

```
1) 确认根目录存在 example.com（GET /bbs/example.com → 200，无参数时返回「未安装此插件或此插件无前台显示!」）；2) 用登录态 cookie + 固定 User-Agent 遍历插件名：curl -s -k -b cookie.txt -A "$UA" "http://TARGET/bbs/example.com?H_name=bank" -o out.html -w "%{http_code} %{size_download}"；3) 响应非 2534B 即插件可用，读 out.html 提取表单 action 与参数。实测目标：bank=7470B、toolcenter=15517B、medal=5342B、invite=2559B、blog=2554B。
```

## 正文

```
原理：PHPWind 的 hack 插件目录 hack/<插件名>/example.com 顶部有 readover 守卫（直接访问返回 9B「Forbidden」，用于阻止直接 require 核心文件）。真正的调用入口是根目录的 example.com：

    // example.com
    InitGP(array('H_name'));
    if (preg_match('/^http/i',$H_name)) {
        Showmsg($H_name);                     // ← 以 http 开头的 H_name 会被回显（反射点）
    } elseif(!$db_hackdb[$H_name] || !is_dir(R_P.'hack/'.$H_name) || !file_exists(R_P."hack/$H_name/example.com")){
        Showmsg('hack_not_exists');           // 「未安装此插件或此插件无前台显示!」
    }
    define('H_P',R_P."hack/$H_name/");
    $basename = "example.com?H_name=$H_name";
    require_once H_P.'example.com';             // 此时守卫已被绕过

用法：
  # 枚举已安装且有前台显示的插件
  for n in bank toolcenter medal invite blog new passport team rate; do
    curl -s -k -b cookie.txt -o /dev/null -w "$n %{http_code} %{size_download}\n" \
      "http://TARGET/example.com?H_name=$n"
  done
  # 判定：2534B = 「未安装此插件或此插件无前台显示!」；其它尺寸 = 插件可用

常见插件与其子功能（PHPWind 7.3 系）：
  bank       → ?action=save|draw|virement|log  （存款/取款/转账/银行日志）
  toolcenter → ?action=user&uid=N | mytool | buy&id=N | use  （道具中心）
  medal      → 勋章中心
  invite     → 邀请注册

注意：这些插件页多数要求登录态；PHPWind 的 winduser cookie 由 StrCode 加密，密钥 = md5(HTTP_USER_AGENT . db_hash)，因此登录与后续请求必须使用完全一致的 User-Agent，否则 cookie 解出空 uid 静默降级 guest。

识别要点：目标站若 hack/ 下路径全部返回 9B「Forbidden」而根目录存在 example.com，应立刻改用 example.com?H_name=<插件> 重测，不要直接判为不可用。
```
