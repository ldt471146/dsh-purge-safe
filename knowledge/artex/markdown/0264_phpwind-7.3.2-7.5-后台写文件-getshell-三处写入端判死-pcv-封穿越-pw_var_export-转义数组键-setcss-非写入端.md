# PHPWind 7.3.2/7.5 后台写文件 getshell 三处写入端判死（Pcv 封穿越 / pw_var_export 转义数组键 / setcss 非写入端）+ data 目录"是否写入成功"的可靠判据

- **code**: phpwind-7.3.2-7.5-后台写文件-getshell-三处写入端判死-pcv-封穿越-pw_var_export-转义数组键-setcss-非写入端
- **kind**: template
- **category**: path-traversal
- **component**: PHPWind 7.3.2/7.5SP3 admin/setstyles.php + example.com PostLog + require/common.php Pcv/pw_var_export
- **language**: php
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-08 在 example.com + example.com（PHPWind 7.3.2 GBK / nginx / 宝塔）实测：002 上 `POST adminjob=setstyles body action=add&step=2&setting[0]=zq9x&setting[1]=wind` → 200|14759「添加风格完成」(INSERT+updatecache_sy 均执行)，随后 `GET /data/bbscache/wind_zq9x.css` → **404|548**（静态判据）；001 上合法后台 marker POST（`mk=PWMARK9XF1`，回显 200|14759「非法请求」= PostLog 之后才 PostCheck）后完整下载 `/data/bbscache/admin_record.php`（200|27524443）→ **marker 0 命中**，末条时间戳 1785304153(2026-07) 未变。对照：`/data/style/wind_css.htm` → 200|14279 且带 `Last-Modified: Fri, 18 Jun 2021 04:40:46 GMT`（静态判据可用）；`/data/style/zq9x.php` → 403|548、`/data/style/zq9x.php/` → 404|548（两者都不能当存在性判据）。源码依据取自本地 PHPWind 7.5SP3（require/target105.example.com:221/231/372/456/646、admin/target188.example.com:156/168/186、admin/target117.example.com:612-647、admin/example.com:103/197/537）。
- **path**: pocs/phpwind-7.3.2-7.5-后台写文件-getshell-三处写入端判死-pcv-封穿越-pw_var_export-转义数组键-setcss-非写入端/poc.php
- **tags**: phpwind,后台getshell,判死,Pcv,路径穿越,setcss,PostLog,admin_record,pw_var_export,写文件判据,readonly
- **created_at**: 2026-10-08T06:31:56.720Z
- **found_by**: exploit

## 描述

PHPWind 后台写文件 getshell 链的三处写入端（setstyles name/tplpath 穿越、cache.php eval 输入、PostLog 追加 .php）源码级+实测双重判死，并给出 data/ 目录下唯一可靠的"文件是否写成功"判据。

## 用法

```
打 PHPWind 后台 getshell 前先读本条的"判死"三条，直接跳过：① 不要用 `../` 做 setstyles name/tplpath 穿越（Pcv 会 exit('Forbidden')，返回 9 字节）；② 不要用 POST 数组键做代码注入（键也被转义）；③ 不要指望 `action=setcss` 写 CSS 内容（它只 setConfig）。验证"文件到底写没写进去"时，**只用静态后缀路径**（.css/.htm/.txt）或静态文件的 `Last-Modified`，绝不要用 `/data/**.php` 的 403、也不要只用 `/data/**.php/` 的 200/404。
```

## 正文

```
# 结论：PHPWind「后台写文件 getshell」链在本机三处写入点全灭（源码级 + 实测双证）

## 一、源码级三条硬约束（7.5SP3 源码逐行，与目标 7.3.2 同源）
1. **Pcv 封死路径穿越**（require/target105.example.com:372-380）：
   ```php
   function Pcv($filename,$ifcheck=1){
     $tmpname=strtolower($filename);
     $tmparray=array('://',"\0"); $ifcheck && $tmparray[]='..';
     if (str_replace($tmparray,'',$tmpname)!=$tmpname) exit('Forbidden');
     return $filename;
   }
   ```
   而 `writeover()`（:231）与 `readover()`（:221）**默认都带 $check=1 调 Pcv** ⇒
   `writeover(D_P."data/style/$name.php",...)`、`writeover(D_P."data/bbscache/".$tplpath."_".$stylepath.".css",...)` 里的
   `$name`/`$tplpath`/`$stylepath` **只要含 `..` 就直接 exit('Forbidden')**。所以 setstyles 的 name/tplpath 路径穿越**不是"能不能写"，而是源码层就不可达**（判据：请求会拿到 9 字节 `Forbidden` 而不是别的）。
2. **pw_var_export 连数组键一起转义**（:456-471）：字符串分支 `str_replace(array("\\","'"),array("\\\\","\'"),$input)`；数组分支对 `$key` 也递归调用 `pw_var_export($key,...)` ⇒ 用 POST 数组键（`setting[3][x]=`）做 PHP 代码注入的常见套路**在 PHPWind 上不成立**。
3. **action=setcss 是开关不是写入端**（admin/target188.example.com:156-166）：
   ```php
   } elseif ($_POST['action'] == 'setcss') {
     InitGP(array('showcss'));
     setConfig('db_showcss', $showcss);
     updatecache_c();
     if ($showcss) { updatecache_sy(); }
     adminmsg('operate_success');
   ```
   只改配置 + 可选触发 updatecache_sy()，**不写任何文件内容** ⇒ 不能把 payload 写进 `data/style/wind_css.htm`。
   （`action=editcss` 那段在 :136-155 被整段 `/* */` 注释，官方已关。）
   ⇒ **`target117.example.com:642-644` 的 eval 链（readover `data/style/{tplpath}_css.htm` → `eval("\$style_css = \"$style_css\";")`）虽然是真的，但没有可控写入端喂它，链条不闭合。**

## 二、两条实测（本项目 2026-10-08）
| 判据 | 命令 | 结果 |
|---|---|---|
| 静态文件判据（无 PHP 兜底干扰） | `GET /data/bbscache/wind_zq9x.css`（`action=add` 令 updatecache_sy 去写它，tplpath=wind/stylepath=zq9x） | **404\|548** ⇒ 没写成 |
| 全量日志判据 | 合法后台会话发 marker POST（PostLog 在 PostCheck 之前执行 ⇒ 一定经过 example.com:197 的 `writeover($bbsrecordfile,$new_record,"ab")`）→ 完整下载 `/data/bbscache/admin_record.php`（27,524,443B） | **marker 出现 0 次**，末条时间戳仍 1785304153(2026-07) |

## 三、判据纪律（血泪）
- **`/data/**.php` 不带尾斜杠 → 403，与文件是否存在无关**（nginx deny 规则先命中）⇒ 403 **不能**当存在性判据。
- `/data/**.php/` 带尾斜杠 → 有的实例返 404|548，有的实例返一段 `_SERVER` 转储（372/587B，跟 Cookie 长度变）⇒ **尾斜杠也不是可靠判据**。
- **可靠的只有静态后缀**：`.css`/`.htm`/`.txt`（200+内容 或 404|548）+ `Last-Modified` 头（例：`data/style/wind_css.htm` → `Last-Modified: Fri, 18 Jun 2021 04:40:46 GMT`）。
- PostLog 会把 `password`/`check_pwd` 掩码成 `***`（example.com:544），**别指望从日志里捞 DB 口令**；本项目 27.5MB 日志里 `dbpw/dbuser/dbname` 出现 0 次。

```
