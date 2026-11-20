# PHPWind 7.x 探测方法论：CC 防护 pwDefendCc 导致的「0 字节假阴性」与四条规避规范

- **code**: phpwind-7.x-探测方法论-cc-防护-pwdefendcc-导致的-0-字节假阴性-与四条规避规范
- **kind**: script
- **category**: recon
- **component**: PHPWind 探测方法论
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.126（PHPWind 7.3.2 / nginx 1.30.4 / 宝塔）实测：改用 -b -c 同文件读写后连发 8 个请求（showface/tag/leaveword 循环）全部正常返回 826/61/86，零 0 字节；而旧方法（只 -b 不回写）从第 2-3 个请求起就全 0。交错基准 + 10s 间隔下做 4 轮独立验证（含文件字节测量），3 种基准 action 共 11 次全部零偏离。pwDefendCc 机制由 require/common.php L83-124 源码逐行确证。\n\n【2026-10 增补 · 三态判据】双站 206 项 action 枚举实战：六合王 example.com 23 项（基准 preview 4 次全 2490B）、pw_example.com 52 项（基准 showface 8 次全 826B）、其余入口 56 项；主站 job+ajax 75 项（基准 showface 9 次全 826B）—— 其中主站首轮 7 项 curl 未产生响应体（size=-1），按旧口径被计入「0 字节」→ 误判为不存在。单独复核（间隔 10s，基准 826×2）后确认 5 项实际存在：taglist=2515B、topost=2611B、birth=2573B、pushto=79B（没有可供推送的位置）、delmutiatt=1025B；仅 pcexport、delmutiattone 真为 0 字节。\n\n【根因】12-probe-actions.ps1 里 `$size = if (Test-Path $body) { (Get-Item $body).Length } else { -1 }`，而汇总行用了 `Where-Object { $_.size -le 0 }` 把 -1 与 0 混为一谈 → 后人据此判「不存在」即假阴性。**正确做法**：汇总时分别统计 `-eq -1`（失败，需重测）、`-eq 0`（不存在）、`-gt 0`（存在）三态，并把 `-1` 项单独列出重跑。
- **path**: pocs/phpwind-7.x-探测方法论-cc-防护-pwdefendcc-导致的-0-字节假阴性-与四条规避规范/phpwind-probe-cc-bypass.md
- **tags**: phpwind,方法论,CC防护,假阴性,探测规范,盲注,布尔判定
- **created_at**: 2026-10-06T19:03:37.102Z
- **found_by**: exploit

## 描述

PHPWind 主动探测规范：规避 pwDefendCc 造成的 0 字节假阴性（cookie 回写 + 基准校准 + 文件字节测量）

## 用法

```
照抄第三节骨架即可。核心四件事：① curl 必须 -b jar -c jar 同文件读写 ② 每轮夹 showface(826)/preview(2474) 基准做判据校准 ③ size 用 (Get-Item f).Length 而非 curl -w ④ ★**输出口径必须显式区分三态**：`-1`（curl 未产生响应体，请求失败）/ `0`（真 0 字节）/ `>0`（有响应）。判「不存在」的唯一合法条件 = **同轮基准正常 + 测试为 `0`**；**`-1` 绝不能判「不存在」**（实战踩过：主站首轮 7 项 `-1` 被误读为 0 字节，导致错误得出「两套部署 action 集不同」的结论，复核后 5 项实际存在）。
```

## 正文

```
#!/usr/bin/env bash
# =============================================================================
# PHPWind 7.x 主动探测规范 —— 规避 CC 防护 pwDefendCc 造成的「0 字节假阴性」
#
# 适用：任何对 PHPWind 7.x 站点做 action 存在性探测 / 盲注 / 布尔判定
# 价值：不遵守本规范会把「存在但被 CC 拦」误判为「action 不存在」，
#       直接导致整条攻击链被错误判死（本项目实测踩过）
# =============================================================================

## 一、根因：require/common.php L83-124 pwDefendCc()
#   global.php L36-38: if ($db_cc && !defined('COL')) pwDefendCc($db_cc);
#   L91:  Cookie('c_stamp',$timestamp,0);                                  # 下发时间戳 cookie
#   L92:  $c_stamp = GetCookie('c_stamp');
#   L93:  $c_crc32 = substr(md5($c_stamp.$pwServer['HTTP_REFERER']),0,10); # 指纹 = f(c_stamp, Referer)
#   L100: if (($db_xforwardip || $cc==2) && ($timestamp-$c_stamp>3 || $timestamp<$c_stamp)) {
#   L108:     if (trim($c_value[1])==$onlineip && $c_crc32==$c_value[0]) { $c_on = true; break; }
#   L114:     if ($c_on) { echo 'Forbidden, Please Refresh'; ... exit; }   # 命中即封
#   L122:     writeover(D_P.'data/ccip.txt',"$c_crc32\t$onlineip\n",'ab'); # 记录指纹
#
# 触发链（最常见的误操作）：
#   只 -b 读 cookie、不用 -c 回写  => 服务端 L91 下发的 c_stamp 永远不回传
#   => L92 取空 => L93 指纹恒为 md5('' . Referer) 这个常量
#   => 首次被 L122 写入 ccip.txt 后，后续每次都命中 L108 => L114 exit
#   => 表现为「HTTP 200 + 空 body（0 字节）」—— 与「action 不存在」完全撞车

## 二、四条硬性操作规范
# 1) cookie 同文件读写（最关键）
#    curl -sk --noproxy '*' -b jar.txt -c jar.txt -A "$UA" -e "$BASE/" ...
#    -b 与 -c 必须指向同一文件；长时间暂停后建议重建 jar（旧 c_stamp 会导致持续命中）
# 2) 请求间隔 ≥ 10s（或 < 3s 且回传 cookie）
#    L100 的条件是 $timestamp-$c_stamp>3 才进检查；10s 间隔 + 回传 cookie 时
#    c_stamp 每次刷新为新时间戳 => 指纹每次不同 => 不会命中历史记录
# 3) 每轮测试前后夹「已知存在的基准 action」
#    基准选型（PHPWind 7.3.2 实测值，用作判据校准）：
#      pw_example.com?action=showface          -> 826 字节
#      pw_example.com?action=tag&tid=1         -> 61  字节
#      pw_example.com?action=leaveword         -> 86  字节（需登录态）
#      example.com?action=preview               -> 2474 字节
#      example.com?action=sign                  -> 804  字节
#    判据：只有「基准正常 + 测试为 0」才判不存在；基准也被污染则该轮作废重跑
# 4) size 必须用「文件实际字节数」测量，绝不用 curl -w
#    原因：-o NUL 时 PowerShell 报 StandardOutputEncoding 错误，$r 会静默变空字符串
#    正确写法：
#      curl.exe ... -o out.html "$URL"
#      $sz = (Get-Item out.html).Length
#    错误写法（会产生假数据源，静默把 size 变成空值）：
#      $r = & curl.exe ... -o NUL -w "%{size_download}" "$URL"    # $r 为空字符串

## 三、可直接复用的探测骨架（PowerShell）
$BASE = "https://TARGET/bbs"
$UA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/203.0.113.36 Safari/537.36"
$JAR  = "jar.txt"
function Probe($label, $body, $path) {
  $f = "out_$label.html"; Remove-Item $f -ErrorAction SilentlyContinue
  & curl.exe -sk --noproxy '*' -b $JAR -c $JAR -A $UA -e "$BASE/" -X POST -d $body -o $f "$BASE/$path" 2>$null
  $sz = if (Test-Path $f) { (Get-Item $f).Length } else { -1 }
  "{0,-24} size={1}" -f $label, $sz
}
# 交替序列：基准 -> 测试 -> 基准 -> 测试 -> 基准
Probe "bench-showface" "action=showface" "pw_example.com"; Start-Sleep 10
Probe "test-target"    "action=XXX"      "pw_example.com"; Start-Sleep 10
Probe "bench-showface" "action=showface" "pw_example.com"

## 四、「0 字节」的三个来源（必须区分，否则误判）
#  来源1 action 真不存在      -> 干净基准下的 0
#  来源2 CC 防护封禁           -> 连续快发/未回传 cookie 后的 0（本规范要消灭的）
#  来源3 action 存在但无输出   -> 如 pw_example.com 游客白名单的 pingpage/login 缺参数时
# 另注意：PHPWind 对「未登录 + 非白名单 action」返回的是 101 字节 not_login 提示页（非 0），
#         所以「0 字节」不能用「掉登录」来解释 —— 掉登录会给你 101 字节。

## 五、配套：pwInitGlobals() 掐死 register_globals 注入
#  require/common.php L132-148
#  $allowed = array('GLOBALS'=>1,'_GET'=>1,'_POST'=>1,'_COOKIE'=>1,'_FILES'=>1,'_SERVER'=>1,'P_S_T'=>1);
#  foreach ($GLOBALS as $key => $value) { if (!isset($allowed[$key])) { $GLOBALS[$key]=null; unset($GLOBALS[$key]); } }
#  => 除上述白名单外的所有全局变量被置 null 并 unset
#  => 「用请求参数覆盖 $GLOBALS 里某个变量」这类利用思路（如覆盖 example.com L86 的 $_G['uploadtype']）一律无效
#  测试该机制是否生效的方法：传一个与源码全局变量同名的参数，看行为是否变化；不变化即已被清理

```
