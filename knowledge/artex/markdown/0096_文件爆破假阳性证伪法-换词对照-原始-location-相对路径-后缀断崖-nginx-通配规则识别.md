# nginx `/login` 通配重定向规则会造成 ffuf 假阳性：命中项必须用『任意词对照』核实

- **code**: 文件爆破假阳性证伪法-换词对照-原始-location-相对路径-后缀断崖-nginx-通配规则识别
- **kind**: script
- **category**: methodology
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com 靶标 203.0.113.36:443（Windows 宝塔托管的 PHP 系统 dishini，nginx + PHP 7.4.33）实测：ffuf 用 287 词 webshell 字典跑 /upload/（1148 请求）与 /dtjs/（1148 请求），各只命中一条 /upload/login、/dtjs/login（302）。用本方法证伪 —— ① 换词对照：/abc/login、/foobar/login、/dtjs/zzqqxx/login、/upload/admin/login 全部同样 302 且 Location 与命中项完全相同；② 原始 Location 为相对路径 ../example.com，被 curl 按请求目录解析后产生"目标不同"的错觉；③ 后缀断崖：/dtjs/login2、/dtjs/alogin、/upload/loginx 全部 404。⇒ 确认该 nginx 存在规则「凡以 /login 结尾的路径一律交给 PHP 并回 header('Location: ../example.com')」，两条命中均为假阳性（未计入成果）。附带情报：由规则的 Location 反推出真实存在的 /agent/login.php、/uxj/login.php。该方法同时纠正了我早期把 /agent/login 误读为"302 到 /agent/login.php（真实文件）"的错误表述。
- **path**: pocs/文件爆破假阳性证伪法-换词对照-原始-location-相对路径-后缀断崖-nginx-通配规则识别/poc.sh
- **tags**: 假阳性,nginx重写,通配规则,目录爆破,ffuf,对照实验,Location相对路径,方法论
- **created_at**: 2026-09-28T23:08:06.277Z
- **found_by**: vuln-scan

## 描述

识别并证伪"nginx 重写/通配规则制造的文件爆破假阳性"的方法：换词对照 + 查原始 Location 相对路径 + 后缀断崖测试三件套；并把假阳性反向利用为服务端规则指纹与真实文件推断。含检查清单与常见误判。

## 用法

```
# 从一个"命中"出发，三步证伪/证实
HIT="/upload/login"; BASE="https://TARGET"
# ① 换词对照：同形态不同词，若结果一致 ⇒ 规则
for w in abc foobar zzqqxx admin a 1; do
  curl -s -k -i "$BASE/upload/$w/login" | head -1
  curl -s -k -i "$BASE/upload/$w/login" | grep -i "^Location:"
done
# ② 打印原始 Location（不要用 curl -w %{redirect_url}，它会解析相对路径）
curl -s -k -i "$BASE$HIT" | grep -iE "^(HTTP|Location|X-Powered-By)"
# ③ 后缀断崖：破坏匹配形态应立刻 404
for s in "" 2 x /x; do curl -s -k -o /dev/null -w "login$s -> %{http_code}\n" "$BASE/upload/login$s"; done
# ④ 若确认为规则：把它当情报——用 Location 反推真实文件、并把该词标记为"本例恒定假阳性"
```

## 正文

```
## 问题
目录/文件爆破（ffuf、dirsearch、feroxbuster）在 nginx 站点上会产生**由 nginx 重写/通配规则制造的固定假阳性**——某个词恰好命中规则的匹配形态，于是"命中"了，但它**不是真实文件**。若直接计入成果，报告里就会出现一条查不到的"隐藏入口"。

## 判据：随机词对照（三件套，必须同时做）
1. **换一个词，保持同样的形态**：若 `/<任意词>/<命中词>` 也返回相同状态码与相同响应头 ⇒ 是规则，不是文件。
   实证：`/upload/login`、`/dtjs/login`、`/abc/login`、`/foobar/login`、`/dtjs/zzqqxx/login`、`/upload/admin/login` **全部 302 且 `Location` 完全相同** ⇒ 规则为「凡以 `/login` 结尾一律交给 PHP 并回 `Location: ../example.com`」。
2. **看 Location 是否为相对路径**。相对路径（`../example.com`、`login.php`）说明是**应用内 `header()` 输出**，会被客户端按"请求所在目录"解析，**同一响应在不同 URL 下解析出不同目标**——这正是误判"某个路径 302 到某个真实文件"的根源。
   实证：`/upload/login` 的 `Location: ../example.com` 被解析成 `/example.com`；`/upload/agent/login` 的同一响应被解析成 `/upload/example.com`。**看起来像"不同目标"，其实是同一条规则。**
3. **加/减后缀必须断崖**：真实文件通常 `.php` 存在、`.phpx` 不存在；但规则的匹配形态一旦被破坏（`login2`、`alogin`、`loginx`）就立刻 404 —— 证实它是**形态匹配**（正则 `$/login$` 之类）而非文件。

## 反向利用：把假阳性变成"规则指纹"
一旦确认是规则，这条规则本身就是**服务端配置情报**：
- 它揭示了 nginx 的 location/rewrite 形态（如"`/…/login` 交给 PHP 统一处理"），可用于**推断应用的路由层设计**；
- 它给出了**该服务器上唯一确定存在的真实文件**（本例中由规则的 Location 反推出 `/agent/login.php`、`/uxj/login.php` 确实存在）；
- 它让后续所有人的字典结果可被校正：**在该目标上，`login` 一词恒产生 1 条假阳性**。

## 检查清单（每次爆破后必做）
- [ ] 逐条命中做"换词对照"（至少 2 个随机词 + 1 个同前缀异后缀）
- [ ] 打印**原始 `Location` 头**（不要只看 curl 的 `%{redirect_url}`，它会解析相对路径）
- [ ] 对照是"同码同长度同头"才算假阳性；**只要有一处不同，就可能是真文件**
- [ ] 假阳性**写明在 asset_test 里**，别让它流进报告

## 常见误判
- 只看状态码不看响应头 ⇒ 把规则当文件。
- 只看 curl 解析后的 `redirect_url` ⇒ 相对路径被按请求目录解析，产生"不同路径不同目标"的错觉。
- 用通用大字典跑完就直接写报告 ⇒ 规则类假阳性在多数 nginx 站点上都会撞到 1~2 条。
```
