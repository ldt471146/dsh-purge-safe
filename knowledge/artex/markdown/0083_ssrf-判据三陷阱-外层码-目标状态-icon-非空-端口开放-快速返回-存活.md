# SSRF 判据三陷阱：外层码≠目标状态 / icon 非空≠端口开放 / 快速返回≠存活

- **code**: ssrf-判据三陷阱-外层码-目标状态-icon-非空-端口开放-快速返回-存活
- **kind**: poc
- **category**: ssrf
- **component**: [通用方法] SSRF 响应判读 / get_head 类 URL 解析器
- **severity**: info
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.32:888（六零导航页 LyLme Spage example.com）实测踩坑并纠正：最初把"SSRF 回显里的 code=200"误读为"目标 127.0.0.1:8888 上有宝塔面板"（并据此上过一条情报），事后按正确判据重测——`127.0.0.1:80` title=`404 Not Found`、`127.0.0.1:443` title=`400 The plain HTTP request was sent to HTTPS port`、`127.0.0.1:888` title=`403 Forbidden`（三者均为真实 HTTP 响应），而 `8888/8080/3306/6379/9200/11211/27017/22/21/2375/9010/10010/7001/9090/3000` 的 **title 全为空**；13 个宝塔特征路径（`/login`、`/pma/`、`/phpmyadmin/`、`/site?action=GetSiteList` 等）title 亦全空、无差异 ⇒ **正式撤回"8888 是宝塔"的结论**。源码依据：`include/function.php:242-247`（icon 回退逻辑）与 `219-251`（get_head 只正则提取 4 个字段）。
- **tags**: SSRF,判据陷阱,get_head,误判,方法论,icon字段,端口探测
- **created_at**: 2026-09-28T21:27:18.033Z
- **found_by**: exploit

## 描述

用"服务端抓取并回显解析结果"的 SSRF（典型实现：curl 抓页面 → 正则提取 title/icon/description/keywords → 以 JSON 返回）时，**三个极易踩的判据陷阱**：<br>① **外层 HTTP 码不是目标服务的状态码**：应用自己总是返回 200，被 SSRF 请求的目标是死是活、返回几几几，都体现在回显 JSON 的字段里，**看 title/description/keywords 才能判断目标是否有可用响应**；<br>② **`icon` 字段非空 ≠ 目标端口开放**：这类实现通常会在拿不到 icon 时"拼一个 `<scheme>://<host>:<port>/favicon.ico` 并探测"，而探测函数在**连接失败（返回 false）**与**响应非 404** 时**走的是同一个分支**，结果都是"icon 被赋值"，所以 icon 非空既不能证明端口开放、也不能证明它是 HTTP；<br>③ **"快速返回"也不等于"存活"**：连接被拒（RST）会立刻返回空内容，而被 DROP 会长时间超时 —— 两者都不能单独作为存活判据，必须结合 title 是否可解析。

## 用法

```
```bash
# 正确姿势：只看回显 JSON 里的 title（有可解析文本 = 目标返回了 HTML）
curl -s "http://TARGET/apply/example.com?url=http://127.0.0.1:80/" | jq -r '.title'
# 期望：nginx 的 "404 Not Found" → 证明目标本机 80 有 HTTP 服务
# 若 title 为空 → 无论 icon 是否有值、无论耗时多短，都不能断定该端口有 HTTP 服务
```
```
