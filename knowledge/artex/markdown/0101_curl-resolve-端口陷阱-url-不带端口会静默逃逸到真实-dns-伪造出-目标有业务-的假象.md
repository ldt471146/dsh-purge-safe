# curl --resolve 端口陷阱：URL 不带端口会静默逃逸到真实 DNS（伪造出"目标有业务"的假象）

- **code**: curl-resolve-端口陷阱-url-不带端口会静默逃逸到真实-dns-伪造出-目标有业务-的假象
- **kind**: script
- **category**: recon
- **severity**: info
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-09-29 在 449918-com 靶标复核 203.0.113.73/.178/.188:8443 时实际踩中并复现：错误写法下三个域名分别返回 46913B（CF 版 neapi 首页）、15102B（CF 回源 .71:80 的 net.ng-api.vip）、114B（AWS 上 GoDaddy 停放页），几乎被误判为"8443 上存在隐藏业务站点"；同一批次中 ng-api.vip 返回 000（其真实 DNS 为 NXDOMAIN）暴露了逃逸。改用 URL 显式带 :8443 并加 -w "%{remote_ip}" 后，peer 显示 203.0.113.73/.178/.188，全部 Host 返回同一份 10B 响应（sha 93F5808BADB0AA5D，三台一致），与既有 host-map.log 结论相符 ⇒ 原结论无需更正。
- **path**: pocs/curl-resolve-端口陷阱-url-不带端口会静默逃逸到真实-dns-伪造出-目标有业务-的假象/curl-resolve-port-trap.md
- **tags**: curl,取证陷阱,方法论,vhost,避坑,静默失败
- **created_at**: 2026-09-28T23:42:29.946Z
- **found_by**: vuln-scan

## 描述

记录一个静默失败型取证陷阱：curl --resolve 绑定非标准端口时，若 URL 未显式带同一端口，请求会逃逸到真实 DNS（CDN/公网真站），返回真实内容从而伪装成"目标机的业务响应"，极易产出完全错误的结论。

## 用法

```
复现（错误写法 vs 正确写法）：
# 错误：URL 无端口，--resolve 绑 8443 ⇒ 逃逸到 CF，拿到真实站点内容
curl.exe -k -s --resolve "www.neapi.com:8443:203.0.113.73" -o e.bin -w "%{http_code} %{size_download}\n" "https://www.neapi.com/"
#   -> 200 46913（Cloudflare 内容，非目标机）

# 正确：URL 显式带同一端口 + 打印 remote_ip 自证
curl.exe -k -s --resolve "www.neapi.com:8443:203.0.113.73" -o c.bin -w "%{remote_ip}|%{http_code} %{size_download}\n" "https://www.neapi.com:8443/"
#   -> 203.0.113.73|200 10（目标机真实响应）

# 更稳的等价写法
curl.exe -k -s --connect-to "www.neapi.com:8443:203.0.113.73:8443" -o c2.bin -w "%{remote_ip}|%{http_code}\n" "https://www.neapi.com:8443/"
```

## 正文

```
# curl --resolve 端口陷阱：URL 不带端口 ⇒ 静默逃逸到真实 DNS
#
# ============ 症状 ============
# 对 <IP>:8443 做 vhost 探测时写出：
#     curl -k --resolve "host.example.com:8443:203.0.113.6" https://host.example.com/
# 期待：连到 203.0.113.6:8443。
# 实际：URL 未带端口 ⇒ curl 默认拨 **443**；
#       --resolve 的映射被绑定在 **8443** 上 ⇒ 443 这个端口号没有任何映射被命中
#       ⇒ curl 回落到**真实 DNS 解析** ⇒ 请求发到了 Cloudflare / AWS / 公网真站。
#
# ============ 为什么危险（静默 + 高可信假象） ============
# 1. curl 不报错，HTTP 状态码是 200/301/404，看起来完全正常；
# 2. 返回的是**真实网站的真实内容**，比"目标机空白页"更像"有业务"；
# 3. 于是极容易写出"发现隐藏站点！"这种完全错误的结论——而证据其实来自 CDN。
# 实测踩坑样本（2026-09-29，靶标 449918-com）：
#     www.neapi.com        -> 200 len=46913   ← 实为 Cloudflare 后的 WordPress
#     net.ng-api.vip       -> 200 len=15102   ← 实为 CF 回源到另一台 .71:80 的结果
#     www.luckywin666.net  -> 200 len=114     ← 实为 AWS 上 GoDaddy 域名停放页
#     ng-api.vip           -> 000             ← 该域真实 DNS 为 NXDOMAIN，暴露了"根本没走 --resolve"
#     （对照：端口为 443 的 .68:443 因端口号恰好匹配，结果才是有效的）
#
# ============ 强制自证的三件套（缺一不可） ============
# 1) URL 必须显式带端口，与 --resolve 的端口**逐字一致**；
# 2) -w 里打印 %{remote_ip}，逐请求核对对端是否 == 目标 IP，不等就标记 ESCAPED；
# 3) 保留一个"真实 DNS 为 NXDOMAIN 的对照域"（如 ng-api.vip）作探针——
#    它若返回 000 而其它域返回 200，说明 --resolve 生效（因为该域只能靠 --resolve 解析成功）；
#    它若也能返回内容，说明发生了逃逸。
#
# ============ 正确写法 ============
#   curl.exe -k -s --resolve "host.example.com:8443:203.0.113.6" \
#        -o out.bin -w "%{remote_ip}|%{http_code}" "https://host.example.com:8443/"
# 判读：输出里的 remote_ip 必须等于 203.0.113.6，否则整批数据作废。
#
# 附：等价的安全做法（不依赖 --resolve）
#   curl.exe -k -s -o out.bin -w "%{remote_ip}|%{http_code}" \
#        --connect-to "host.example.com:8443:203.0.113.6:8443" "https://host.example.com:8443/"
#   --connect-to 语义更不易错（src_port:dst_port 成对出现），推荐优先使用。

```
