# Werkzeug 2.2.3 TLS 反代：绝对形式 request-target 不触发 SSRF（path 提取/netloc 丢弃 + 公共出口证书明码校验）

- **code**: werkzeug-2.2.3-tls-反代-绝对形式-request-target-不触发-ssrf-path-提取-n
- **kind**: poc
- **category**: ssrf
- **component**: Werkzeug/2.2.3 + Flask reverse proxy
- **severity**: low
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 于 shopto.net 90.152.8.56:5012（Werkzeug/2.2.3 Python/3.7.3，TLS cert SHA256=da3258bfa2faff61…）实测：43 条公共 CONNECT 出口按 robots 200/25B+X-Cache Miss+证书 SHA256 三重定标；28 种绝对形式 request-line（http://example.com/、IMDS、127.0.0.1:8081/BC140、localhost:8080、90.152.8.58、192.168.56.180:7700、10.50.7.28:6379、http:/、http:\\、//、@、%2f%2f、hex/dec IP 等）全部只得到 CloudFront 上下文 404/121B（md5 41893a01…）或 403/919B；GET http://www.shopto.net/robots.txt 与 http://shopto.net/robots.txt 均返回 25B API origin robots（www 直连同路径为 787B）证明 netloc 被丢弃；curl 8.5 --request-target 独立复现同样结果（404/121B 与 200/25B）。
- **tags**: ssrf,werkzeug,absolute-form,request-target,negative,proxy-cert-pinning,fake-proxy
- **created_at**: 2026-11-11T22:12:01.944Z
- **engine**: https://90.152.8.56:5012

## 描述

Werkzeug 2.2.x 的 WSGIRequestHandler 会对绝对形式 request-target 做 urlsplit：PATH_INFO 取 URL 的 path、HTTP_HOST 取 netloc，但该反代只把 PATH_INFO+query 拼到固定上游（CloudFront API 分发），netloc 不参与任何出站连接，因此绝对形式请求不构成 SSRF；netloc-only（无 path）形式会触发 308，Location=https://<netloc>/（客户端可控 Location，浏览器无法发送绝对形式 request-line，实际不可利用）。另一条铁律：公共 CONNECT 出口必须逐请求核对目标 TLS 证书 SHA256（本例 da3258bfa2faff61…），曾见出口 13.233.172.115:24183 先通过内容定标、后以不同证书 eceb0a57… 冒充并返回 'EIG Embedded Web Server'/'unsupported path: http://…'/'Could not connect'，只信 robots 内容会被伪出口欺骗。

## 用法

```
复测口径（本机直连目标不可达时）：
1) 出口定标：对每个公共 CONNECT 出口并发 raw TLS（SNI=目标 vhost）GET /robots.txt，要求 200/25B + X-Cache: Miss from cloudfront + TLS 证书 SHA256 与历史值完全一致；
2) 绝对形式测试：CONNECT 目标 IP:5012 后 raw 写入 "GET http://<target>/ HTTP/1.1" + "Host: <vhost>"，逐条记录 status/len/md5/Server/X-Cache；关键鉴别=GET http://<vhost>/robots.txt 返回的是固定上游内容（25B）而非该 vhost 直连内容（787B）→ netloc 被丢弃；
3) 对照：同一绝对形式直连可达的 www:443（--noproxy '*'），若也返回 Example Domain 则是本地记录代理伪造成立、结论作废；
4) curl 交叉复现：env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY curl -sk --path-as-is --proxytunnel -x http://<exit> --request-target 'http://example.com/' -H 'Host: <vhost>' https://<ip>:5012/（注意 --noproxy '*' 会使 -x 失效）。
```
