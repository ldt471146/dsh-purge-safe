# CT 有证书但多源无历史解析：判定内部 docker 预发布反代命名空间（Mnemonic 覆盖窗对照 + 主机复用阴性对照）

- **code**: ct-有证书但多源无历史解析-判定内部-docker-预发布反代命名空间-mnemonic-覆盖窗对照-主机复用阴性
- **kind**: template
- **category**: recon
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 对 fanatical.com 的 prelive-proxy.api/prelive-proxy.frontend/prelive.nginx/docker-nginx 实测：crt.sh 显示 2018-06-08~06-14 四张 LE X3 单域名证书（无 IP SAN）；Mnemonic（同源 fanatical.com 有 22 条、最早 2017-04，证明覆盖 2018）对四名字均 object.not.found；OTX hostname passive_dns/http_scans/geo 全空、Wayback CDX 空、ip138 无历史、rapiddns 域级 101 行无命中；18 个变体当前全 NODATA（zzz-nonexist 同空对照）；对 2018 CF IP 104.20.96.71/97.71、2017 IP 160.153.16.36、Heroku GA、AWS 源站实测：CF 1016 与 zone 内随机名同构、Heroku No such app、107.21.85.212 的 302 与随机 Host 同构（nginx 默认 server+泛证书）；绝对 URI/CONNECT 均非代理。结论：内部 docker 预发布反代命名空间，从未有公网 A 记录。
- **path**: pocs/ct-有证书但多源无历史解析-判定内部-docker-预发布反代命名空间-mnemonic-覆盖窗对照-主机复用阴性/poc.md
- **tags**: crt.sh,证书透明,被动DNS,Mnemonic,DNS-01,docker预发布,主机复用,阴性情报,覆盖窗对照
- **created_at**: 2026-11-11T20:17:42.430Z
- **engine**: prelive.nginx.fanatical.com
- **found_by**: recon

## 描述

当 CT（crt.sh）出现某名字的证书、但当前 DNS NODATA 时，判断它是"历史上真实对外解析过的旧基础设施（值得复原历史 IP 实测）"还是"从未公网解析的内部环境主机名（自动关闭该面）"。核心判据：①公开 CA 单域名证书+无 IP SAN+同批同日批量签发 ⇒ 自建 docker 预发布环境特征；②必须做被动 DNS 源的【覆盖时间窗对照】——Mnemonic 对根域有 2017 年起的记录而目标名为 object.not.found，才证明"空"有证明力；③主机复用必须做随机 Host/随机 SNI 阴性对照，否则 nginx 默认 server + 泛证书会把任意 Host 的 302 误判成"专属配置"。

## 用法

```
1) crt.sh 拉证书历史（看 not_before / issuer / 是否 IP SAN / 同批名字）：
curl -s "https://crt.sh/?q=%25.<root>&output=json" | jq -r '.[]|[.not_before,.issuer_name,.common_name,.name_value]|@tsv'
curl -s "https://crt.sh/?q=<fqdn>&output=json"
2) 被动 DNS（至少 3 源，含覆盖窗对照）：
curl -s "https://api.mnemonic.no/pdns/v3/<fqdn>?limit=100"；curl -s "https://api.mnemonic.no/pdns/v3/<root>?limit=1000"  # 对照根域最早时间戳
curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/<fqdn>/{passive_dns,http_scans,geo}"
curl -s "http://web.archive.org/cdx/search/cdx?url=<fqdn>&matchType=host&output=json"
curl -s "https://site.ip138.com/<fqdn>/"；curl -s "https://rapiddns.io/subdomain/<root>?full=1"
3) 历史/已知 IP 实测（务必加阴性对照）：
curl -sk --noproxy '*' --resolve "<fqdn>:443:<ip>" "https://<fqdn>/" -D -
curl -s --noproxy '*' --resolve "<fqdn>:80:<ip>" "http://<fqdn>/"
# 必做对照：同一 IP + 随机 Host/随机 SNI（zzz-random-nonexist.invalid），若响应同构=默认 server 非专属
# CF 1016/530 与 zone 内随机名同构 ⇒ CF 无该记录；Heroku 404 No such app ⇒ 无 app
4) 代理语义：原始 socket 发 GET http://example.com/ HTTP/1.1 与 CONNECT example.com:443；若 example.com 本身在 CF 上，其 200 是正常 Host 路由，必须以非 CF 域（google.com=409、iana.org=530）与随机 Host 作对照才能排除开放代理误判。
```

## 正文

```
判定流程（本次 fanatical 实测）：
A. CT：crt.sh 显示 2018-06-08T09:20:40 prelive-proxy.frontend、09:21:57 prelive.nginx、23:23:19 docker-nginx、2018-06-14 prelive-proxy.api，均 Let's Encrypt X3、单域名、无 IP SAN ⇒ 2018-06 docker 预发布环境批量 certbot 特征。
B. 覆盖窗对照（关键）：Mnemonic 对 fanatical.com 有 22 条、最早 2017-04-15（160.153.16.36）、2017-10 起为 CF 104.20.96.71/97.71 ⇒ 源覆盖 2018 年；对三名字均 count=0 object.not.found ⇒ 空结果有证明力（不同于"假零"）。
C. 其它源：OTX passive_dns/http_scans/geo 空、Wayback CDX []、ip138 无历史行、rapiddns 101 行无命中；urlscan 匿名仅 30 天窗口（不可当证明）。
D. 当前 DNS：18 个变体全 NODATA，zzz-nonexist 同 NODATA（无通配）、www 有 A（对照）。
E. 主机复用：2018 CF IP 全 000；2017 IP 160.153.16.36 为 GoDaddy 共享托管（反查 1000 无关站）且 000；当前 CF 边缘 530/17 error 1016 与 zzz-nonexist 同构；Heroku GA 404/548 No such app；107.21.85.212（nginx/1.9.10）对三名字与随机 Host 同为 302 /login?next= + 对任意 SNI 返 *.fanatical.com 泛证书（默认 server，非复用）。
F. 代理语义：绝对 URI 301/404；CONNECT 400；CF IP 对 example.com 200 因其 NS 是 CF（非开放代理，用 google=409/iana=530/随机=409 对照）。
结论模板：公开 CA 单域名+无 IP SAN + 同批同日 + 多源（含覆盖窗对照）无历史解析 + 已知 IP 无专属路由（随机 Host 同构） ⇒ 内部命名空间，DNS-01 验证签发，从未公网解析，关闭该面；反向（任一源有历史 A/或某 IP 对专属 Host 响应异于随机对照）⇒ 继续做存活性与代理语义实测。
```
