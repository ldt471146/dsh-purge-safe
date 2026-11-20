判定流程（本次 fanatical 实测）：
A. CT：crt.sh 显示 2018-06-08T09:20:40 prelive-proxy.frontend、09:21:57 prelive.nginx、23:23:19 docker-nginx、2018-06-14 prelive-proxy.api，均 Let's Encrypt X3、单域名、无 IP SAN ⇒ 2018-06 docker 预发布环境批量 certbot 特征。
B. 覆盖窗对照（关键）：Mnemonic 对 fanatical.com 有 22 条、最早 2017-04-15（160.153.16.36）、2017-10 起为 CF 104.20.96.71/97.71 ⇒ 源覆盖 2018 年；对三名字均 count=0 object.not.found ⇒ 空结果有证明力（不同于"假零"）。
C. 其它源：OTX passive_dns/http_scans/geo 空、Wayback CDX []、ip138 无历史行、rapiddns 101 行无命中；urlscan 匿名仅 30 天窗口（不可当证明）。
D. 当前 DNS：18 个变体全 NODATA，zzz-nonexist 同 NODATA（无通配）、www 有 A（对照）。
E. 主机复用：2018 CF IP 全 000；2017 IP 160.153.16.36 为 GoDaddy 共享托管（反查 1000 无关站）且 000；当前 CF 边缘 530/17 error 1016 与 zzz-nonexist 同构；Heroku GA 404/548 No such app；107.21.85.212（nginx/1.9.10）对三名字与随机 Host 同为 302 /login?next= + 对任意 SNI 返 *.fanatical.com 泛证书（默认 server，非复用）。
F. 代理语义：绝对 URI 301/404；CONNECT 400；CF IP 对 example.com 200 因其 NS 是 CF（非开放代理，用 google=409/iana=530/随机=409 对照）。
结论模板：公开 CA 单域名+无 IP SAN + 同批同日 + 多源（含覆盖窗对照）无历史解析 + 已知 IP 无专属路由（随机 Host 同构） ⇒ 内部命名空间，DNS-01 验证签发，从未公网解析，关闭该面；反向（任一源有历史 A/或某 IP 对专属 Host 响应异于随机对照）⇒ 继续做存活性与代理语义实测。