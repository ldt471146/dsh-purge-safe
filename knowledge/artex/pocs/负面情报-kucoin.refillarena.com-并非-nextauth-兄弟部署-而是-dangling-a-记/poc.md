## 判据（30 秒否证）
1) `nslookup kucoin.refillarena.com 8.8.8.8` → 209.38.186.173
2) `curl -k -D- -o /dev/null https://kucoin.refillarena.com/` → 301 Location: https://meqqusaalik.gl/kl-gl/gl/
3) `echo | openssl s_client -connect 209.38.186.173:443 -servername kucoin.refillarena.com 2>/dev/null | openssl x509 -noout -subject -ext subjectAltName` → subject=CN=meqqusaalik.gl，SAN 仅 meqqusaalik.gl / www.meqqusaalik.gl / meqq-new.baernholdt.dev
4) `curl -k https://kucoin.refillarena.com/api/auth/providers` → 404（nginx/WP 404 页）；`/wp-json/` → 200 且 name=Meqqusaalik、url=https://meqqusaalik.gl
→ 该子域不是 Next.js/NextAuth，无 session JWE 签发面，跨部署 secret 互通无从测试。

## 历史 / 定性
crt.sh: kucoin.refillarena.com 2025-07-16 签发 LE E5 证书（2025-10-14 到期），同批 *.refillarena.com 覆盖 www.kucoin.refillarena.com → 当时由 refillarena 侧控制；此后未续签，A 记录指向的 IP 现由第三方 meqqusaalik.gl 的 WordPress/WooCommerce 源站占用（DigitalOcean 旧 IP 回收复用），构成 dangling A record / 子域内容失控。

## 影响与限制（本目标实测）
- 第三方可在 kucoin.refillarena.com 返回任意页面（/wp-login.php 200），可做钓鱼；但 TLS 证书不匹配，浏览器会告警。
- 主站会话/CSRF 为 __Host- 前缀（__Host-next-auth.csrf-token），子域无法覆盖主站 session；仅 __Secure-next-auth.callback-url 属 __Secure- 可被覆盖（影响仅登录后跳转且 NextAuth 同源校验），对打后台价值低。
- 该主机属边界外第三方资产，未对其做漏洞测试。