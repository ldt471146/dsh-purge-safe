# 开放 HTTP CONNECT 代理的 fake-200 / TLS MITM 识破判据（以真实证书+TEST-NET 对照为准）

- **code**: def-real_proxy-proxy-ctrl-3.8.196.174-443-dev.shopto.ne
- **kind**: script
- **category**: methodology
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 在 shopto.net 任务实测：134.209.29.120:3128 / 139.59.1.14:3128 对 CONNECT 3.8.196.174:443 回 200 但给出 CN=* / issuer "O=Example Inc., CN=Example Inc. CA" 的自签 MITM 证书并回 403 Forbidden；165.154.7.156:8888 对 TEST-NET 192.0.2.1:443 也回 CONNECT 200（无脑假 200）；而 149.86.142.224:8080、160.19.41.52:80 对同一对照站点给出真实 CN=dev.shopto.net / Let's Encrypt 证书后再判目标（159.253.215.128-140 全超时）。另 socks5 里 98.191.0.47:4145 也返回 "None, LLC" MITM 证书。
- **tags**: proxy,connect,tls,mitm,recon,fake-200
- **created_at**: 2026-11-11T17:17:40.739Z
- **engine**: 159.253.215.128

## 描述

判据三步：①CONNECT 对照站点真实域名，TLS 拿 binary DER 证书用 openssl x509 看 subject/issuer；②对 TEST-NET 192.0.2.1:443 发 CONNECT，回 200 的代理直接丢弃；③通过校验的代理再测目标，目标侧失败才可归因于目标。配套脚本 pattern 见 i1427/check_proxy.py、i1554/lib1554.py。

## 用法

```
python3 lib1554.py 里的 tunnel()/http_via()；校验：tunnel(proxy,'3.8.196.174',443) 后 ssl.wrap_socket(server_hostname='dev.shopto.net')，DER 证书 openssl x509 -noout -subject -issuer；对照组 tunnel(proxy,'192.0.2.1',443) 必须失败。
```
