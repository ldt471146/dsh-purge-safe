# TLS 证书 SAN 反查域名（纯 IP 段挖真实业务域名 + vhost 路由）

- **code**: tls-cert-san-domain-harvest
- **kind**: script
- **category**: info-leak
- **component**: 通用手法 / TLS 证书
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.38/24 实测验证：从纯 IP 扫描结果出发，一次采集挖出 20 个真实域名（aimanplay.cn / 251w.com / 2vshop.com / 56meme.com / harness.nanlat.com / amazoney.com / files.cjngames.cn / 755500.xyz / cha.6-7.cc / wenjie.us / download.hdljdylzsx.top / example.com 等）。其中用域名 example.com 加 Host 头访问 203.0.113.40:443，命中「芋道管理系统」后台（默认 IP 访问只返回 MinIO 的 AccessDenied XML），vhost 路由效果得到验证。另发现 .33:8443 与 .140:8443 使用 Apple 官方证书做域名前置伪装。
- **path**: pocs/tls-cert-san-domain-harvest/tls_cert_san_harvest.sh
- **tags**: 信息收集,证书,域名挖掘,vhost,TLS,SAN,纯IP目标
- **created_at**: 2026-10-15T20:45:11.957Z
- **found_by**: vuln-scan

## 描述

在只有 IP、没有域名的目标段上，从 443/8443 等 HTTPS 端口的 TLS 证书 subject CN 与 SAN 字段批量提取真实业务域名，然后用这些域名做 vhost 路由访问同一 IP，常常能命中与该 IP 默认响应完全不同的服务（管理后台、对象存储、API 等）。

## 用法

```
bash tls_cert_san_harvest.sh 203.0.113.38/24 内的 IP 列表
再对提取出的域名执行：curl -sk -H "Host: <domain>" https://<IP>/
关键：openssl s_client 必须带 -servername <IP>，否则很多 nginx 不下发证书。
```

## 正文

```
#!/bin/bash
# TLS 证书 SAN 反查域名 —— 纯 IP 目标段挖真实域名的最高效手法
#
# 场景：扫描只拿到 IP，不知道域名（无 PTR、无 DNS 记录可用）
# 原理：443/8443 等 HTTPS 端口握手时会下发服务器证书，证书的 subject CN 与 SAN 字段
#       包含该服务真实绑定的全部域名。用 SNI 指向 IP 本身也能触发证书下发。
# 收益：实测在纯 IP 段中一次挖出 20+ 个真实业务域名（含管理后台、对象存储、支付等子域），
#       并可用挖到的域名做 vhost 路由（同一 IP 上多个服务靠 Host 头区分）。

CIDR_IPS="$@"          # 传入 IP 列表或从 nmap 结果提取
PORTS="443 8443 9443 6443 10443"

for ip in $CIDR_IPS; do
  for port in $PORTS; do
    out=$(echo | timeout 6 openssl s_client -connect "$ip:$port" -servername "$ip" 2>/dev/null \
          | openssl x509 -noout -subject -issuer -ext subjectAltName 2>/dev/null | tr '\n' ' ')
    if [ -n "$out" ]; then
      cn=$(echo "$out" | grep -oP 'CN=\K[^,]+' | head -1)
      sans=$(echo "$out" | grep -oP 'DNS:\K[^, ]+' | tr '\n' ',' | sed 's/,$//')
      echo "$ip:$port | CN=$cn | SAN=$sans"
    fi
  done
done

# 拿到域名后关键一步：用域名重新访问同一 IP（vhost 路由），
# 常见会命中完全不同的服务：
#   curl -sk -H "Host: <domain>" https://IP/
#   curl -sk -H "Host: <domain>" https://IP:8443/
#
# 进阶：把域名喂给 crt.sh 继续扩面
#   curl -s "https://crt.sh/?q=%25.<domain>&output=json" | jq -r '.[].name_value' | sort -u

```
