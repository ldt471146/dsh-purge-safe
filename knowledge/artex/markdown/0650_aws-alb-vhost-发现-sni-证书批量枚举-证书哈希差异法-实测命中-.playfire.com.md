# AWS ALB vhost 发现：SNI 证书批量枚举（证书哈希差异法）实测命中 *.playfire.com

- **code**: aws-alb-vhost-发现-sni-证书批量枚举-证书哈希差异法-实测命中-.playfire.com
- **kind**: script
- **category**: recon
- **component**: AWS ALB
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 在 heimdal-alb（54.243.13.29 / 52.70.110.208）实测：2748 个字典 Host + 54 个其它品牌域名的 SNI 扫描，仅 *.playfire.com 呈现不同证书（CN=*.playfire.com, Amazon RSA 2048 M01, 2026-10-17~2027-05-02, EF85...）；playfire.com/www/api.playfire.com 的公共 DNS A 记录直指这两个 ALB IP（8.8.8.8/1.1.1.1 一致），HTTP(S) 全路径/方法仍统一 404|0|awselb 空体。
- **path**: pocs/aws-alb-vhost-发现-sni-证书批量枚举-证书哈希差异法-实测命中-.playfire.com/sni_sweep.py
- **tags**: aws,alb,vhost,sni,tls-cert,recon,subdomain-discovery
- **created_at**: 2026-11-11T18:41:11.336Z
- **engine**: 54.243.13.29 (heimdal-alb-11a7nap6cmt6p-1337146968.us-east-1.elb.amazonaws.com)

## 描述

原理：AWS ALB 的 HTTPS listener 按 SNI 从证书列表选择证书（wildcard 匹配单个标签）。以随机不存在名字的证书哈希为基线，对候选 Host 名逐个做 TLS 握手并比对证书 sha256，出现不同哈希即证明该名字（或其 wildcard 父域）被配置在该 ALB 的证书列表；这是在不发 HTTP 请求、不依赖 DNS 的情况下发现未登记 vhost/品牌域的手段。拿到候选后再用 Host/SNI 双置位发 HTTP 请求判定是否真有 listener 规则与后端。

## 用法

```
python3 sni_sweep.py 54.243.13.29 hosts.txt（并发 32，每 host 一次 TLS 握手，约 100-300 次/秒）；输出 BASELINE 与所有 DIFF host。实测：2748+3539 个候选 SNI 中仅 playfire.com / www.playfire.com / api.playfire.com 返回 CN=*.playfire.com（sha256 EF852C90...9C31），其余（含 china/capsule/gmgfarm/随机）全部返回默认 CN=*.greenmangaming.com（C109B4EC...DFE6）；配合 dig A playfire.com → 54.243.13.29/52.70.110.208 坐实品牌域绑定，但 HTTP 全路径仍 404 awselb 空体（证书级命中、规则级阴性）。
```

## 正文

```
#!/usr/bin/env python3
# AWS ALB vhost discovery via SNI certificate sweep
# 用法: python3 sni_sweep.py <ALB_IP> hosts.txt
# 对每个候选 SNI 完成 TLS 握手并取服务器证书 sha256，与随机 SNI 基线对比；
# 证书哈希不同 => 该名字(含 wildcard 匹配)在 ALB listener 证书列表中被配置。
import ssl, socket, hashlib, sys, concurrent.futures

IP = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
HOSTFILE = sys.argv[2] if len(sys.argv) > 2 else "hosts.txt"
BASELINE_SNI = "zzrandom9f2a.invalid"

def probe(host):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((IP, 443), timeout=6) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                return host, hashlib.sha256(ss.getpeercert(binary_form=True)).hexdigest()
    except Exception as e:
        return host, "ERR:" + type(e).__name__ + ":" + str(e)[:60]

hosts = sorted({l.strip() for l in open(HOSTFILE) if l.strip()})
base = probe(BASELINE_SNI)
print("BASELINE", base[1], flush=True)
with concurrent.futures.ThreadPoolExecutor(max_workers=32) as ex:
    for host, fp in ex.map(probe, hosts):
        if fp != base[1]:
            print("DIFF", host, fp)
```
