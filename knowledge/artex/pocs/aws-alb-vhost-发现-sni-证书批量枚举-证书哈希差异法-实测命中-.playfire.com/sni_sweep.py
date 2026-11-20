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