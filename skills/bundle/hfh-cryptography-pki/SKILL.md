---
name: hfh-cryptography-pki
description: 网络安全知识库「密码学与 PKI」分类技能包，源自 Hi-FullHouse/CyberSecurity-Skills 上游 35-密码学与PKI-CryptographyPKI。覆盖 TLS/SSL 安全配置与审计（协议版本与密码套件安全评级、PFS 与 SWEET32 风险、Nginx/Apache 加固配置模板、HSTS 与 OCSP Stapling、testssl.sh 与 nmap ssl-enum-ciphers 审计、证书到期自动巡检、certbot 自动化部署与证书链验证）、PKI 架构与证书管理（OpenSSL 三级 CA 搭建与 SAN/KeyUsage 扩展、证书生命周期与吊销 CRL/OCSP、Vault PKI 与 CFSSL 自动化签发、mTLS 配置、PKI 健康检查评分）以及加密算法与密钥管理（对称/非对称/哈希算法对比与选型、OpenSSL/GPG/age 加解密与 Ed25519 签名、密钥分类 C0-C3 与轮换销毁审计、SoftHSM 与 AWS/Azure/GCP KMS 操作、密钥管理最佳实践），含 4 份中文原文 references。
---

# 密码学与 PKI（Cryptography & PKI）

本技能用于**加密配置审计与信任体系治理**：先审 TLS 部署（版本/套件/证书链/OCSP），再管 PKI（CA 层级、签发、吊销、健康），最后落到密钥生命周期（生成、存储、轮换、销毁）。

选型基线固定：传输用 **TLS 1.3 / 1.2 + AES-256-GCM 或 ChaCha20-Poly1305 + ECDHE**；数据加密用 **AES-256-GCM（AEAD）**；签名用 **Ed25519 / ECDSA-P256**；密码存储用 **Argon2id / bcrypt**；密钥交换用 **X25519**；磁盘加密用 **AES-256-XTS**。关键工具：OpenSSL、testssl.sh、certbot/acme.sh、CFSSL、EasyRSA、Vault PKI、HashiCorp Vault、GPG、age、SoftHSM、p11tool、AWS/Azure/GCP KMS。

## 一、TLS/SSL 安全配置与审计

### 1. 协议版本与密码套件评级

| 版本 | 安全 | 年份 | 说明 |
|:---|:---:|:---:|:---|
| TLS 1.3 | ✅ | 2018 | 推荐 — 最新安全标准 |
| TLS 1.2 | ✅ | 2008 | 可接受 — 需禁用弱密码套件 |
| TLS 1.1 | ❌ | 2006 | 弃用 — 易受 BEAST 攻击 |
| TLS 1.0 | ❌ | 1999 | 弃用 — 存在多个已知漏洞 |
| SSL 3.0 | ❌ | 1996 | 弃用 — POODLE |
| SSL 2.0 / 1.0 | ❌ | 1995/1994 | 弃用 |

| 密码套件 | 评级 | 说明 |
|:---|:---|:---|
| TLS_AES_256_GCM_SHA384 | secure | TLS 1.3 默认 |
| TLS_CHACHA20_POLY1305_SHA256 | secure | 移动设备推荐 |
| TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | secure | 有 PFS |
| TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | secure | 有 PFS |
| TLS_RSA_WITH_AES_256_CBC_SHA256 | weak | 无 PFS |
| TLS_RSA_WITH_AES_128_CBC_SHA | weak | 无 PFS |
| TLS_RSA_WITH_3DES_EDE_CBC_SHA | insecure | SWEET32 |
| TLS_RSA_WITH_RC4_128_SHA | insecure | RC4 已破解 |

推荐配置要点：`min_tls_version=1.2`、`preferred=1.3`、套件取 TLS 1.3 三条 + ECDHE-RSA-AES256/128-GCM；开关项为禁用 SSLv2/v3 与 TLS 1.0/1.1、启用 HSTS、启用 OCSP Stapling、禁用压缩、确保前向保密。

评级算法口径：含 1.0/1.1 扣 30 分，含 SSL 3.0/2.0 扣 50 分，每个弱套件（3DES/RC4/DES）扣 20 分，无 PFS 扣 20 分，支持 TLS 1.3 加 10 分，结果截断到 0–100。

### 2. 配置实践

```nginx
server {
    listen 443 ssl http2;
    server_name api.company.com;

    ssl_certificate /etc/ssl/certs/company.crt;
    ssl_certificate_key /etc/ssl/private/company.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 1.1.1.1;

    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;

    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    ssl_dhparam /etc/ssl/certs/dhparam.pem;
}
```

```bash
sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
```

```apache
<VirtualHost *:443>
    ServerName api.company.com
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/company.crt
    SSLCertificateKeyFile /etc/ssl/private/company.key

    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    SSLHonorCipherOrder off

    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

    SSLUseStapling on
    SSLStaplingResponderTimeout 5
    SSLStaplingReturnResponderErrors off
    SSLStaplingCache shmcb:/var/run/ocsp(128000)
</VirtualHost>
```

### 3. 安全审计

```bash
git clone https://github.com/drwetter/testssl.sh.git && cd testssl.sh
./testssl.sh --quick api.company.com:443
./testssl.sh --full api.company.com:443
./testssl.sh --heartbleed api.company.com:443
./testssl.sh --poodle api.company.com:443
./testssl.sh --breach api.company.com:443
./testssl.sh --jsonfile tls_report.json api.company.com:443
./testssl.sh --certificate api.company.com:443
./testssl.sh --cipher-per-proto api.company.com:443

nmap --script ssl-enum-ciphers -p 443 api.company.com
nmap --script ssl-cert -p 443 api.company.com
nmap --script ssl-heartbleed -p 443 api.company.com
nmap --script ssl-dh-params -p 443 api.company.com

openssl s_client -connect api.company.com:443 -servername api.company.com 2>/dev/null | openssl x509 -text
openssl s_client -connect api.company.com:443 -tls1_3 2>/dev/null | head -5
openssl s_client -connect api.company.com:443 -tls1_2 2>/dev/null | head -5

openssl ocsp -issuer ca.crt -cert server.crt -url http://ocsp.company.com -text
```

```python
import subprocess
from datetime import datetime

class TLSCertChecker:
    def __init__(self, domains): self.domains = domains

    def check_cert_expiry(self, domain, port=443):
        cmd = (f"openssl s_client -connect {domain}:{port} -servername {domain} 2>/dev/null "
               f"| openssl x509 -noout -dates")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            return {"domain": domain, "error": "Connection failed"}

        dates = {}
        for line in result.stdout.strip().split("\n"):
            if "notBefore" in line:  dates["not_before"] = line.split("=")[1]
            elif "notAfter" in line: dates["not_after"] = line.split("=")[1]

        if "not_after" in dates:
            expiry = datetime.strptime(dates["not_after"], "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.now()).days
            return {"domain": domain, "expires": dates["not_after"], "days_left": days_left,
                    "status": "expired" if days_left <= 0 else
                              "critical" if days_left <= 14 else
                              "warning" if days_left <= 30 else "ok",
                    "renewal_recommended": days_left <= 30}
        return {"domain": domain, "error": "Could not parse certificate"}

    def check_all(self):
        return [self.check_cert_expiry(d) for d in self.domains]
```

### 4. 证书部署自动化

```bash
sudo apt-get install certbot python3-certbot-nginx
sudo certbot --nginx -d api.company.com -d www.company.com

sudo certbot certonly --manual --preferred-challenges dns -d *.company.com -d company.com
sudo certbot renew --dry-run
echo "0 3 * * * /usr/bin/certbot renew --quiet --post-hook 'systemctl reload nginx'" | sudo crontab -

# 证书链顺序: 服务器证书 → 中间证书 → 根证书
cat server.crt intermediate.crt > fullchain.crt
openssl verify -CAfile ca.crt -untrusted intermediate.crt server.crt

openssl pkcs12 -export -out certificate.pfx -inkey private.key -in certificate.crt -certfile ca.crt
openssl x509 -in certificate.crt -outform der -out certificate.der
openssl x509 -in certificate.crt -text -noout | grep -E "Subject:|Issuer:|Not Before|Not After|DNS:"
```

## 二、PKI 架构与证书安全管理

### 1. 私有 CA 三级搭建

```bash
# 1. Root CA（10 年）
openssl genrsa -aes256 -out root_ca.key 4096
openssl req -x509 -new -nodes -key root_ca.key -sha256 -days 3650 \
  -out root_ca.crt \
  -subj "/C=CN/O=Company Root CA/CN=Company Root Certificate Authority"

# 2. Intermediate CA（5 年）
openssl genrsa -aes256 -out intermediate_ca.key 4096
openssl req -new -key intermediate_ca.key -out intermediate_ca.csr \
  -subj "/C=CN/O=Company PKI/CN=Company Intermediate CA"
openssl x509 -req -in intermediate_ca.csr \
  -CA root_ca.crt -CAkey root_ca.key -CAcreateserial \
  -out intermediate_ca.crt -days 1825 -sha256 -extfile intermediate.ext

# 3. 服务器证书（1 年）
openssl genrsa -out server.company.com.key 2048
openssl req -new -key server.company.com.key -out server.company.com.csr \
  -subj "/C=CN/O=Company/CN=server.company.com"
```

```
# san.ext
subjectAltName=DNS:server.company.com,DNS:api.company.com
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
```

```bash
openssl x509 -req -in server.company.com.csr \
  -CA intermediate_ca.crt -CAkey intermediate_ca.key -CAcreateserial \
  -out server.company.com.crt -days 365 -sha256 -extfile san.ext

cat server.company.com.crt intermediate_ca.crt > fullchain.crt
openssl verify -CAfile root_ca.crt -untrusted intermediate_ca.crt server.company.com.crt
```

### 2. 证书生命周期管理

```python
from datetime import datetime, timedelta

class CertificateLifecycle:
    def __init__(self):
        self.certificates = {}; self.audit_log = []

    def issue_certificate(self, cn, san_list=None, validity_days=365, cert_type="server"):
        cert_id = f"CERT-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        cert = {"id": cert_id, "common_name": cn, "san": san_list or [cn],
                "type": cert_type, "status": "active",
                "issued": datetime.now().isoformat(),
                "expires": (datetime.now() + timedelta(days=validity_days)).isoformat(),
                "issuer": "Company Intermediate CA", "revoked": False}
        self.certificates[cert_id] = cert
        self._log("ISSUE", cert_id, f"Issued {cert_type} cert for {cn}")
        return cert

    def revoke_certificate(self, cert_id, reason="unspecified"):
        self.certificates[cert_id].update({
            "revoked": True, "revoked_at": datetime.now().isoformat(),
            "revocation_reason": reason})
        self._log("REVOKE", cert_id, f"Revoked: {reason}")

    def check_expiry_warnings(self):
        warnings = []; now = datetime.now()
        for cert_id, cert in self.certificates.items():
            if cert["status"] != "active" or cert.get("revoked"): continue
            days_left = (datetime.fromisoformat(cert["expires"]) - now).days
            if days_left <= 30:
                warnings.append({"cert_id": cert_id, "cn": cert["common_name"],
                                 "days_left": days_left,
                                 "action": "renew_now" if days_left <= 14 else "renew_soon"})
        return warnings

    def get_certificate_summary(self):
        vals = self.certificates.values()
        return {"total": len(self.certificates),
                "active": sum(1 for c in vals if c["status"] == "active" and not c.get("revoked")),
                "expired": sum(1 for c in vals if datetime.fromisoformat(c["expires"]) < datetime.now()),
                "revoked": sum(1 for c in vals if c.get("revoked")),
                "expiring_soon": len(self.check_expiry_warnings())}
```

### 3. 撤销与 OCSP

```bash
# CRL
openssl ca -gencrl -out crl.pem -config openssl.cnf
openssl crl -in crl.pem -text -noout
# default_crl_days = 30，需定期更新并分发

# OCSP 响应服务器
openssl ocsp -index index.txt -CA root_ca.crt \
  -rsigner ocsp_response.crt -rkey ocsp_response.key -port 8080 -text

# 客户端查询
openssl ocsp -issuer intermediate_ca.crt -cert server.crt \
  -url http://ocsp.company.com:8080 -CAfile root_ca.crt

# OCSP Stapling 配置（Nginx）
# ssl_stapling on;
# ssl_stapling_verify on;
# resolver 8.8.8.8 1.1.1.1 valid=300s;

openssl s_client -connect api.company.com:443 -status -servername api.company.com 2>&1 | grep -A 20 "OCSP response"
```

配置项：`crlDistributionPoints=URI:http://crl.company.com/crl.pem`、`authorityInfoAccess=OCSP;URI:http://ocsp.company.com`。

### 4. 自动化 PKI

```bash
# Vault PKI
vault secrets enable pki
vault secrets enable -path=pki_int pki

vault write pki/root/generate/internal common_name="Company Root CA" ttl=87600h
vault write pki_int/intermediate/generate/internal common_name="Company Intermediate CA"
vault write pki/root/sign-intermediate csr=@pki_int.csr ttl=43800h
vault write pki_int/intermediate/set-signed certificate=@signed.crt

vault write pki_int/roles/webserver \
  allowed_domains="company.com" allow_subdomains=true \
  max_ttl=720h key_type=rsa key_bits=2048

vault write pki_int/issue/webserver \
  common_name="api.company.com" alt_names="admin.company.com" ttl=168h
```

```bash
# CFSSL
go get github.com/cloudflare/cfssl/cmd/cfssl
go get github.com/cloudflare/cfssl/cmd/cfssljson
cfssl genkey -initca ca-csr.json | cfssljson -bare ca
cfssl gencert -ca ca.pem -ca-key ca-key.pem -config ca-config.json \
  -profile=server server-csr.json | cfssljson -bare server
```

```json
{
  "signing": {
    "default": {"expiry": "8760h"},
    "profiles": {
      "server": {"expiry": "8760h", "usages": ["signing", "key encipherment", "server auth"]},
      "client": {"expiry": "8760h", "usages": ["signing", "key encipherment", "client auth"]},
      "peer":   {"expiry": "8760h", "usages": ["signing", "key encipherment", "server auth", "client auth"]}
    }
  }
}
```

```bash
# mTLS
cfssl gencert -ca ca.pem -ca-key ca-key.pem -config ca-config.json \
  -profile=client client-csr.json | cfssljson -bare client
# Nginx: ssl_client_certificate /etc/ssl/certs/ca.crt; ssl_verify_client on; ssl_verify_depth 2;
```

### 5. PKI 健康检查

```python
class PKIHealthCheck:
    CHECKS = {
        "root_ca": ["密钥未泄露", "私钥加密存储", "离线存储", "有效期 > 5年"],
        "intermediate_ca": ["密钥未泄露", "CRL 定期生成", "OCSP 在线", "有效期 > 1年"],
        "certificate_operations": ["CRL 未过期", "OCSP 响应正常", "证书透明度日志", "密钥长度 ≥ 2048"]
    }
    # 逐项判定 → health_score = 通过项 / 总项 × 100
    # 评分分级: ≥90 A / ≥75 B / 其余 C
```

## 三、加密算法与密钥管理

### 1. 算法选型

| 类别 | 算法 | 密钥/输出 | 安全 | 性能 | 用途与说明 |
|:---|:---|:---:|:---:|:---:|:---|
| 对称 | AES-256-GCM | 256 | 安全 | 快 | 数据加密、TLS；**推荐**（AEAD） |
| 对称 | AES-256-CBC | 256 | 需配 HMAC | 快 | 文件加密；无 HMAC 无法防篡改 |
| 对称 | ChaCha20-Poly1305 | 256 | 安全 | 移动端更优 | 移动设备、TLS |
| 对称 | 3DES | 112 | 不安全 | 慢 | 弃用（SWEET32） |
| 非对称 | RSA-4096 | 4096 | 安全 | 慢 | 签名、密钥交换；兼容性最好 |
| 非对称 | ECDSA-P256 | 256 | 安全 | 快 | 数字签名（推荐） |
| 非对称 | Ed25519 | 256 | 安全 | 非常快 | SSH 密钥、签名（OpenSSH 推荐） |
| 非对称 | ECDH | 256 | 安全 | 快 | 密钥交换（前向安全性） |
| 哈希 | SHA-256 | 256 | 安全 | — | 完整性验证、签名（推荐） |
| 哈希 | SHA-3 | 256 | 安全 | — | 新系统（NIST 最新标准） |
| 哈希 | SHA-1 | 160 | 不安全 | — | 弃用（SHAttered 碰撞） |
| 哈希 | MD5 | 128 | 不安全 | — | 已破解，仅校验用 |

场景推荐：

```
tls               → TLS 1.3 + AES-256-GCM / ChaCha20-Poly1305 + ECDHE
file_encryption   → AES-256-GCM（推荐）或 age
digital_signature → Ed25519（推荐）或 ECDSA-P256
password_storage  → Argon2id（推荐）或 bcrypt/scrypt
key_exchange      → ECDH + Curve25519（X25519）
disk_encryption   → AES-256-XTS（LUKS/BitLocker）
message_integrity → HMAC-SHA256
```

密钥强度等价：128-bit 安全 ≈ AES-128 ≈ RSA-3072 ≈ ECDSA-256；256-bit 安全 ≈ AES-256 ≈ RSA-15360 ≈ ECDSA-512。

### 2. 加解密与签名

```bash
# 对称加密
openssl enc -aes-256-gcm -salt -pbkdf2 -iter 100000 \
  -in secret.txt -out secret.enc -pass pass:"your-password"
openssl enc -d -aes-256-gcm -pbkdf2 -iter 100000 \
  -in secret.enc -out secret.txt -pass pass:"your-password"
openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
  -in secret.txt -out secret.enc -pass pass:"your-password"

# 非对称
openssl genrsa -out private.pem 4096
openssl rsa -pubout -in private.pem -out public.pem
openssl pkeyutl -encrypt -pubin -inkey public.pem -in secret.txt -out secret.enc
openssl pkeyutl -decrypt -inkey private.pem -in secret.enc -out secret.txt

# 签名
openssl dgst -sha256 -sign private.pem -out message.sig message.txt
openssl dgst -sha256 -verify public.pem -signature message.sig message.txt

# Ed25519（现代推荐）
openssl genpkey -algorithm Ed25519 -out ed25519_private.pem
openssl pkey -in ed25519_private.pem -pubout -out ed25519_public.pem

# GPG
gpg --full-generate-key
gpg --armor --export alice@company.com > alice_pubkey.asc
gpg --armor --encrypt --recipient alice@company.com secret.txt
gpg --decrypt secret.txt.asc > secret.txt

# age
age-keygen -o key.txt
age -r age1abc123... -o secret.age secret.txt
age -d -i key.txt -o secret.txt secret.age
```

### 3. 密钥管理

```python
import secrets
from datetime import datetime, timedelta

class KeyManager:
    KEY_CLASSIFICATIONS = {
        "c0": "最高机密 — HSM 保护，永不离开硬件",
        "c1": "机密 — 加密存储，严格访问控制",
        "c2": "内部 — 加密存储",
        "c3": "公开 — 无保护要求"
    }

    def __init__(self):
        self.keys = {}; self.access_log = []

    def generate_key(self, key_type, key_size, purpose, classification="c1", rotation_days=365):
        key_id = f"key-{secrets.token_hex(8)}"
        key_material = secrets.token_bytes(key_size // 8)     # aes / hmac
        self.keys[key_id] = {"metadata": {
            "id": key_id, "type": key_type, "size": key_size, "purpose": purpose,
            "classification": classification,
            "created": datetime.now().isoformat(),
            "expires": (datetime.now() + timedelta(days=rotation_days)).isoformat(),
            "status": "active", "version": 1, "access_count": 0},
            "material": key_material}   # 生产环境应使用 KMS 加密存储
        self._audit("GENERATE", key_id)
        return key_id

    def rotate_key(self, key_id):
        old_meta = self.keys[key_id]["metadata"]
        self.keys[key_id]["metadata"]["status"] = "retired"
        new_key_id = self.generate_key(old_meta["type"], old_meta["size"],
                                       old_meta["purpose"], old_meta["classification"])
        self.keys[new_key_id]["metadata"]["version"] = old_meta["version"] + 1
        self.keys[new_key_id]["metadata"]["predecessor"] = key_id
        self._audit("ROTATE", key_id, note=f"New key: {new_key_id}")
        return new_key_id

    def destroy_key(self, key_id, reason):
        key_len = len(self.keys[key_id]["material"])
        self.keys[key_id]["material"] = bytes(key_len)      # 零化
        self.keys[key_id]["metadata"]["status"] = "destroyed"
        self._audit("DESTROY", key_id, note=reason)

    def _audit(self, action, key_id, user="system", note=""):
        self.access_log.append({"timestamp": datetime.now().isoformat(), "action": action,
                                "key_id": key_id, "user": user, "note": note})
```

### 4. HSM 与云 KMS

```bash
# PKCS#11 / SoftHSM
p11tool --provider /usr/lib/softhsm/libsofthsm2.so \
  --init-token --label "Company HSM" --so-pin "1234" --pin "5678"

p11tool --provider /usr/lib/softhsm/libsofthsm2.so \
  --generate-privkey RSA --bits 2048 --label "server-key" --login --pin "5678"

p11tool --provider /usr/lib/softhsm/libsofthsm2.so --list-all --login --pin "5678"

p11tool --provider /usr/lib/softhsm/libsofthsm2.so \
  --sign --label "server-key" --hash sha256 \
  --in message.txt --out message.sig --login --pin "5678"

# AWS KMS
aws kms create-key --description "Database encryption key" --key-usage ENCRYPT_DECRYPT
aws kms create-alias --alias-name alias/db-key --target-key-id <key-id>
aws kms encrypt --key-id alias/db-key --plaintext fileb://secret.txt \
  --output text --query CiphertextBlob --output-file secret.enc
aws kms decrypt --ciphertext-blob fileb://secret.enc \
  --output text --query Plaintext | base64 --decode > secret.txt
aws kms enable-key-rotation --key-id <key-id>

# Azure Key Vault
az keyvault create --name "company-kv" --resource-group security
az keyvault key create --vault-name "company-kv" --name "db-key" --protection software
az keyvault key encrypt --vault-name "company-kv" --name "db-key" --algorithm RSA-OAEP --value "secret-data"

# GCP Cloud KMS
gcloud kms keyrings create "security-ring" --location "global"
gcloud kms keys create "db-key" --location "global" --keyring "security-ring" --purpose "encryption"
gcloud kms encrypt --location "global" --keyring "security-ring" --key "db-key" \
  --plaintext-file secret.txt --ciphertext-file secret.enc
```

### 5. 密钥管理最佳实践

- **生命周期**：使用 KMS/HSM 生成与存储密钥；密钥永不离开加密边界；定期轮换（建议 1 年）；销毁前先验证不再使用。
- **加密策略**：数据加密用 AES-256-GCM（认证加密）；传输加密用 TLS 1.3；密码存储用 Argon2id/bcrypt；数字签名用 Ed25519/ECDSA。
- **密钥分类**：C0 HSM 保护（CA 根密钥、支付密钥）｜C1 KMS 加密存储（数据库密钥、API 密钥）｜C2 配置加密（服务间通信密钥）｜C3 无保护要求（公钥）。
- **审计要求**：所有密钥操作记录审计日志；密钥访问双人审批；季度审查密钥使用；密钥泄露立即轮换。

## 四、常用工具

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| OpenSSL | 加密与 PKI 工具集 | https://www.openssl.org/ |
| testssl.sh | TLS 安全测试 | https://testssl.sh/ |
| certbot | Let's Encrypt 客户端 | https://certbot.eff.org/ |
| nmap ssl-enum-ciphers | TLS 密码扫描 | https://nmap.org/ |
| SSL Labs | TLS 在线测试 | https://www.ssllabs.com/ssltest/ |
| EasyRSA | 简易 CA 管理 | https://github.com/OpenVPN/easy-rsa |
| CFSSL | CloudFlare PKI 工具 | https://github.com/cloudflare/cfssl |
| Vault PKI | 自动化 PKI 引擎 | https://www.vaultproject.io/docs/secrets/pki |
| EJBCA | 企业 PKI 平台 | https://www.ejbca.org/ |
| HashiCorp Vault | 密钥管理平台 | https://www.vaultproject.io/ |
| GPG | 邮件/文件加密 | https://gnupg.org/ |
| age | 现代文件加密 | https://age-encryption.org/ |
| SoftHSM | 软件 HSM 模拟 | https://github.com/opendnssec/SoftHSMv2 |

## 五、参考资源

- [Mozilla TLS Configuration Generator](https://ssl-config.mozilla.org/)
- [NIST SP 800-52 Rev 2 — TLS Guidelines](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)
- [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [Qualys SSL Labs — SSL/TLS Deployment Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [RFC 5280 — X.509 PKI](https://datatracker.ietf.org/doc/html/rfc5280)
- [RFC 6960 — OCSP](https://datatracker.ietf.org/doc/html/rfc6960)
- [NIST SP 800-57 — Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [NIST SP 800-175B — Cryptographic Standards](https://csrc.nist.gov/publications/detail/sp/800-175b/final)
- [OpenSSL PKI Tutorial](https://pki-tutorial.readthedocs.io/)
- [Vault PKI Documentation](https://developer.hashicorp.com/vault/docs/secrets/pki)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [AWS KMS Best Practices](https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html)
- [NSA CNSA 2.0 — Quantum-Resistant Algorithms](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/NSA_CNSA_2.0_ALGORITHMS_.PDF)

## 六、上游原文（references/）

| 上游文件 | 本包路径 |
|:---|:---|
| `README.md`（模块概述与关键工具） | `references/README.md` |
| `skills/TLS-SSL安全配置与审计-TLSSSLSecurityConfigurationAudit.md` | `references/TLS-SSL安全配置与审计-TLSSSLSecurityConfigurationAudit.md` |
| `skills/PKI架构与证书安全管理-PKIArchitectureCertificateManagement.md` | `references/PKI架构与证书安全管理-PKIArchitectureCertificateManagement.md` |
| `skills/加密算法与密钥管理-EncryptionAlgorithmsKeyManagement.md` | `references/加密算法与密钥管理-EncryptionAlgorithmsKeyManagement.md` |
