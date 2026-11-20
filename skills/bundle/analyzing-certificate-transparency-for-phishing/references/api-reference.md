# API 参考：证书透明度钓鱼检测

## crt.sh API

### 搜索证书
```bash
# JSON 输出
curl "https://crt.sh/?q=%.example.com&output=json"

# 排除已过期证书
curl "https://crt.sh/?q=%.example.com&output=json&exclude=expired"

# 精确匹配
curl "https://crt.sh/?q=example.com&output=json"
```

### 响应字段
| 字段 | 描述 |
|-------|-------------|
| `id` | crt.sh 数据库中的证书 ID |
| `common_name` | 证书通用名称（CN） |
| `name_value` | 所有 SAN（换行分隔） |
| `issuer_name` | 证书颁发机构 |
| `not_before` | 有效期开始时间 |
| `not_after` | 有效期结束时间 |
| `serial_number` | 证书序列号 |

## Certstream - 实时 CT 监控

### Python 客户端
```python
import certstream

def callback(message, context):
    if message["message_type"] == "certificate_update":
        data = message["data"]
        domains = data["leaf_cert"]["all_domains"]
        for domain in domains:
            if "example" in domain:
                print(f"[ALERT] {domain}")

certstream.listen_for_events(callback, url="wss://certstream.calidog.io/")
```

### 消息字段
| 字段 | 路径 |
|-------|------|
| 域名 | `data.leaf_cert.all_domains` |
| 签发机构 | `data.leaf_cert.issuer.O` |
| 主体 | `data.leaf_cert.subject.CN` |
| 指纹 | `data.leaf_cert.fingerprint` |
| 来源 | `data.source.name` |

## CT 日志服务器

| 日志名 | 运营商 | URL |
|-----|----------|-----|
| Argon | Google | `ct.googleapis.com/logs/argon2024` |
| Xenon | Google | `ct.googleapis.com/logs/xenon2024` |
| Nimbus | Cloudflare | `ct.cloudflare.com/logs/nimbus2024` |
| Oak | Let's Encrypt | `oak.ct.letsencrypt.org/2024h1` |
| Yeti | DigiCert | `yeti2024.ct.digicert.com/log` |

## 钓鱼检测技术

### 同形字符 / IDN 攻击
| 原始域名 | 仿冒域名 | 技术手法 |
|----------|-----------|-----------|
| example.com | examp1e.com | 字符替换（l→1） |
| google.com | gооgle.com | 西里尔字母 о (U+043E) |
| paypal.com | paypa1.com | l→1 替换 |
| microsoft.com | mіcrosoft.com | 西里尔字母 і (U+0456) |

### dnstwist 集成
```bash
dnstwist -r -f json example.com   # 生成并解析置换域名
dnstwist -w wordlist.txt example.com  # 基于字典
```

## 证书详情查询
```bash
# 从 crt.sh 获取完整证书
curl "https://crt.sh/?d=<cert_id>"

# OpenSSL 检查
openssl s_client -connect domain.com:443 -servername domain.com </dev/null 2>/dev/null | \
  openssl x509 -noout -text
```

## 可疑指标
| 模式 | 风险级别 |
|---------|-----------|
| 免费 CA + 新域名 + 品牌关键词 | 高 |
| 最近注册域名上的通配符证书 | 高 |
| 轻微域名变体的多个证书 | 中 |
| 模仿品牌的 IDN/punycode 域名 | 高 |
| 与域名注册同日签发的证书 | 中 |
