---
name: hfh-data-security-privacy
description: 网络安全知识库「数据安全与隐私」分类技能包，源自 Hi-FullHouse/CyberSecurity-Skills 上游 22-数据安全与隐私-DataSecurityPrivacy。覆盖数据分类与分级保护（四级分类体系与等保 2.0 分级、Purview/Varonis 自动化发现、中国身份证手机号信用卡正则、S3/AIP/Atlas 分级标记、生命周期与安全删除）、DLP 数据防泄漏（Zeek/nDPI 网络 DLP、USB/剪贴板/打印终端监控、共享盘敏感数据扫描、Microsoft/Symantec 策略配置、压缩/隐写/Base64 绕过检测、AWS Macie 与 GCP DLP 云侧）、数据脱敏与匿名化（静态/动态脱敏 SQL 实现、SQL Server DDM 与 Oracle DBMS_REDACT、k-匿名与泛化分桶、Laplace 差分隐私与隐私预算组合、PostgreSQL Anonymizer）、GDPR 与个保法合规评估（ROPA 记录生成、DSAR 数据主体权利响应与 15 天/30 天时限、跨境传输五条合规路径、DPIA 模板、Cookie 与隐私政策自动审计、合规差距矩阵）、数据库安全与加密（最小权限与 SSL/锁定策略、行级安全、TDE 透明加密、pgcrypto 与 AES 列加密、pgAudit 审计、MySQL/PostgreSQL 加固基线、加密备份）与隐私影响评估 PIA/DPIA（触发条件判定、六节报告结构、风险矩阵评分与残余风险、Privacy by Design 审计清单、DPIA 文档模板），含 7 份中文原文 references。
---

# 数据安全与隐私保护（Data Security & Privacy）
本技能用于**数据安全治理与隐私合规**评估：先从「数据在哪、什么级别」开始（分类分级），再看「怎么流出去、有没有拦住」（DLP），然后处理「非生产环境与共享场景如何降险」（脱敏匿名化），最后落到「法规要求是否满足」（GDPR/PIPL 合规 + DPIA/PIA）与「存储层是否硬」（数据库加密审计）。

参考标准统一：**ISO 27001 / ISO 27701、等级保护 2.0、GDPR、中国《个人信息保护法》PIPL、NIST Privacy Framework、NIST SP 800-60/188、PCI DSS**。关键工具：Microsoft Purview、Varonis、BigID、Apache Atlas、Zeek、nDPI、AWS Macie、GCP DLP、ARX、PostgreSQL Anonymizer、HashiCorp Vault、pgAudit、CNIL PIA Tool、OneTrust。

## 一、数据分类与分级保护
### 1. 分类框架
```
# 典型四级分类体系
Level 1 - 公开 (Public):     对外宣传资料、公开文档
Level 2 - 内部 (Internal):   内部邮件、制度文档、非敏感运营数据
Level 3 - 敏感 (Confidential): 客户信息、财务数据、业务策略
Level 4 - 绝密 (Restricted):  商业秘密、核心算法、用户隐私数据

# 等级保护2.0 数据分级
一级 - 一般数据：泄露不损害公共利益
二级 - 重要数据：泄露损害公共利益
三级 - 核心数据：泄露严重损害国家安全
```

### 2. 自动化发现与分类
```powershell
New-DlpSensitiveInformationType -Name "CreditCard" -Description "Credit Card Number"
New-DlpComplianceRule -Name "CCN Detection" -ContentContainsSensitiveInformation @{Name="CreditCard"; minCount="1"; maxCount="5"}
Get-Content "\\server\share" | Select-String -Pattern "\d{4}-\d{4}-\d{4}-\d{4}" -SimpleMatch
```

```python
import re, os

patterns = {
    'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
    'email':       r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'phone_cn':    r'1[3-9]\d{9}',
    'id_card_cn':  r'\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b'
}

for root, dirs, files in os.walk('/data'):
    for file in files:
        path = os.path.join(root, file)
            try:
            with open(path, 'r', errors='ignore') as f:
                content = f.read()
                for name, pattern in patterns.items():
                    if re.search(pattern, content):
                        print(f"[{name}] {path}")
        except:
            pass
```

### 3. 分级标记与标签管理
```bash
aws s3api put-object-tagging --bucket my-bucket --key data.csv \
  --tagging 'TagSet=[{Key=Classification,Value=Confidential},{Key=Retention,Value=7Y}]'
```

```powershell
Set-AIPFileLabel -Path "C:\data\report.docx" -LabelID "confidential-label-id" -JustificationMessage "Data classification audit"
```

```sql
COMMENT ON COLUMN users.phone IS 'ENCRYPTED:LEVEL3:PII'; ; COMMENT ON COLUMN users.email IS 'MASKED:LEVEL2:PII';
```

```bash
curl -u admin:admin -X POST -H "Content-Type: application/json" \
  -d '{"classification":"PII","entityGuid":"guid-xxxx"}' \
  http://atlas:21000/api/atlas/v2/entity/guid-xxxx/classifications
```

### 4. 生命周期与安全删除
```bash
fsutil behavior set disablelastaccess 1     # Windows 禁用最后访问时间 ; chattr +a sensitive_data.csv                # Linux 不可变（防删除）
cipher /w:C:\data\                          # Windows 覆盖删除 ; shred -vfz -n 7 sensitive_data.csv          # Linux 安全删除
```

```sql
-- MySQL 脱敏导出 ; SELECT CONCAT(LEFT(name, 1), '***') as name,
  CONCAT(LEFT(phone, 3), '****', RIGHT(phone, 4)) as phone,
  email ; INTO OUTFILE '/tmp/export_masked.csv' ; FROM users;
```

### 5. 分类分级检查清单
| 检查项 | 方法 | 合规标准 |
|:---|:---|:---:|
| 敏感数据发现 | 正则扫描/ML 分类器 | ISO 27001 A.8.2.1 |
| 数据分级标签 | 自动化标记策略 | 等级保护 2.0 |
| 访问控制策略 | 基于分级的最小权限 | NIST SP 800-53 |
| 加密存储 | 静态加密（AES-256） | GDPR Art.32 |
| 传输加密 | TLS 1.2+ | PCI DSS 4.0 |
| 数据保留 | 自动过期策略 | 个保法 Art.19 |
## 二、DLP 数据防泄漏
DLP 覆盖数据三种状态：**静态**（存储）、**传输中**（网络）、**使用中**（终端）。

### 1. 网络 DLP
```bash
zeek -C -r capture.pcap
```

```zeek
module DLP; ; event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (to_lower(name) == "content-type" && /json|xml|csv/ in value) {
        print fmt("HTTP API传输: %s -> %s", c$http$uri, c$id$orig_h); }
}
```

```bash
ndpiReader -i eth0 -s 60 -w ndpi-output.txt ; tshark -r capture.pcap -Y "dns.txt_len > 60" -T fields -e dns.qry.name   # DNS 隧道外泄
```

### 2. 终端 DLP
```powershell
Register-WmiEvent -Query "SELECT * FROM Win32_VolumeChangeEvent WHERE EventType=2" -Action {
    Write-EventLog -LogName Security -Source DLP -EntryType Warning -EventId 4100 -Message "USB设备接入告警"
} ; Add-Type -AssemblyName System.Windows.Forms ; $clipboardText = [System.Windows.Forms.Clipboard]::GetText() ; if ($clipboardText -match '\b\d{4}-\d{4}-\d{4}-\d{4}\b') {
    Write-Warning "检测到信用卡号被复制到剪贴板!" ; [System.Windows.Forms.Clipboard]::Clear()
} ; Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PrintService/Admin'; ID=307} |
    Select-Object TimeCreated, Message ; Get-Process | Where-Object { $_.ProcessName -match 'SnippingTool|Snip|ScreenCapture' }
```

### 3. 存储 DLP 与数据发现
```bash
clamscan -r --heuristic-alerts --gen-json /shared/folder
```

```powershell
$patterns = @(
    '\d{4}-\d{4}-\d{4}-\d{4}',
    '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    '1[3-9]\d{9}'
) ; Get-ChildItem -Path "\\fileserver\share" -Recurse -File |
    Select-String -Pattern $patterns |
    Export-Csv -Path "dlp_findings.csv" -NoTypeInformation
```

### 4. 策略配置与响应
```powershell
$dlpPolicy = @{
    Name = "PII保护策略" ; Mode = "Enable" ; Rules = @(
        @{ Name = "阻止信用卡外传" ; Condition = "ContentContainsSensitiveInformation 'Credit Card'" ; Action = "BlockAccess | NotifyUser | GenerateIncident"; Priority = 1 },
        @{ Name = "告警身份证外传" ; Condition = "ContentContainsSensitiveInformation 'China ID Card'" ; Action = "NotifyUser | GenerateAlert"; Priority = 2 },
        @{ Name = "审计手机号外传" ; Condition = "ContentContainsSensitiveInformation 'Phone Number'" ; Action = "AuditOnly"; Priority = 3 } )
}
```

```bash
dlpcmd policy -list ; dlpcmd policy -test -name "PII Policy" -file sample_data.txt
```

### 5. 绕过检测
```bash
tcpdump -i eth0 -A 'tcp port 443' | grep -E '(zip|rar|7z|tar|gz)'    # 压缩后外传 ; java -jar StegExpose.jar stego_images/                                # 图片隐写
```

```python
import base64, re
def detect_encoded_data(text):
    b64_pattern = r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    for m in re.findall(b64_pattern, text):
        try:
            decoded = base64.b64decode(m) if any(c.isascii() and not c.isprintable()
                for c in decoded):
                print(f"检测到编码数据外传: {m[:50]}...")
        except:
            pass
```

高熵字符串（尤其 10 组以上 Base64 块）是编码混淆外传的典型特征。

### 6. 云 DLP
```bash
aws macie2 create-classification-job \
  --job-type SCHEDULED \
  --s3-job-definition bucketDefinitions=[{bucketId=my-data-bucket}] \
  --sampling-percentage 50 ; curl -X POST -H "Authorization: Bearer $(gcloud auth application-default print-access-token)" \
  -H "Content-Type: application/json" \
  -d '{"item": {"value": "用户手机号: 13800138000"}, "inspectConfig": {"infoTypes": [{"name": "CHINA_PHONE_NUMBER"}]}}' \
  "https://dlp.googleapis.com/v2/projects/my-project/content:inspect" ; az purview classification-rule create \
  --account-name my-purview --name "ChinaIDRule" --classification-name "China ID Number"
```

## 三、数据脱敏与匿名化
关键技术：**k-匿名、l-多样性、t-紧密性、差分隐私**。

### 1. 静态脱敏（SDM）
```sql
UPDATE users SET name = CONCAT(LEFT(name, 1), '***'); ; UPDATE users SET phone = CONCAT(LEFT(phone, 3), '****', RIGHT(phone, 4));
UPDATE users SET id_card = CONCAT(LEFT(id_card, 6), '**********', RIGHT(id_card, 4)); ; UPDATE users SET email = CONCAT(LEFT(email, 2), '***@', SPLIT_PART(email, '@', 2)); ; -- 地址泛化：保留省市，隐藏街道
UPDATE users SET address = CONCAT(
  SPLIT_PART(address, '省', 1), '省',
  SPLIT_PART(SPLIT_PART(address, '省', 2), '市', 1), '市***'
); ; -- MySQL 脱敏函数 ; INSERT INTO test_users (name, phone, email) ; SELECT INSERT(name, 2, CHAR_LENGTH(name)-1, REPEAT('*', CHAR_LENGTH(name)-1)),
  INSERT(phone, 4, 4, '****'),
  INSERT(email, 2, INSTR(email, '@')-2, REPEAT('*', INSTR(email, '@')-2)) ; FROM production_users;
```

### 2. 动态脱敏（DDM）
```sql
-- SQL Server ; ALTER TABLE users ALTER COLUMN email ADD MASKED WITH (FUNCTION = 'email()'); ; ALTER TABLE users ALTER COLUMN phone ADD MASKED WITH (FUNCTION = 'partial(1,"****",3)');
ALTER TABLE users ALTER COLUMN name  ADD MASKED WITH (FUNCTION = 'partial(1,"***",0)'); ; CREATE USER admin_user WITHOUT LOGIN; ; GRANT UNMASK TO admin_user; ; -- Oracle DBMS_REDACT
BEGIN DBMS_REDACT.ADD_POLICY(
    object_schema => 'APP', object_name => 'USERS', policy_name => 'phone_mask',
    column_name => 'PHONE', function_type => DBMS_REDACT.PARTIAL,
    function_parameters => '1,4,****,3'); ; END;
```

### 3. k-匿名
```python
import pandas as pd

def apply_k_anonymity(df, quasi_identifiers, k=5):
    for col in quasi_identifiers:
        if df[col].dtype == 'object':
            df[col] = df[col].str[:1] + '**'              # 字符串：截断到首字符
        elif df[col].dtype in ['int64', 'float64']:
            df[col] = pd.cut(df[col], bins=10, precision=0)  # 数值：按范围分桶 counts = df.groupby(quasi_identifiers).size() violating = counts[counts < k]
    print(f"k={k}匿名检验:") print(f"  违反k-匿名的组数: {len(violating)}") print(f"  最小等价类大小: {counts.min()}") return df
```

### 4. 差分隐私
```python
import numpy as np

def laplace_mechanism(data, epsilon, sensitivity=1.0):
    scale = sensitivity / epsilon noise = np.random.laplace(0, scale, len(data)) return data + noise

def count_with_dp(data, epsilon):
    true_count = len(data) noise = np.random.laplace(0, 1/epsilon) return max(0, true_count + noise)

ages = np.array([25, 32, 28, 45, 35, 29, 41, 33, 27, 38])
epsilon = 0.1                                   # 隐私预算，越小隐私越好
print(f"真实均值: {np.mean(ages):.2f}")
print(f"差分隐私均值(ε={epsilon}): {np.mean(laplace_mechanism(ages, epsilon)):.2f}")

def compose_epsilon(epsilons):                  # 串行组合定理 return sum(epsilons)

def advanced_composition(k, epsilon, delta=1e-5):  # 高级组合定理 return epsilon * np.sqrt(2 * k * np.log(1/delta)) + k * epsilon * (np.exp(epsilon) - 1)
```

### 5. PostgreSQL Anonymizer
```sql
CREATE EXTENSION IF NOT EXISTS anon CASCADE; ; SELECT anon.init(); ; SECURITY LABEL FOR anon ON COLUMN users.name    IS 'MASKED WITH FUNCTION anon.fake_first_name()';
SECURITY LABEL FOR anon ON COLUMN users.phone   IS 'MASKED WITH FUNCTION anon.partial(anon.random_phone(),3,******,3)';
SECURITY LABEL FOR anon ON COLUMN users.email   IS 'MASKED WITH FUNCTION anon.fake_email()'; ; SECURITY LABEL FOR anon ON COLUMN users.id_card IS 'MASKED WITH FUNCTION anon.random_string(18)';
SELECT anon.anonymize_database(); ; SELECT anon.anonymize('users') TO '/tmp/anonymized_users.csv';
```

```bash
pg_dump --column-inserts --data-only -t users | sed -e 's/[0-9]\{11\}/138****8000/g' > anonymized_dump.sql
```

## 四、GDPR / 个保法合规评估
### 1. 处理活动记录（ROPA）
```python
import json
from datetime import datetime

class DataProcessingRecord:
    def __init__(self):
        self.activities = []

    def add_activity(self, name, controller, purpose, categories,
                     recipients, retention, safeguards):
        self.activities.append({
            "activity_name": name,
            "controller": controller,
            "processing_purpose": purpose,
            "data_categories": categories,
            "data_subjects": ["员工", "客户", "合作伙伴"],
            "recipients": recipients,
            "retention_period": retention,
            "technical_safeguards": safeguards,
            "legal_basis": "合同履行/法律义务/用户同意",
            "cross_border_transfer": False,
            "dpi_required": False,
            "record_date": datetime.now().isoformat() })

    def to_json(self, filename="ropa_records.json"):
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump({"organization": "", "data_protection_officer": "",
                       "processing_activities": self.activities},
                      f, indent=2, ensure_ascii=False)
```

### 2. 数据主体权利响应（DSAR）
流程：① 验证请求者身份 ② 搜索全部系统中的主体数据（HR/CRM/日志/备份）③ 生成数据包 ④ 法定期限内响应（**GDPR 30 天，PIPL 15 个工作日**）。

```bash
USER_EMAIL="user@example.com" ; mysql -h hr-db -e "SELECT * FROM employees WHERE email='$USER_EMAIL';"
curl -s "https://crm.company.com/api/search?email=$USER_EMAIL" -H "Authorization: Bearer $TOKEN" | jq .
curl -X GET "https://elastic:9200/app-*/_search?q=email:$USER_EMAIL&size=100" -u elastic:password | jq '.hits.hits[]._source'
find /shared -type f -exec grep -l "$USER_EMAIL" {} \; ; # 删除请求（含关联表与日志）
DELETE FROM users WHERE email = 'user@example.com'; ; DELETE FROM orders WHERE user_id IN (SELECT id FROM users WHERE email = 'user@example.com');
DELETE FROM logs WHERE user_id IN (SELECT id FROM users WHERE email = 'user@example.com'); ; aws s3 rm s3://my-bucket/users/user@example.com/ --recursive
```

### 3. 跨境数据传输路径
| 路径 | 适用条款 | 条件 | 工具 |
|:---|:---|:---|:---|
| SCC 标准合同条款 | GDPR Art.46(2) | 双方签署 SCC | EU SCC Generator |
| BCR 约束性公司规则 | GDPR Art.47 | 集团内统一隐私规则 | BCR Application Toolkit |
| 充分性认定 | GDPR Art.45 | 接收国被认定充分保护（日本、英国、韩国、以色列） | — |
| 安全评估 | 个保法 第38条 | 通过国家网信办安全评估 | 网信办申报系统 |
| 标准合同 | 个保法 第38条 | 签署标准合同 | 网信办标准合同范本 |
传输地图要素：数据类别、origin/destination、目的、法律依据、安全措施（如 TLS 1.3 + 访问日志审计）、备案状态。

### 4. 隐私合规自动审计
```bash
cookie-auditor scan https://example.com
```

```python
import re
def analyze_privacy_policy(text):
    checks = {
        "数据收集目的": "目的" in text or "purpose" in text.lower(),
        "数据共享": "共享" in text or "share" in text.lower(),
        "数据保留期": "保留" in text or "保留期限" in text,
        "用户权利": "删除" in text and "更正" in text,
        "联系方式": "contact" in text.lower() or "联系" in text,
        "Cookie说明": "Cookie" in text or "cookie" in text.lower(),
        "跨境传输": "跨境" in text or "cross-border" in text.lower(),
        "DPO信息": "数据保护官" in text or "DPO" in text } missing = [k for k, v in checks.items() if not v]
    print(f"缺少以下条款: {', '.join(missing)}" if missing else "隐私政策合规检查通过") return checks
```

```bash
java -jar pia-*-jar-with-dependencies.jar \
  --template pia-template.json --output pia-report.pdf --analysis-level 3
```

### 5. 合规差距矩阵
| 法规要求 | 检查项 | 当前状态 | 修复优先级 | 修复建议 |
|:---|:---|:---:|:---:|:---|
| GDPR Art.5 | 数据最小化 | 部分实施 | 🔴 高 | 审查数据字段，删除非必要采集 |
| GDPR Art.17 | 被遗忘权 | 未实施 | 🔴 高 | 建立自动化数据删除流程 |
| GDPR Art.32 | 安全措施 | 已实施 | 🟢 低 | 定期渗透测试 |
| PIPL Art.15 | 单独同意 | 部分实施 | 🟡 中 | 敏感信息处理增加单独同意弹窗 |
| PIPL Art.38 | 跨境传输 | 未实施 | 🔴 高 | 完成网信办安全评估申报 |
| CCPA | Opt-out 权利 | 未实施 | 🟡 中 | 添加 "Do Not Sell" 链接 |
## 五、数据库安全与加密
### 1. 访问控制与身份认证
```sql
-- MySQL：最小权限应用账户 ; CREATE USER 'app_user'@'10.0.0.%' IDENTIFIED BY 'strong_password_here'; ; GRANT SELECT, INSERT, UPDATE ON mydb.* TO 'app_user'@'10.0.0.%';
REVOKE DROP, ALTER, CREATE ON mydb.* FROM 'app_user'@'10.0.0.%'; ; ALTER USER 'app_user'@'10.0.0.%' REQUIRE SSL; ; ALTER USER 'app_user'@'10.0.0.%'
  PASSWORD EXPIRE INTERVAL 90 DAY FAILED_LOGIN_ATTEMPTS 5 PASSWORD_LOCK_TIME 1; ; -- PostgreSQL 行级安全 ; CREATE POLICY user_policy ON users USING (user_id = current_setting('app.current_user')::int);
ALTER TABLE users ENABLE ROW LEVEL SECURITY; ; -- MongoDB 角色 ; db.createRole({ role: "appReadWrite",
  privileges: [{ resource: { db: "app", collection: "" }, actions: ["find", "insert", "update"] }],
  roles: [] }); ; db.createUser({user: "app_user", pwd: "password", roles: ["appReadWrite"]});
```

### 2. 透明数据加密（TDE）
```sql
-- SQL Server ; CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'StrongPassword123!'; ; CREATE CERTIFICATE TDECert WITH SUBJECT = 'TDE Certificate'; ; USE MyDatabase;
CREATE DATABASE ENCRYPTION KEY WITH ALGORITHM = AES_256 ENCRYPTION BY SERVER CERTIFICATE TDECert; ; ALTER DATABASE MyDatabase SET ENCRYPTION ON; ; SELECT DB_NAME(database_id) AS DBName,
       encryption_state_desc = CASE encryption_state WHEN 0 THEN 'No encryption' WHEN 1 THEN 'Unencrypted' ; WHEN 2 THEN 'Encryption in progress' WHEN 3 THEN 'Encrypted'
         WHEN 4 THEN 'Key change in progress' WHEN 5 THEN 'Decryption in progress' ; END ; FROM sys.dm_database_encryption_keys; ; -- MySQL 企业版加密表空间 ; CREATE TABLESPACE secure_ts ADD DATAFILE 'secure.ibd'
  ENCRYPTION='Y' DEFAULT STORAGE ENGINE=InnoDB; ; CREATE TABLE secure_data (id INT, data VARCHAR(100)) TABLESPACE secure_ts;
```

### 3. 列级加密
```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto; ; INSERT INTO users (name, ssn, credit_card) ; VALUES ('张三',
  pgp_sym_encrypt('123-45-6789', 'encryption_key'),
  pgp_sym_encrypt('4111-1111-1111-1111', 'encryption_key')); ; SELECT name,
  pgp_sym_decrypt(ssn, 'encryption_key') AS ssn,
  pgp_sym_decrypt(credit_card, 'encryption_key') AS credit_card ; FROM users WHERE name = '张三'; ; SELECT gen_keypair('RSA', 2048) INTO keypair;      -- 非对称：公钥加密
UPDATE users SET ssn_encrypted = pgp_pub_encrypt('123-45-6789', dearmor(public_key)); ; -- MySQL ; INSERT INTO users (name, ssn) VALUES ('张三', AES_ENCRYPT('123-45-6789', 'encryption_key'));
SELECT name, AES_DECRYPT(ssn, 'encryption_key') AS ssn FROM users;
```

### 4. 审计与监控
```
# postgresql.conf
shared_preload_libraries = 'pgaudit'
pgaudit.log = 'read,write,role,ddl'
pgaudit.log_catalog = off
pgaudit.log_level = 'notice'
pgaudit.log_relation = on
```

```sql
CREATE EXTENSION pgaudit; ; SET pgaudit.session_level_read = on; ; SET pgaudit.session_level_write = on; ; SELECT audit.audit_table('users');
SELECT audit.audit_table('orders', 'insert,update,delete'); ; SELECT * FROM pgaudit.log WHERE audit_type = 'DDL' ORDER BY event_time DESC; ; -- MariaDB/MySQL server_audit
INSTALL SONAME 'server_audit'; ; SET GLOBAL server_audit_logging = ON; ; SET GLOBAL server_audit_events = 'CONNECT,QUERY,TABLE'; ; SET GLOBAL server_audit_incl_users = 'app_user,admin';
SET GLOBAL server_audit_file_rotate_size = 100000000; ; -- Oracle ; AUDIT SELECT, INSERT, UPDATE, DELETE ON app.users BY ACCESS; ; AUDIT EXECUTE ON app.procedure_name;
AUDIT CREATE ANY TABLE BY admin;
```

### 5. 加固基线
```ini
# my.cnf ; [mysqld] ; local-infile=0 ; skip-symbolic-links=yes ; skip-networking=0 ; bind-address=127.0.0.1 ; max_connections=1000 ; max_user_connections=50 ; connect_timeout=10 ; wait_timeout=600
validate_password.policy=STRONG ; validate_password.length=12 ; log_error=/var/log/mysql/error.log ; slow_query_log=ON ; general_log=OFF ; ssl-ca=/etc/mysql/ssl/ca.pem
ssl-cert=/etc/mysql/ssl/server-cert.pem ; ssl-key=/etc/mysql/ssl/server-key.pem
```

```
# postgresql.conf
listen_addresses = 'localhost'
password_encryption = 'scram-sha-256'
ssl = on
ssl_ciphers = 'HIGH:MEDIUM:+3DES:!aNULL'
logging_collector = on
log_directory = 'pg_log'
log_filename = 'postgresql-%Y-%m-%d.log'
log_statement = 'ddl'
log_line_prefix = '%t %u %d %p %r '
log_checkpoints = on
log_connections = on
log_disconnections = on
log_lock_waits = on
log_temp_files = 0
statement_timeout = 30000
idle_in_transaction_session_timeout = 60000
```

### 6. 备份安全
```bash
mysqldump --all-databases --single-transaction --routines --triggers | \
  gpg --encrypt --recipient backup-key@company.com > mysql_backup_$(date +%Y%m%d).sql.gpg ; pg_dumpall | gzip | \
  openssl enc -aes-256-cbc -salt -pass pass:backup_password > pg_backup_$(date +%Y%m%d).sql.gz.enc ; mongodump --archive | gzip | \
  openssl enc -aes-256-cbc -salt -pass pass:backup_password > mongo_backup.archive.gz.enc ; gpg --verify backup.sql.gpg.sig backup.sql.gpg      # 完整性校验 ; sha256sum -c backup.sha256
openssl enc -d -aes-256-cbc -in backup.sql.gz.enc -pass pass:backup_password | gunzip | mysql -u root -p
```

## 六、隐私影响评估（PIA / DPIA）
GDPR Art.35 要求高风险处理前必须做 DPIA；PIPL 第五十五条要求自动化决策、委托处理等场景做影响评估。

### 1. 触发条件判定
```python
def check_dpia_required(activity):
    high_risk_indicators = [
        activity.get('systematic_profiling'),
        activity.get('large_scale_sensitive_data'),
        activity.get('public_area_monitoring'),
        activity.get('vulnerable_data_subjects'),
        activity.get('innovative_technology'),
        activity.get('cross_border_transfer'),
        activity.get('automated_decision_making') ] met = sum(1
                for i in high_risk_indicators if i) if met >= 2:
        return True, f"满足{met}个高风险指标，必须开展DPIA"
    elif met == 1:
        return True, "建议开展DPIA"
    return False, "无需DPIA，但建议记录判断依据"
```

EDPB 必做清单：员工监控系统、大数据健康分析、信用评分系统、精准广告投放、人脸识别系统、位置轨迹追踪、儿童数据处理。

### 2. 报告结构与数据流
```
dpia_report:
  metadata: { title, version, date, status } section_1: 处理活动描述 section_2: 必要性与相称性评估 section_3: 风险评估 section_4: 风险处置措施 section_5: 数据主体参与 section_6: 结论与建议
```

```yaml
data_flow:
  sources: ["Web前端 (用户行为埋点)", "移动App SDK", "线下POS系统"] processing: ["数据清洗与去重", "用户画像构建 (自动化决策)", "实时推荐引擎"] storage: ["ClickHouse (3个月热数据)", "HDFS (2年冷数据)"]
  recipients: ["推荐算法团队", "BI分析团队"] retention: "用户注销后30天删除"
```

### 3. 风险矩阵与残余风险
```python
class PrivacyRiskAssessment:
    def __init__(self): self.risks = []

    def add_risk(self, risk_id, description, likelihood, impact, data_subjects):
        score = likelihood * impact           # likelihood/impact: 1-5 self.risks.append({
            "id": risk_id, "description": description,
            "likelihood": likelihood, "impact": impact, "risk_score": score,
            "risk_rating": "低" if score <= 6 else ("中" if score <= 12 else "高"),
            "affected_subjects": data_subjects, "mitigation": "", "residual_risk": ""
        })

    def add_mitigation(self, risk_id, mitigation, residual_likelihood, residual_impact):
        for risk in self.risks:
            if risk["id"] == risk_id:
                risk["mitigation"] = mitigation residual = residual_likelihood * residual_impact
                risk["residual_risk"] = "低" if residual <= 6 else ("中" if residual <= 12 else "高")

pia = PrivacyRiskAssessment()
pia.add_risk("R1", "用户画像披露导致歧视", 3, 5, "全体用户")
pia.add_risk("R2", "数据泄露导致身份冒用", 2, 5, "10万+用户")
pia.add_risk("R3", "未经同意的自动化决策", 4, 3, "活跃用户")
pia.add_mitigation("R1", "禁止敏感属性画像，人工审核机制", 2, 3)
pia.add_mitigation("R2", "数据加密、访问控制、安全审计", 1, 4)
pia.add_mitigation("R3", "用户可关闭个性化推荐", 2, 2)
```

### 4. Privacy by Design 审计
```python
dpb_design_checklist = {
    "数据最小化": ["仅收集业务必需字段", "设置合理的数据保留期限", "定期清理过期数据"],
    "默认隐私":   ["最严格的隐私设置作为默认值", "用户需主动选择开启数据共享", "选择性同意（Granular Consent）"],
    "透明度":     ["清晰易懂的隐私政策", "实时的数据使用说明", "数据访问与导出接口"],
    "安全性":     ["端到端加密", "假名化/匿名化处理", "访问日志与异常检测"],
    "用户控制权": ["One-click 数据导出", "账户删除流程", "隐私偏好中心"]
}
# 逐项比对 system_config，输出「隐私设计合规率 = 通过项 / 总项」
```

### 5. DPIA 文档模板
```markdown
# DPIA: [项目名称]

## 1. 处理活动描述
- **处理目的**：  - **数据类别**：  - **数据主体**：
- **处理方式**（自动化/半自动化）：  - **涉及的新技术**：

## 2. 必要性评估
| 评估项 | 说明 |
|:---|:---|
| 处理目的合法 | |
| 数据最小化 | |
| 存储期限合理 | |
| 替代方案 | |

## 3. 风险评估矩阵
| 风险ID | 风险描述 | 可能性(1-5) | 影响(1-5) | 风险等级 | 缓解措施 | 残余风险 |
|:---:|:---|:---:|:---:|:---:|:---|:---:|
| R01 | | | | | | |

## 4. 风险处置计划
| 优先级 | 风险 | 措施 | 负责人 | 截止日期 | 状态 |
|:---:|:---|:---|:---:|:---:|:---:|
| 🔴 高 | | | | | ⏳ |

## 5. 结论
**DPIA结论：** □ 可接受（残余风险在可接受范围内）
□ 不可接受（需向监管机构咨询）

**DPO签名：** ______ **日期：** ______
```

## 八、参考资源
- [ISO 27001:2022 — Annex A 8.2 Data classification](https://www.iso.org/standard/27001)
- [ISO 27701 — Privacy Information Management](https://www.iso.org/standard/71670.html)
- [ISO 29134 — Privacy Impact Assessment Guidelines](https://www.iso.org/standard/75250.html)
- [NIST SP 800-60 — Guide for Mapping Types of Information](https://csrc.nist.gov/publications/detail/sp/800-60/vol-1-rev-1/final)
- [NIST SP 800-188 — De-identification](https://csrc.nist.gov/publications/detail/sp/800-188/draft)
- [NIST Privacy Framework](https://www.nist.gov/privacy-framework)
- [等级保护2.0 — 数据安全分级指南](https://www.gov.cn/zhengce/zhengceku/2022-12/16/content_5732384.htm)
- [中国个人信息保护法（PIPL）](https://www.gov.cn/xinwen/2021-08/20/content_5632151.htm)
- [GDPR Full Text](https://gdpr-info.eu/)
- [GDPR Compliance Checklist](https://gdpr.eu/checklist/)
- [EDPB Guidelines on DPIA](https://edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-data-protection-impact-assessment-dpia_en)
- [ICO DPIA Guidance](https://ico.org.uk/for-organisations/guide-to-data-protection/guide-to-the-general-data-protection-regulation-gdpr/data-protection-impact-assessments-dpias/)
- [CNIL DPIA Methodology](https://www.cnil.fr/en/privacy-impact-assessments-pia)
- [OWASP Data Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Data_Protection_Cheat_Sheet.html)
- [OWASP Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)
- [CIS Database Security Benchmarks](https://www.cisecurity.org/benchmark/database/)
- [CISA Data Loss Prevention Best Practices](https://www.cisa.gov/data-loss-prevention)
- [PostgreSQL Security Best Practices](https://www.postgresql.org/docs/current/security.html)
- [MongoDB Security Checklist](https://www.mongodb.com/docs/manual/administration/security-checklist/)

## 九、上游原文（references/）
| 上游文件 | 本包路径 |
|:---|:---|
| `README.md`（分类导读与技能清单） | `references/README.md` |
| `skills/数据分类与分级保护-DataClassificationGrading.md` | `references/数据分类与分级保护-DataClassificationGrading.md` |
| `skills/DLP数据防泄漏策略-DataLossPrevention.md` | `references/DLP数据防泄漏策略-DataLossPrevention.md` |
| `skills/数据脱敏与匿名化-DataMaskingAnonymization.md` | `references/数据脱敏与匿名化-DataMaskingAnonymization.md` |
| `skills/GDPR-个保法合规评估-PrivacyCompliance.md` | `references/GDPR-个保法合规评估-PrivacyCompliance.md` |
| `skills/数据库安全与加密-DatabaseSecurityEncryption.md` | `references/数据库安全与加密-DatabaseSecurityEncryption.md` |
| `skills/隐私影响评估-PIA-PrivacyImpactAssessment.md` | `references/隐私影响评估-PIA-PrivacyImpactAssessment.md` |