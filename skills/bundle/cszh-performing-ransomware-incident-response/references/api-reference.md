# 勒索软件事件响应 - API 参考

## 文件系统扫描

### 勒索软件扩展名
常见加密文件扩展名：`.encrypted`、`.locked`、`.crypt`、`.locky`、`.cerber`、`.zepto`、`.wncry`、`.wnry`、`.wcry`、`.onion`、`.micro`、`.r5a`

### 勒索信文件名
常见模式：`readme.txt`、`how_to_decrypt.txt`、`decrypt_instructions.html`、`restore_files.txt`、`_readme.txt`、`how_to_recover.txt`

## IOC 采集

### hashlib（Python 标准库）
```python
sha = hashlib.sha256()
with open(path, "rb") as f:
    for chunk in iter(lambda: f.read(8192), b""):
        sha.update(chunk)
sha.hexdigest()
```

### ID Ransomware 变体识别
将勒索信或加密文件样本上传到 id-ransomware.malwarehunterteam.com 进行变体识别。

## 卷影副本检测（Windows）

```bash
vssadmin list shadows
```

勒索软件通常通过以下方式删除卷影副本：
```bash
vssadmin delete shadows /all /quiet
wmic shadowcopy delete
```

## 遏制检查清单

1. 网络隔离 - 禁用网卡或迁移到隔离 VLAN
2. 证据保全 - 修复前对磁盘进行镜像
3. 凭据重置 - krbtgt（两次）、DA 账号、服务账号
4. 范围评估 - 枚举受影响主机和文件共享
5. 变体识别 - 向威胁情报平台提交 IOC
6. 恢复 - 确认根因后从干净备份恢复

## 输出 Schema

```json
{
  "report": "ransomware_incident_response",
  "encrypted_files_found": 342,
  "ransom_notes_found": 5,
  "shadow_copy_status": {"intact": false, "shadow_copies": 0},
  "containment_actions": [{"priority": 1, "action": "Isolate affected hosts"}],
  "file_hashes": [{"path": "/data/file.encrypted", "sha256": "abc123..."}]
}
```

## CLI 用法

```bash
python agent.py --target /mnt/affected_share --max-files 5000 --output report.json
```
