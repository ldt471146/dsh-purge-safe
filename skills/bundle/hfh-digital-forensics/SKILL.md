---
name: hfh-digital-forensics
description: 网络安全知识库「数字取证」分类技能包，源自 Hi-FullHouse/CyberSecurity-Skills 上游 30-数字取证-DigitalForensics。覆盖磁盘镜像与证据获取（dd/dcfldd 分块镜像与哈希、guymager/FTK Imager E01 格式、硬件与软件写保护验证、Sleuth Kit mmls/fls/icat/istat 文件系统分析、证据保管链与哈希校验、Plaso 超级时间线、文件恢复与痕迹分析）、内存取证（LiME/WinPmem/DumpIt 获取、Volatility 2/3 进程与 psxview 隐藏进程、netscan 网络连接、hivelist/printkey/hashdump 注册表、malfind/apihooks/ssd 内核挂钩检测、Linux 内存插件、自动化扫描脚本）、Windows 数字取证（MFT 与 USN Journal 及时间戳欺骗识别、Hayabusa/EvtxeCmd 事件日志与关键事件 ID、Prefetch/Shimcache/Amcache/SRUM 执行痕迹、LNK/JumpList/ShellBags/回收站、KAPE 采集与时间线）、Linux 数字取证（auth.log/auditd 日志、用户进程与 /proc 取证、Sleuth Kit MAC 时间轴、chkrootkit/rkhunter 与 LD_PRELOAD 检测、Docker 容器取证）以及浏览器与邮件取证（Chrome/Firefox SQLite 历史与 1601 微秒时间戳换算、下载与搜索词提取、Outlook PST/OST 转换、邮件头 Received 链与 SPF/DKIM/DMARC、钓鱼与社交工程特征识别），含 6 份中文原文 references。
---

# 数字取证（Digital Forensics）
本技能用于**事件调查与电子证据固定**：先保证证据完整性（写保护 + 哈希 + 保管链），再按「磁盘 → 内存 → 系统痕迹 → 应用痕迹」逐层提取，最后拼时间线还原攻击过程。

三条铁律：**① 先取证后分析**（镜像与转储完成并校验哈希前不动原盘）；**② 只读访问**（挂载一律 `ro,noexec`）；**③ 每一步都记录时间、操作者与哈希**（法律可用性取决于保管链）。关键工具：dcfldd、guymager、FTK Imager、libewf、Sleuth Kit、Autopsy、Volatility 2/3、LiME、WinPmem、KAPE、Hayabusa、Eric Zimmerman 工具集、Plaso、Photorec、Hindsight。

## 一、磁盘镜像与证据获取
### 1. 磁盘镜像工具
```bash
sudo fdisk -l ; sudo lsblk ; sudo dd if=/dev/sda of=/evidence/case001/image.dd bs=4M conv=noerror,sync status=progress ; dcfldd if=/dev/sda of=/evidence/case001/image.dd \
  bs=4M hash=sha256 hashlog=/evidence/case001/image.hash \
  hashwindow=1G status=on conv=noerror,sync ; dcfldd if=/dev/sda of=/evidence/case001/image.dd ofsplit=2G bs=4M \
  hash=sha256 hashlog=/evidence/case001/hash.log ; dcfldd if=/dev/sda bs=4M | nc forensic-server 9999   # 网络传输 ; # 接收端: nc -l -p 9999 > image.dd
```

```bash
sudo apt-get install guymager && sudo guymager    # 支持 Raw/DD、EnCase E01、AFF ; ftkimager.exe \\.\PhysicalDrive0 C:\Evidence\case001.E01 \
  --e01 --compress 2 \
  --case-number "CASE-001" --evidence-number "E01" \
  --description "Suspect Laptop HDD"
```

### 2. 写保护
```bash
sudo hdparm -r /dev/sdb             # readonly = 1 (on) 确认写保护 ; sudo mount -o ro,noexec /dev/sdb1 /mnt/evidence
sudo dd if=/dev/zero of=/dev/sdb bs=512 count=1   # 验证：应返回 Operation not permitted ; sudo asr imagescan --source /dev/disk2            # macOS
sudo asr --source /dev/disk2 --target /tmp/forensic_image.dmg --erase
```

### 3. 文件系统分析（Sleuth Kit）
```bash
mmls /mnt/evidence/disk_image.dd                       # 分区表 ; fls -f ntfs -o 2048 /mnt/evidence/disk_image.dd        # 列目录（o=分区偏移）
fls -r -f ntfs -o 2048 /mnt/evidence/disk_image.dd > file_list.txt ; icat -f ntfs -o 2048 /mnt/evidence/disk_image.dd 12345-123 > extracted_file.dll
istat -f ntfs -o 2048 /mnt/evidence/disk_image.dd 12345   # MAC 时间
```

### 4. 保管链
```python
import json
from datetime import datetime

class ChainOfCustody:
    def __init__(self, case_id, evidence_id):
        self.evidence = {
            "case_id": case_id, "evidence_id": evidence_id,
            "description": "", "source": "", "acquisition_method": "",
            "hash_sha256": "", "hash_md5": "", "size_bytes": 0,
            "acquisition_date": None, "acquirer": "", "transfers": []
        }

    def record_acquisition(self, device, method, acquirer, hash_value):
        self.evidence.update({
            "device": device, "acquisition_method": method,
            "hash_sha256": hash_value,
            "acquisition_date": datetime.now().isoformat(), "acquirer": acquirer
        })
        self.add_transfer("acquisition", acquirer, f"Evidence acquired from {device}")

    def add_transfer(self, custodian, reason, location=""):
        self.evidence["transfers"].append({
            "from": self.evidence["transfers"][-1]["to"] if self.evidence["transfers"] else "crime_scene",
            "to": custodian, "date": datetime.now().isoformat(),
            "reason": reason, "location": location or "lab"
        })

    def verify_integrity(self, current_hash):
        return {"original_hash": self.evidence["hash_sha256"], "current_hash": current_hash,
                "intact": self.evidence["hash_sha256"] == current_hash,
                "verified_at": datetime.now().isoformat()}
```

保管链报告应含：案件编号、证据编号、获取时间与获取人、SHA256、逐条转移记录（时间 | 移交人 → 接收人 | 原因）。

### 5. 镜像格式与哈希验证
```bash
sudo apt-get install libewf-tools ; ewfacquire /evidence/image.dd --format encase6 --compress 2 \
  --case-number "CASE-001" -C /evidence/case001.E01 ; ewfexport /evidence/case001.E01 --format raw -t /evidence/exported_image.dd ; sha256sum /evidence/image.dd > /evidence/image.hash
sha256sum -c /evidence/image.hash ; ewfinfo /evidence/case001.E01 | grep -i hash ; sudo mount -o loop,ro /evidence/image.dd /mnt/forensic
sudo xmount --in dd --out vdi /evidence/image.dd /mnt/virtual
```

```python
import hashlib

class ForensicHashVerifier:
    @staticmethod
    def calculate_hash(filepath, algorithms=["sha256"]):
        hashers = {alg: hashlib.new(alg) for alg in algorithms}
        with open(filepath, 'rb') as f:
            while True:
                block = f.read(65536)
                if not block: break
                for hasher in hashers.values():
                    hasher.update(block)
        return {alg: h.hexdigest() for alg, h in hashers.items()}

    @staticmethod
    def verify_image_segments(segment_pattern, total_segments):
        combined = hashlib.sha256()
        for i in range(total_segments):
            with open(f"{segment_pattern}.{i:03d}", 'rb') as f:
                while True:
                    data = f.read(65536)
                    if not data: break
                    combined.update(data)
        return combined.hexdigest()
```

镜像格式对比：Raw（.dd/.raw/.img，最基础无压缩）｜E01（EnCase，压缩 + 元数据 + 校验和）｜AFF（开源压缩格式）。

### 6. Windows 痕迹速查
```bash
PECmd.exe -d "C:\Windows\Prefetch" --csv "output.csv"                       # 程序执行 ; JLECmd.exe -d "C:\Users\admin\AppData\Roaming\Microsoft\Windows\Recent" --csv output.csv  # Jump Lists
AmcacheParser.exe -f "C:\Windows\AppCompat\Programs\Amcache.hve" --csv output.csv ; AppCompatCacheParser.exe --csv output.csv                                   # ShimCache
RBCmd.exe -d "C:\$Recycle.Bin"                                              # 回收站 ; hindsight -i "C:\Users\admin\AppData\Local\Google\Chrome\User Data" -o output
```

### 7. Linux 痕迹速查
```bash
for user in $(ls /home/); do echo "=== $user ==="; cat /home/$user/.bash_history 2>/dev/null; done ; cat ~/.ssh/authorized_keys
cat /etc/ssh/sshd_config | grep -v "^#" | grep -v "^$" ; ls -la /var/spool/cron/crontabs/ ; cat /etc/crontab ; ls -la /etc/cron.d/
cat /etc/systemd/system/*.service ; systemctl list-units --type=service --state=running ; last -100 > login_history.txt
find / -perm -4000 -ls 2>/dev/null      # SUID ; find / -perm -2000 -ls 2>/dev/null      # SGID ; find /etc -mtime -7 -ls 2>/dev/null
find /var/www -mtime -7 -ls 2>/dev/null
```

### 8. 文件恢复与特征分析
```bash
sudo photorec /dev/sda ; sudo extundelete /dev/sda2 --restore-all --output-dir /recovery/ ; sudo extundelete /dev/sda2 --restore-directory /home/user/documents/
# NTFS：Autopsy 文件浏览 → 过滤 "Deleted Files"
file suspicious_file ; file --mime-type suspicious_file ; exiftool image.jpg ; sha256sum suspicious_file ; md5sum suspicious_file
```

### 9. 取证时间线
```bash
log2timeline.py --parsers ntfs,filestat,pe,chrome_cache,prefetch timeline.dump /mnt/evidence/disk_image.dd ; psort.py timeline.dump -o l2tcsv -w timeline.csv
```

关键时间节点：恶意文件首次出现｜系统文件被篡改｜计划任务创建｜用户登录/登出｜数据外传压缩包创建。

## 二、内存取证（Volatility）
**内存获取必须在系统运行状态下进行，获取后立即哈希校验以保证据链完整。**

### 1. 内存获取
```bash
git clone https://github.com/504ensicsLabs/LiME.git && cd LiME/src && make ; sudo insmod lime-$(uname -r).ko "path=/evidence/memory.lime format=raw"
# format 选项: raw（Volatility 推荐）/ lime（带元数据压缩）/ padded（对齐填充） ; sudo insmod fmem.ko && sudo dd if=/dev/fmem of=/tmp/memory.dd bs=1M ; sudo ./avml /tmp/memory.raw          # AVML（Microsoft 开源）
```

```bash
winpmem_mini.exe C:\Evidence\memory.raw                        # Windows（AFF4） ; winpmem_mini.exe --format raw -o C:\Evidence\memory.raw
winpmem_mini.exe --format raw | nc forensic-server 9999        # 无文件获取 ; DumpIt.exe /Outfile=C:\incident\memory.dmp
MagnetRAMCapture.exe C:\incident\memory.raw ; certutil -hashfile C:\incident\memory.raw SHA256 > C:\incident\memory.sha256 ; # FTK Imager GUI: File → Capture Memory → 选择保存路径
```

虚拟机内存：VMware 挂起时的 `.vmem`｜Hyper-V 的 `.bin`/`.vmrs`｜VirtualBox 的 `.sav`/`.vmem`。

### 2. Volatility 基础
```bash
python3 vol.py -f memory.raw windows.info        # V3 自动识别 OS，无需 profile
python2 vol.py -f memory.raw imageinfo           # V2 先跑 imageinfo 定 Profile ; python2 vol.py -f memory.raw --profile=Win10x64_19041 [plugin]
```

### 3. 进程分析
```bash
python3 vol.py -f memory.raw windows.pslist ; python3 vol.py -f memory.raw windows.pstree        # 父进程异常检测
python3 vol.py -f memory.raw windows.psxview       # 隐藏进程 ; python3 vol.py -f memory.raw windows.cmdline       # 命令行
python3 vol.py -f memory.raw windows.envars        # 环境变量（恶意 DLL 搜索路径） ; python3 vol.py -f memory.raw windows.dlllist --pid 1234
python3 vol.py -f memory.raw windows.dumpfiles --pid 1234 ; python2 vol.py -f memory.raw --profile=Win10x64 memdmp --pid 1234 -D processes/
```

恶意进程检测特征：① 无父进程 ② 从临时目录运行 ③ 相似进程名（svch0st.exe vs svchost.exe）④ pslist 看不到但 psxview 可见 ⑤ 无对应可执行文件 ⑥ 父进程异常（如 explorer.exe 的父进程是 svchost.exe）。

### 4. 网络与注册表
```bash
python3 vol.py -f memory.raw windows.netscan ; python2 vol.py -f memory.raw --profile=Win10x64 netscan     # Win7+；XP 用 connscan
python2 vol.py -f memory.raw --profile=Win10x64 sockets ; python3 vol.py -f memory.raw windows.sockets ; python3 vol.py -f memory.raw windows.connections
```

网络指标：通往已知恶意 IP 的 C2 连接｜非标准端口监听（Shell）｜大量对外连接（外传）｜Tor/I2P 匿名网络连接。

```bash
python2 vol.py -f memory.raw --profile=Win10x64 hivelist ; python2 vol.py -f memory.raw --profile=Win10x64 printkey -K "ControlSet001\\Control\\ComputerName\\ComputerName"
python2 vol.py -f memory.raw --profile=Win10x64 hashdump     # SAM 哈希 ; python2 vol.py -f memory.raw --profile=Win10x64 autorunsc    # 自启动项
python2 vol.py -f memory.raw --profile=Win10x64 lsadump      # 用户凭据 ; python2 vol.py -f memory.raw --profile=Win10x64 shellbags
python3 vol.py -f memory.raw windows.hivelist ; python3 vol.py -f memory.raw windows.printkey --key "Microsoft\Windows\CurrentVersion\Run"
python3 vol.py -f memory.raw windows.printkey --key "Microsoft\Windows\CurrentVersion\RunOnce" ; python3 vol.py -f memory.raw windows.printkey --key "System\CurrentControlSet\Services"
python3 vol.py -f memory.raw windows.printkey --key "Microsoft\Windows NT\CurrentVersion\Winlogon"
```

### 5. DLL 与模块
```bash
python3 vol.py -f memory.raw windows.dlllist ; python3 vol.py -f memory.raw windows.ldrmodules    # 隐藏/未链接 DLL ; python3 vol.py -f memory.raw windows.modscan
```

DLL 劫持关注点：从 `%TEMP%`/`%APPDATA%` 加载｜伪装系统 DLL 名但路径不对｜签名缺失或无效｜基址偏移与正常不一致。

### 6. 恶意代码与 Rootkit 检测
```bash
python2 vol.py -f memory.raw --profile=Win10x64 mftparser ; python2 vol.py -f memory.raw --profile=Win10x64 filescan
python2 vol.py -f memory.raw --profile=Win10x64 modules ; modscan ; python2 vol.py -f memory.raw --profile=Win10x64 ssdt      # 内核 SSDT 挂钩
python2 vol.py -f memory.raw --profile=Win10x64 idt ; python2 vol.py -f memory.raw --profile=Win10x64 driverirp
python2 vol.py -f memory.raw --profile=Win10x64 malfind   # 注入代码 ; python2 vol.py -f memory.raw --profile=Win10x64 apihooks
python3 vol.py -f memory.raw windows.malfind --dump ; python3 vol.py -f memory.raw windows.apihooks
python3 vol.py -f memory.raw windows.yarascan --yara-rules /path/to/rules.yar ; python2 vol.py -f memory.raw --profile=Win10x64 cmdline
python2 vol.py -f memory.raw --profile=Win10x64 consoles ; python2 vol.py -f memory.raw --profile=Win10x64 cmdscan
python2 vol.py -f memory.raw --profile=Win10x64 clipboard ; python2 vol.py -f memory.raw --profile=Win10x64 procdump -p 1234 -D extracted/
python2 vol.py -f memory.raw --profile=Win10x64 dlldump -p 1234 -b -D extracted/
```

### 7. Linux 内存取证
```bash
python3 vol.py -f linux.mem linux.pslist ; python3 vol.py -f linux.mem linux.pstree ; python3 vol.py -f linux.mem linux.bash          # Bash 历史
python3 vol.py -f linux.mem linux.check_syslog  # 系统日志 ; python3 vol.py -f linux.mem linux.check_afinfo  # 网络协议钩子
python3 vol.py -f linux.mem linux.dmesg ; python3 vol.py -f linux.mem linux.lsmod         # 内核模块 ; python3 vol.py -f linux.mem linux.psxview       # 隐藏进程 ; python3 vol.py -f linux.mem linux.netstat
```

### 8. 时间线与自动化
```bash
python3 vol.py -f memory.raw windows.timeliner ; python3 vol.py -f memory.raw windows.timeliner --output=csv > timeline.csv
```

```bash
# 自动化：批量跑关键插件并筛可疑进程
python3 vol.py -f memory.raw windows.pstree  | grep -Ei "temp|powershell|rundll32|regsvr32"
python3 vol.py -f memory.raw windows.netscan  | grep -Ei "ESTABLISHED|LISTENING"
python3 vol.py -f memory.raw windows.malfind --dump --dump-dir extracted/
python3 vol.py -f memory.raw windows.cmdline
```

## 三、Windows 数字取证
### 1. 文件系统取证（MFT & USN Journal）
```bash
MFTECmd.exe -f "C:\Evidence\C\$MFT" --csv "C:\Output" ; python3 analyzeMFT.py -f "C:\Evidence\C\$MFT" -o mft_parsed.csv ; USNJournal2CSV.exe -m -c \\.\C: -o usn_journal.csv
```

MFT 提取重点：已删除文件（Flag 含 0x02）｜四类时间戳（创建/修改/MFT 修改/访问）｜文件大小与簇信息｜短文件名 + 长文件名。

**时间戳欺骗（Timestomping）识别**：正常时 `$STANDARD_INFORMATION ≈ $FILE_NAME` 时间；两者相差数秒以上即可疑。USN Journal 位于 `C:\$Extend\$UsnJrnl:$J`，删除事件搜 `USN_REASON_DELETE (0x80000100)`。

### 2. 事件日志分析
```
Security:   C:\Windows\System32\winevt\Logs\Security.evtx
System:     C:\Windows\System32\winevt\Logs\System.evtx
Application:C:\Windows\System32\winevt\Logs\Application.evtx
PowerShell: C:\Windows\System32\winevt\Logs\Windows PowerShell.evtx
```

```bash
hayabusa.exe csv-timeline -d "C:\Evidence\Logs" -o timeline.csv ; hayabusa.exe hunt -d "C:\Evidence\Logs" -o hunt_results.csv
hayabusa.exe hunting -r rules/hunting/ -d "C:\Evidence\Logs" ; EvtxeCmd.exe -f "C:\Evidence\Security.evtx" --csv "C:\Output"
```

关键事件 ID：**4624** 登录成功｜**4625** 登录失败｜**4672** 特殊权限登录｜**4688** 进程创建｜**4648** 显式凭据登录（RunAs）｜**4698** 计划任务创建｜**4103** PowerShell 管道执行｜**4104** PowerShell 脚本块。

```python
from collections import Counter

def detect_brute_force(log_entries):
    failed = [e for e in log_entries if e.get("EventID") == 4625]
    ip_counts = Counter(e.get("IpAddress", "") for e in failed)
    return [{"ip": ip, "failed_count": c} for ip, c in ip_counts.items() if c > 10]

def detect_lateral_movement(log_entries):
    return [e for e in log_entries
            if e.get("EventID") == 4624 and e.get("LogonType") == 3
            and not e.get("IpAddress", "").startswith("192.168.1")]

def detect_powershell_abuse(log_entries):
    suspicious = []
    for evt in [e
                for e in log_entries if e.get("EventID") in [4103, 4104]]:
        script = evt.get("ScriptBlockText", "")
        if any(kw in script.lower() for kw in
               ["downloadstring", "invoke-", "iex", "-enc ", "base64", "bypass"]):
            suspicious.append(evt)
    return suspicious
```

### 3. 执行痕迹
```bash
PECmd.exe -f "C:\Evidence\C\Windows\Prefetch\*.pf" --csv "C:\Output" ; AppCompatCacheParser.exe --csv "C:\Output" -f "C:\Evidence\C\Windows\System32\config\SYSTEM"
AmcacheParser.exe -f "C:\Evidence\C\Windows\AppCompat\Programs\Amcache.hve" --csv "C:\Output" ; SrumECmd.exe -f "C:\Evidence\C\Windows\System32\sru\SRUDB.dat" --csv "C:\Output"
```

| 痕迹 | 位置 | 关键信息 |
|:---|:---|:---|
| Prefetch | `C:\Windows\Prefetch\*.pf` | 执行次数、首次/最后执行时间、加载的 DLL |
| Shimcache | `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` | 文件名、最后修改时间 |
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` | 已安装程序、执行过的文件、驱动 |
| SRUM | `C:\Windows\System32\sru\SRUDB.dat` | 网络连接、CPU、能耗、数据流量 |
### 4. 用户活动痕迹
```bash
LECmd.exe -f "C:\Evidence\Users\*\Recent\*.lnk" --csv "C:\Output" ; RBCmd.exe -f "C:\Evidence\C\$Recycle.Bin\S-1-5-21-XXXX\$IXXXXX" --csv "C:\Output"
```

- **ShellBags**：`USRCLASS.DAT` 与 `NTUSER.DAT`，反映文件夹视图与访问历史。
- **Jump Lists**：`C:\Users\%USER%\AppData\Roaming\Microsoft\Windows\Recent`。
- **LNK 文件**包含目标原始路径、创建/访问时间、目标文件序列号、网络位置。
- **回收站**：`$I<ID>` 为元数据、`$R<ID>` 为原始文件。
- **浏览器**：Chrome `...\Google\Chrome\User Data\Default\History`｜Edge 同理｜Firefox `...\Mozilla\Firefox\Profiles\`。

### 5. 时间线
```bash
pip install plaso ; log2timeline.py --storage-file evidence.plaso "C:\Evidence\C" ; psort.py -o null evidence.plaso
psort.py -o l2tcsv -w timeline.csv evidence.plaso ; psort.py -o l2tcsv -w timeline.csv \
  -q "date > '2026-05-01 00:00:00' AND date < '2026-05-15 23:59:59'" evidence.plaso
```

三类分析手法：① 时间线拼接（合并 MFT + EVTX + Prefetch + 注册表）② 时间窗口聚焦攻击时段 ③ 活动序列重建用户操作顺序。

### 6. KAPE 采集
```bash
# KAPE 采集 + Hayabusa 时间线（等价命令）
kape.exe --tsource C:\Evidence\C --tdest C:\Output --target !SANS_Triage --gui 0
hayabusa.exe csv-timeline -d C:\Output -o hayabusa_timeline.csv -q
```

## 四、Linux 数字取证
### 1. 日志取证
```
/var/log/syslog       系统日志          /var/log/auth.log   认证（Ubuntu/Debian）
/var/log/secure       认证（RHEL）      /var/log/messages   系统消息
/var/log/kern.log     内核日志          /var/log/cron       Cron 任务
/var/log/audit/       auditd 审计       /var/log/apache2/  · /var/log/nginx/  Web 访问
/var/log/btmp         登录失败          /var/log/wtmp       登录历史
/var/log/lastlog      最后登录时间
```

```bash
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head -20 ; grep "Accepted password" /var/log/auth.log
grep "sudo" /var/log/auth.log ; ausearch -m COMMAND -ts recent
```

```
# /etc/audit/rules.d/audit.rules
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/crontab -p wa -k cron_changes
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /bin/su -p x -k su_exec
-w /usr/bin/sudo -p x -k sudo_exec
```

### 2. 用户与进程取证
```bash
who ; w ; last ; lastb ; lastlog ; cat ~/.bash_history ; cat ~/.zsh_history
for user in $(ls /home/); do echo "=== $user ==="; cat /home/$user/.bash_history 2>/dev/null; done ; ps auxf ; ps -ef ; pstree -a
netstat -tulpn ; ss -tulpn ; ls -la /proc/[pid]/ ; cat /proc/[pid]/cmdline ; cat /proc/[pid]/environ ; ls -la /proc/[pid]/fd/ ; cat /proc/[pid]/maps
```

异常进程特征：① 无关联二进制 ② 隐藏进程（对比 ps 输出与 /proc 列表）③ 从 `/tmp`、`/dev/shm` 运行。

```bash
comm -13 <(ls /proc | grep '^[0-9]' | sort) \
         <(ps -eo pid | grep '^ *[0-9]' | sort)      # 隐藏进程检测
```

### 3. 文件系统时间轴
```bash
fls -r -m / /dev/sda1 > body_file.txt ; mactime -b body_file.txt -d > timeline.csv ; istat /dev/sda1 123456 ; icat /dev/sda1 123456 > recovered_file
stat /etc/passwd ; find / -xdev -mmin -60 -type f      # 过去 60 分钟修改 ; find / -xdev -ctime -1 -type f      # 过去 24 小时元数据变化
find / -xdev -atime -1 -type f      # 过去 24 小时访问
```

时间戳篡改检测：比较 ctime 与 atime 的巨大差距。

### 4. Rootkit 与恶意软件检测
```bash
sudo chkrootkit ; sudo rkhunter --check ; lsmod | head -50 ; for mod in /sys/module/*; do ; if [ ! -f "$mod/version" ]; then echo "No version: $mod"; fi
done ; cat /etc/ld.so.preload ; cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep LD_PRELOAD ; rpm -Va | grep -E "(S|5)"    # RHEL 包完整性
debsums -c                   # Debian 包完整性 ; dpkg --verify                # Debian 系统文件校验
```

### 5. Docker 容器取证
```bash
docker ps -a ; docker logs <container_id>
docker export <container_id> -o container.tar && tar xvf container.tar ; docker inspect <container_id>
docker container diff <container_id>
docker commit <container_id> forensic_snapshot ; docker inspect --format='{{json .Mounts}}' <container_id>
docker events --since 24h ; ps aux | grep container-shim    # 从宿主机看容器内进程
```

### 6. 采集脚本
```bash
# Linux 取证自动化收集（等价命令）
hostname ; uname -a ; uptime ; cat /etc/os-release ; mount -l ; df -h ; free -h
cat /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/crontab /etc/hosts /etc/ssh/sshd_config > artifacts.txt
ls -la /etc/cron.d/ /etc/init.d/ /etc/systemd/system/ /etc/systemd/system/multi-user.target.wants/ ~/.config/systemd/user/ ~/.bashrc ~/.profile ~/.ssh/authorized_keys > persistence.txt
lsmod > modules.txt
```

## 五、浏览器与邮件取证
### 1. Chrome / Chromium
```
%LOCALAPPDATA%\Google\Chrome\User Data\Default\History        历史 + 下载
                                                  \Bookmarks   书签
                                                  \Cookies     Cookies
                                                  \Login Data  登录凭据
                                                  \Cache\  \Extensions\
```

```bash
sqlite3 "C:\Users\%USER%\AppData\Local\Google\Chrome\User Data\Default\History"
SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 50; ; -- Chrome 时间戳（1601-01-01 起微秒） ; SELECT url, title,
  datetime(last_visit_time/1000000-11644473600, 'unixepoch') AS visit_time ; FROM urls ORDER BY last_visit_time DESC; ; SELECT term, url FROM keyword_search_terms
JOIN urls ON keyword_search_terms.url_id = urls.id ORDER BY keyword_search_terms.id; ; SELECT target_path, url, start_time, received_bytes, total_bytes FROM downloads; ; SELECT host_key, name, value,
  datetime(creation_utc/1000000-11644473600, 'unixepoch') AS created ; FROM cookies WHERE host_key LIKE '%target%';
```

```python
import sqlite3, json
from datetime import datetime

class ChromeForensics:
    def __init__(self, profile_path):
        self.profile = profile_path
        self.epoch_offset = 11644473600     # Windows 1601 → Unix epoch

    def convert_chrome_time(self, chrome_time):
        if chrome_time == 0: return "unknown"
        return datetime.fromtimestamp(chrome_time / 1000000 - self.epoch_offset).isoformat()

    def get_history(self, limit=100):
        conn = sqlite3.connect(f"{self.profile}/History")
        rows = conn.execute("""SELECT url, title, visit_count, last_visit_time, typed_count
                               FROM urls ORDER BY last_visit_time DESC LIMIT ?""", (limit,))
        out = [{"url": r[0], "title": r[1], "visit_count": r[2],
                "last_visit": self.convert_chrome_time(r[3]), "typed_count": r[4]} for r in rows]
        conn.close(); return out

    def get_downloads(self):
        conn = sqlite3.connect(f"{self.profile}/History")
        rows = conn.execute("""SELECT target_path, url, start_time, received_bytes, total_bytes, state
                               FROM downloads ORDER BY start_time DESC""")
        out = [{"path": r[0], "url": r[1], "time": self.convert_chrome_time(r[2]),
                "size": f"{r[3]}/{r[4]} bytes", "completed": r[5] == 1} for r in rows]
        conn.close(); return out

    def get_search_terms(self):
        conn = sqlite3.connect(f"{self.profile}/History")
        out = [{"term": r[0], "url": r[1]} for r in conn.execute(
            "SELECT term, url FROM keyword_search_terms k JOIN urls u ON k.url_id = u.id")]
        conn.close(); return out
```

### 2. Firefox
```
%APPDATA%\Mozilla\Firefox\Profiles\*.default-release\
  places.sqlite     历史 + 书签
  cookies.sqlite    Cookies
  downloads.sqlite  下载
  logins.json       登录凭据
```

```sql
SELECT url, title, visit_count,
  datetime(last_visit_date/1000000, 'unixepoch') AS visit_time ; FROM moz_places ORDER BY last_visit_date DESC LIMIT 50; ; SELECT b.title, p.url, datetime(b.dateAdded/1000000, 'unixepoch') AS added
FROM moz_bookmarks b JOIN moz_places p ON b.fk = p.id WHERE b.type = 1; ; SELECT name, source, datetime(startTime/1000000, 'unixepoch') AS start, state FROM moz_downloads;
```

通用注意事项：① 先对数据库文件做哈希校验 ② 用写保护方式复制证据 ③ **避免打开浏览器导致时间戳被更新** ④ 记录文件系统时间戳。

### 3. Outlook / PST
```
PST（个人存储）: %USERPROFILE%\Documents\Outlook Files\
OST（脱机存储）: %LOCALAPPDATA%\Microsoft\Outlook\
自动完成缓存:   %APPDATA%\Microsoft\Outlook\NK2（2010-）
自动完成:       %APPDATA%\Microsoft\Outlook\Stream_Autocomplete_*（2013+）
```

```bash
readpst -o output_dir -r -j 4 "C:\Evidence\outlook.pst"     # -e EML / -m MBOX ; readpst -M -o output_mbox "C:\Evidence\outlook.pst" ; pffexport -t all "C:\Evidence\outlook.pst"
```

邮件头关键字段：`Received`（路由路径，检测伪造）｜`Authentication-Results`（SPF/DKIM/DMARC）｜`Message-ID`｜`Reply-To`（可能与 From 不一致）｜`X-Originating-IP`。

### 4. 邮件头分析与社交工程检测
```bash
Received: from mail-smtp.example.com (192.168.1.1) by ... ; Received: from mx.mail.com (203.0.113.5) by mail-smtp.example.com ... ; Received: from unknown (10.0.0.1) by mx.mail.com ...
# 从下往上读，最后一跳最接近收件人
```

验证判读：`spf=pass` 表示发件 IP 在 SPF 记录中；`dkim=pass` 表示签名有效；`dmarc=pass` 表示 SPF+DKIM 一致。

伪造/社工标记：`X-Priority: High`、`X-MSMail-Priority: High`、`Importance: High`、显示名与实际地址不符、Reply-To 与 From 不一致。

```python
import mailbox, re
from email import policy
import email as email_mod

class EmailForensics:
    def analyze_eml(self, eml_path):
        with open(eml_path, 'rb') as f:
            msg = email_mod.message_from_binary_file(f, policy=policy.default)
        return {"from": msg.get('From'), "to": msg.get('To'), "subject": msg.get('Subject'),
                "date": msg.get('Date'), "message_id": msg.get('Message-ID'),
                "received_chain": msg.get_all('Received'),
                "auth_results": msg.get('Authentication-Results'),
                "reply_to": msg.get('Reply-To'), "return_path": msg.get('Return-Path'),
                "x_originating_ip": msg.get('X-Originating-IP'), "x_mailer": msg.get('X-Mailer')}

    def extract_original_ip(self, msg):
        ips = []
        for header in msg.get_all('Received', []):
            ips.extend(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', header))
        return ips[0] if ips else None

    def _is_suspicious(self, msg, body):
        if not body: return False
        checks = ["urgent" in body.lower(), "click here" in body.lower(),
                  "password" in body.lower(), "verify your account" in body.lower(),
                  msg.get('Reply-To') and msg.get('Reply-To') != msg.get('From')]
        return sum(1 for c in checks if c) >= 2
```

Thunderbird：配置在 `%APPDATA%\Thunderbird\Profiles\*.default`，邮件存于 `ImapMail/` 与 `Mail/`，全局索引为 `global-messages-db.sqlite`。

## 六、常用工具
| 工具 | 用途 | 链接 |
|:---|:---|:---|
| dcfldd | 增强磁盘镜像 | https://sourceforge.net/projects/dcfldd/ |
| guymager | GUI 取证镜像 | https://guymager.sourceforge.io/ |
| FTK Imager | Windows 取证镜像/内存获取 | https://www.exterro.com/digital-forensics-software/ftk-imager |
| EnCase | 商业取证平台 | https://www.opentext.com/products/encase-forensic |
| libewf | E01 格式工具集 | https://github.com/libyal/libewf |
| Autopsy | 开源数字取证平台 | https://www.autopsy.com/ |
| Sleuth Kit | 命令行取证工具集 | https://www.sleuthkit.org/ |
| Plaso (log2timeline) | 超级取证时间线 | https://github.com/log2timeline/plaso |
| Volatility 3 | 内存取证框架 | https://github.com/volatilityfoundation/volatility3 |
| Volatility 2 | 内存取证（传统版） | https://github.com/volatilityfoundation/volatility |
| LiME | Linux 内存获取 | https://github.com/504ensicsLabs/LiME |
| WinPmem | Windows 内存获取 | https://github.com/veler/winpmem |
| AVML | Linux 内存获取（Microsoft） | https://github.com/microsoft/avml |
| MemProcFS | 文件系统式内存分析 | https://github.com/ufrisk/MemProcFS |
| KAPE | 取证工件收集 | https://www.kroll.com/en/services/cyber-security/incident-response-tools/kape |
| Hayabusa | 事件日志分析 | https://github.com/Yamato-Security/hayabusa |
| Eric Zimmerman Tools | Windows 取证工具集 | https://ericzimmerman.github.io/ |
| Velociraptor | 端点取证采集 | https://github.com/Velocidex/velociraptor |
| chkrootkit / rkhunter | Rootkit 检测 | https://www.chkrootkit.org/ |
| Photorec | 文件恢复 | https://www.cgsecurity.org/wiki/PhotoRec |
| Hindsight | 浏览器历史取证 | https://github.com/obsidianforensics/hindsight |
| DB Browser for SQLite | SQLite 数据库查看 | https://sqlitebrowser.org/ |
| readpst (libpst) | PST 转换工具 | https://www.five-ten-sg.com/libpst/ |
| oletools | OLE 文件分析 | https://github.com/decalage2/oletools |
## 七、参考资源
- [NIST SP 800-86 — Forensic Techniques](https://csrc.nist.gov/publications/detail/sp/800-86/final)
- [SANS Forensic Acquisition Guidelines](https://www.sans.org/white-papers/forensic-acquisition/)
- [SANS FOR500 — Windows Forensic Analysis](https://www.sans.org/for500/)
- [SANS FOR508 — Advanced Forensic Analysis](https://www.sans.org/for508/)
- [SANS FOR572 — Advanced Memory Forensics](https://www.sans.org/for572/)
- [Volatility 3 Documentation](https://volatility3.readthedocs.io/)
- [SANS Memory Forensics Cheat Sheet](https://www.sans.org/blog/memory-forensics-cheat-sheet/)
- [The Art of Memory Forensics（书籍）](https://www.amazon.com/Art-Memory-Forensics-Detecting-Malware/dp/1118825098)
- [Windows Forensic Artifacts — 13Cubed](https://www.13cubed.com/windows-forensic-artifacts)
- [ForensicArtifacts.com — 数字痕迹百科](https://forensicartifacts.com/)
- [DFIR Wizard — 取证速查表](https://www.dfirwizard.com/)
- [KAPE Documentation](https://kape.li/)

## 八、上游原文（references/）
| 上游文件 | 本包路径 |
|:---|:---|
| `README.md`（模块概述与关键工具） | `references/README.md` |
| `skills/磁盘镜像与证据获取-DiskImagingEvidenceAcquisition.md` | `references/磁盘镜像与证据获取-DiskImagingEvidenceAcquisition.md` |
| `skills/内存取证分析-Volatility-MemoryForensicsVolatility.md` | `references/内存取证分析-Volatility-MemoryForensicsVolatility.md` |
| `skills/Windows数字取证分析-WindowsDigitalForensics.md` | `references/Windows数字取证分析-WindowsDigitalForensics.md` |
| `skills/Linux数字取证分析-LinuxDigitalForensics.md` | `references/Linux数字取证分析-LinuxDigitalForensics.md` |
| `skills/浏览器与邮件取证-BrowserEmailForensics.md` | `references/浏览器与邮件取证-BrowserEmailForensics.md` |