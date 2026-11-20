---
name: cszh-analyzing-docker-container-forensics
description: 通过分析镜像、层、卷、日志和运行时痕迹，调查受损的 Docker 容器，识别恶意活动和证据。
---

> 来源：killvxk/cybersecurity-skills-zh 上游技能 `analyzing-docker-container-forensics`，正文为中文原文照录（仅剥离上游 frontmatter）。
> 定位：分析 Docker 容器取证。
> 用法：按正文的「工作流程 / 命令清单 / 输出格式」执行；本技能在 dsh 中的名字是 cszh-analyzing-docker-container-forensics。

# 分析 Docker 容器取证

## 适用场景
- 调查受损的 Docker 容器或容器主机时
- 分析从注册表拉取的恶意 Docker 镜像时
- 涉及容器化应用程序漏洞的事件响应（Incident Response）期间
- 检查容器逃逸尝试或权限提升（Privilege Escalation）时
- 审计容器配置并识别错误配置时

## 前置条件
- 取证工作站上的 Docker CLI 访问权限
- 访问 Docker 主机文件系统（取证镜像或实时系统）
- 了解 Docker 分层文件系统（overlay2、aufs）
- 用于镜像分析的 dive、docker-explorer 或 container-diff
- 了解 Docker 守护进程配置和 socket 安全
- 用于容器镜像漏洞扫描的 Trivy 或 Grype

## 工作流程

### 步骤 1：保全容器状态和证据

```bash
# 列出所有容器（包括已停止的）
docker ps -a --no-trunc > /cases/case-2024-001/docker/container_list.txt

# 检查受损容器
CONTAINER_ID="abc123def456"
docker inspect $CONTAINER_ID > /cases/case-2024-001/docker/container_inspect.json

# 将容器文件系统导出为 tarball（保留当前状态）
docker export $CONTAINER_ID > /cases/case-2024-001/docker/container_export.tar

# 从容器当前状态创建镜像
docker commit $CONTAINER_ID forensic-evidence:case-2024-001
docker save forensic-evidence:case-2024-001 > /cases/case-2024-001/docker/container_image.tar

# 捕获容器日志
docker logs $CONTAINER_ID --timestamps > /cases/case-2024-001/docker/container_logs.txt 2>&1

# 捕获运行中的进程（如果容器仍在运行）
docker top $CONTAINER_ID > /cases/case-2024-001/docker/container_processes.txt

# 捕获网络连接
docker exec $CONTAINER_ID netstat -tlnp 2>/dev/null > /cases/case-2024-001/docker/container_network.txt

# 从容器复制特定文件
docker cp $CONTAINER_ID:/var/log/ /cases/case-2024-001/docker/container_var_log/
docker cp $CONTAINER_ID:/tmp/ /cases/case-2024-001/docker/container_tmp/
docker cp $CONTAINER_ID:/etc/passwd /cases/case-2024-001/docker/container_passwd

# 对所有导出证据进行哈希计算
sha256sum /cases/case-2024-001/docker/*.tar > /cases/case-2024-001/docker/evidence_hashes.txt
```

### 步骤 2：分析容器镜像层

```bash
# 安装 dive 用于镜像层分析
wget https://github.com/wagoodman/dive/releases/latest/download/dive_linux_amd64.deb
sudo dpkg -i dive_linux_amd64.deb

# 交互式分析镜像层
dive forensic-evidence:case-2024-001

# 非交互式层分析
dive forensic-evidence:case-2024-001 --ci --json /cases/case-2024-001/docker/dive_analysis.json

# 提取并检查单个层
mkdir -p /cases/case-2024-001/docker/layers/
tar -xf /cases/case-2024-001/docker/container_image.tar -C /cases/case-2024-001/docker/layers/

# 列出镜像清单和层顺序
cat /cases/case-2024-001/docker/layers/manifest.json | python3 -m json.tool

# 检查每一层的变更
for layer in /cases/case-2024-001/docker/layers/*/layer.tar; do
    echo "=== 层: $(dirname $layer | xargs basename) ==="
    tar -tf "$layer" | head -20
    echo "..."
done

# 使用 container-diff 与原始基础镜像进行比较
# 安装 container-diff
curl -LO https://storage.googleapis.com/container-diff/latest/container-diff-linux-amd64
chmod +x container-diff-linux-amd64

# 将提交的镜像与原始镜像进行比较
./container-diff-linux-amd64 diff daemon://nginx:latest daemon://forensic-evidence:case-2024-001 \
   --type=file --type=apt --type=history --json \
   > /cases/case-2024-001/docker/container_diff.json
```

### 步骤 3：检查 Docker 主机痕迹

```bash
# Docker 数据目录（默认: /var/lib/docker/）
DOCKER_ROOT="/mnt/evidence/var/lib/docker"

# 检查 overlay2 文件系统层
ls -la $DOCKER_ROOT/overlay2/

# 查找容器的合并文件系统
CONTAINER_HASH=$(docker inspect $CONTAINER_ID --format '{{.GraphDriver.Data.MergedDir}}' 2>/dev/null)
# 或从取证镜像手动查找:
# 查看 /var/lib/docker/containers/<container_id>/config.v2.json

# 分析容器配置文件
cat $DOCKER_ROOT/containers/$CONTAINER_ID/config.v2.json | python3 -m json.tool \
   > /cases/case-2024-001/docker/container_config.json

# 检查 Docker 守护进程配置
cat /mnt/evidence/etc/docker/daemon.json 2>/dev/null > /cases/case-2024-001/docker/daemon_config.json

# 检查 Docker 事件日志
cat $DOCKER_ROOT/containers/$CONTAINER_ID/*.log > /cases/case-2024-001/docker/container_json_logs.txt

# 检查卷挂载（可能的主机文件系统访问）
python3 << 'PYEOF'
import json

with open('/cases/case-2024-001/docker/container_inspect.json') as f:
    data = json.load(f)

inspect = data[0] if isinstance(data, list) else data

print("=== 容器安全分析 ===\n")

# 检查挂载点
print("卷挂载:")
for mount in inspect.get('Mounts', []):
    rw = "读写" if mount.get('RW') else "只读"
    print(f"  {mount.get('Source', 'N/A')} -> {mount.get('Destination', 'N/A')} ({rw})")
    if mount.get('Source') in ('/', '/etc', '/var', '/root') and mount.get('RW'):
        print(f"    警告: 敏感主机路径以读写方式挂载!")

# 检查特权模式
host_config = inspect.get('HostConfig', {})
if host_config.get('Privileged'):
    print("\n警告: 容器以特权（PRIVILEGED）模式运行!")

# 检查能力
cap_add = host_config.get('CapAdd', [])
if cap_add:
    print(f"\n已添加能力: {cap_add}")
    dangerous_caps = ['SYS_ADMIN', 'SYS_PTRACE', 'NET_ADMIN', 'SYS_MODULE']
    for cap in cap_add:
        if cap in dangerous_caps:
            print(f"  警告: 危险能力: {cap}")

# 检查 PID 命名空间
if host_config.get('PidMode') == 'host':
    print("\n警告: 容器共享主机 PID 命名空间!")

# 检查网络模式
if host_config.get('NetworkMode') == 'host':
    print("\n警告: 容器共享主机网络命名空间!")

# 检查用户
user = inspect.get('Config', {}).get('User', 'root（默认）')
print(f"\n运行用户: {user}")

# 检查环境变量中的敏感信息
env_vars = inspect.get('Config', {}).get('Env', [])
print(f"\n环境变量: {len(env_vars)} 个")
for env in env_vars:
    key = env.split('=')[0]
    if any(s in key.upper() for s in ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'CREDENTIAL']):
        print(f"  敏感: {key}=***已隐藏***")
PYEOF
```

### 步骤 4：分析容器文件系统变更

```bash
# 比较容器文件系统与原始镜像
docker diff $CONTAINER_ID > /cases/case-2024-001/docker/filesystem_changes.txt

# A = 新增, C = 变更, D = 删除
# 分析变更
python3 << 'PYEOF'
added = []
changed = []
deleted = []

with open('/cases/case-2024-001/docker/filesystem_changes.txt') as f:
    for line in f:
        line = line.strip()
        if line.startswith('A '):
            added.append(line[2:])
        elif line.startswith('C '):
            changed.append(line[2:])
        elif line.startswith('D '):
            deleted.append(line[2:])

print(f"新增文件: {len(added)}")
print(f"变更文件: {len(changed)}")
print(f"删除文件: {len(deleted)}")

# 标记可疑新增文件
suspicious = [f for f in added if any(s in f for s in
    ['/tmp/', '/dev/shm/', '/root/', '.sh', '.py', '.elf', 'reverse', 'shell', 'backdoor'])]
if suspicious:
    print(f"\n可疑新增文件:")
    for f in suspicious:
        print(f"  {f}")

# 标记可疑变更文件
sus_changed = [f for f in changed if any(s in f for s in
    ['/etc/passwd', '/etc/shadow', '/etc/crontab', '/etc/ssh', '.bashrc'])]
if sus_changed:
    print(f"\n可疑变更文件:")
    for f in sus_changed:
        print(f"  {f}")
PYEOF

# 提取并检查容器导出内容
mkdir -p /cases/case-2024-001/docker/container_fs/
tar -xf /cases/case-2024-001/docker/container_export.tar -C /cases/case-2024-001/docker/container_fs/

# 扫描 Webshell 和恶意文件
find /cases/case-2024-001/docker/container_fs/tmp/ -type f -exec file {} \;
find /cases/case-2024-001/docker/container_fs/ -name "*.php" -newer /cases/case-2024-001/docker/container_fs/etc/hostname
```

### 步骤 5：扫描漏洞并生成报告

```bash
# 扫描镜像中的已知漏洞
trivy image forensic-evidence:case-2024-001 \
   --format json \
   --output /cases/case-2024-001/docker/vulnerability_scan.json

# 扫描导出的文件系统
trivy fs /cases/case-2024-001/docker/container_fs/ \
   --format table \
   --output /cases/case-2024-001/docker/fs_vulnerabilities.txt

# 检查镜像中的敏感信息
trivy image forensic-evidence:case-2024-001 \
   --scanners secret \
   --format json \
   --output /cases/case-2024-001/docker/secrets_scan.json
```

## 核心概念

| 概念 | 定义 |
|------|------|
| 镜像层（Image layers） | 堆叠形成容器镜像的只读文件系统层 |
| overlay2 | 使用联合文件系统实现层的默认 Docker 存储驱动 |
| 容器差异（Container diff） | 运行时文件系统变更与原始镜像的比较 |
| 特权模式（Privileged mode） | 拥有完整主机能力的容器（绕过大多数隔离） |
| Docker socket | 控制 Docker 守护进程的 Unix socket（/var/run/docker.sock） |
| 容器逃逸（Container escape） | 从容器隔离中突破到主机的技术 |
| 卷挂载（Volume mounts） | 在容器内可访问的主机文件系统路径 |
| 镜像历史（Image history） | 用于构建每个层的 Dockerfile 指令记录 |

## 工具与系统

| 工具 | 用途 |
|------|------|
| docker inspect | 详细的容器配置和状态信息 |
| docker diff | 显示运行中/已停止容器中的文件系统变更 |
| dive | 交互式 Docker 镜像层分析工具 |
| container-diff | 用于比较容器镜像内容的 Google 工具 |
| Trivy | 容器镜像和文件系统的漏洞扫描器 |
| docker-explorer | 用于离线 Docker 痕迹分析的取证工具 |
| Sysdig | 容器运行时安全监控和取证 |
| Falco | 用于容器和 Kubernetes 的运行时威胁检测 |

## 常见场景

**场景：Web 应用程序容器被入侵**
导出容器文件系统，识别 Web 根目录中的 Webshell，分析访问日志中的利用尝试，检查新增文件和被修改的配置，检查用于 C2 通信的网络连接，审查容器能力以发现提权路径。

**场景：通过恶意镜像实施供应链攻击（Supply Chain Attack）**
使用 dive 分析镜像层以识别哪一层添加了恶意内容，使用 container-diff 与官方基础镜像进行比较，检查镜像历史中可疑的 RUN 命令，扫描嵌入的后门和加密货币矿工，从注册表日志追踪镜像拉取。

**场景：容器逃逸调查**
检查容器是否以特权或危险能力运行，检查主机文件系统挂载点是否有未经授权的访问，审查启用 Docker-in-Docker 滥用的 Docker socket 挂载，分析主机系统日志中的容器逃逸指标，检查内核利用痕迹。

**场景：容器环境中的加密劫持（Cryptojacking）**
识别高 CPU 占用的容器，导出并分析容器镜像中的挖矿二进制文件，检查注册表中是否有未授权镜像，审查容器创建事件中的流氓部署，检查用于矿池通信的网络连接。

## 输出格式

```
Docker 容器取证摘要:
  容器: abc123def456 (nginx-app)
  镜像: company/web-app:v2.1
  状态: 运行中（启动于 2024-01-10 09:00 UTC）
  主机: docker-host-01.corp.local

  安全配置:
    特权模式: 否
    已添加能力: NET_ADMIN（警告）
    卷挂载: /var/log -> /host-logs（读写）
    网络模式: bridge
    运行用户: root（警告）

  文件系统变更:
    新增: 23 个文件（5 个可疑）
    变更: 12 个文件（2 个可疑）
    删除: 0 个文件

  可疑发现:
    /tmp/reverse.sh - 反向 shell 脚本（新增）
    /var/www/html/.hidden/shell.php - PHP Webshell（新增）
    /etc/crontab - 已修改（添加了持久化 cron 条目）
    /root/.ssh/authorized_keys - 已修改（添加了未授权密钥）

  漏洞扫描:
    严重: 3 个（基础镜像中的 CVE-2024-xxxx）
    高危: 12 个
    中危: 34 个

  证据: /cases/case-2024-001/docker/
```
