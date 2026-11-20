# API 参考：Docker 容器取证工具

## docker inspect - 容器详情

### 语法
```bash
docker inspect <container_id>
docker inspect --format '{{.HostConfig.Privileged}}' <container_id>
docker inspect --format '{{json .Mounts}}' <container_id> | jq
docker inspect --format '{{.GraphDriver.Data.MergedDir}}' <container_id>
```

### 关键 JSON 路径
| 路径 | 描述 |
|------|------|
| `.HostConfig.Privileged` | 特权模式状态 |
| `.HostConfig.CapAdd` | 已添加的能力 |
| `.HostConfig.PidMode` | PID 命名空间模式 |
| `.HostConfig.NetworkMode` | 网络命名空间模式 |
| `.Mounts` | 卷挂载配置 |
| `.Config.User` | 容器用户 |
| `.Config.Env` | 环境变量 |
| `.Config.Image` | 来源镜像名称 |
| `.State.StartedAt` | 容器启动时间 |

## docker diff - 文件系统变更

### 语法
```bash
docker diff <container_id>
```

### 输出代码
| 代码 | 含义 |
|------|------|
| `A` | 文件或目录已新增 |
| `C` | 文件或目录已变更 |
| `D` | 文件或目录已删除 |

## docker export - 容器文件系统导出

### 语法
```bash
docker export <container_id> > container_fs.tar
docker export <container_id> | gzip > container_fs.tar.gz
```

## docker commit / docker save - 镜像保全

### 语法
```bash
docker commit <container_id> forensic-evidence:case001
docker save forensic-evidence:case001 > evidence_image.tar
```

## docker logs - 容器日志获取

### 语法
```bash
docker logs --timestamps <container_id>
docker logs --since 2024-01-15 <container_id>
docker logs --tail 1000 <container_id>
docker logs -f <container_id>   # 实时跟踪
```

## dive - 镜像层分析

### 语法
```bash
dive <image_name>                      # 交互模式
dive <image_name> --ci                 # CI 模式（非交互）
dive <image_name> --ci --json out.json # JSON 输出
```

### 输出内容
- 逐层文件系统变更
- 镜像效率评分
- 浪费空间分析

## container-diff - 镜像比较

### 语法
```bash
container-diff diff daemon://nginx:latest daemon://suspect:latest \
  --type=file --type=apt --type=history --json
```

### 差异类型
| 类型 | 描述 |
|------|------|
| `file` | 文件系统差异 |
| `apt` | APT 包差异 |
| `pip` | Python 包差异 |
| `history` | Docker 构建历史差异 |

## Trivy - 漏洞扫描

### 语法
```bash
trivy image <image_name>
trivy image --format json <image_name>
trivy image --scanners vuln,secret <image_name>
trivy fs /path/to/exported/container/
```

### 严重级别
`CRITICAL`（严重）| `HIGH`（高危）| `MEDIUM`（中危）| `LOW`（低危）| `UNKNOWN`（未知）

## docker-explorer - 离线取证

### 语法
```bash
de.py -r /var/lib/docker list
de.py -r /var/lib/docker mount <container_id> /mnt/forensic
de.py -r /var/lib/docker history <container_id>
```
