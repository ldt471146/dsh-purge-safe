# API 参考：dd 和 dcfldd 磁盘镜像

## dd - 标准 Unix 磁盘复制工具

### 核心语法
```bash
dd if=<source> of=<destination> [options]
```

### 主要选项
| 参数 | 描述 | 示例 |
|------|------|------|
| `if=` | 输入文件（源设备） | `if=/dev/sdb` |
| `of=` | 输出文件（目标镜像） | `of=evidence.dd` |
| `bs=` | 读写块大小 | `bs=4096`（取证标准） |
| `count=` | 要复制的块数量 | `count=1024` |
| `skip=` | 从输入起始跳过 N 个块 | `skip=2048` |
| `conv=` | 转换选项 | `conv=noerror,sync` |
| `status=` | 传输统计级别 | `status=progress` |

### conv= 值说明
- `noerror` - 读取错误时继续（不中止）
- `sync` - 错误时用零填充输入块（保持偏移对齐）
- `notrunc` - 不截断输出文件

### 输出格式
```
500107862016 bytes (500 GB, 466 GiB) copied, 8132.45 s, 61.5 MB/s
976773168+0 records in
976773168+0 records out
```

## dcfldd - DoD 取证版 dd

### 核心语法
```bash
dcfldd if=<source> of=<destination> [options]
```

### 扩展选项
| 参数 | 描述 | 示例 |
|------|------|------|
| `hash=` | 哈希算法 | `hash=sha256,md5` |
| `hashlog=` | 哈希输出文件 | `hashlog=hashes.txt` |
| `hashwindow=` | 每 N 字节计算一次哈希 | `hashwindow=1G` |
| `hashconv=` | 转换前或转换后计算哈希 | `hashconv=after` |
| `errlog=` | 错误日志文件 | `errlog=errors.log` |
| `split=` | 将输出分割成块 | `split=2G` |
| `splitformat=` | 分割文件的后缀格式 | `splitformat=aa` |
| `vf=` | 验证文件 | `vf=evidence.dd` |
| `verifylog=` | 验证结果日志 | `verifylog=verify.log` |

### 输出格式
```
Total (sha256): a3f2b8c9d4e5f6a7b8c9d0e1f2a3b4c5...
1024+0 records in
1024+0 records out
```

## sha256sum - 哈希验证

### 语法
```bash
sha256sum <file_or_device>
sha256sum -c <checksum_file>
```

### 输出格式
```
a3f2b8c9d4e5f6...  /dev/sdb
a3f2b8c9d4e5f6...  evidence.dd
```

## blockdev - 写保护

### 语法
```bash
blockdev --setro <device>   # 设置只读
blockdev --setrw <device>   # 设置读写
blockdev --getro <device>   # 检查：1=只读, 0=读写
blockdev --getsize64 <device>  # 以字节为单位的大小
```

## lsblk - 块设备枚举

### 语法
```bash
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,MODEL,SERIAL,RO
lsblk -J   # JSON 输出
lsblk -p   # 完整设备路径
```

## hdparm - 驱动器识别

### 语法
```bash
hdparm -I <device>   # 详细驱动器信息
hdparm -i <device>   # 摘要识别信息
```
