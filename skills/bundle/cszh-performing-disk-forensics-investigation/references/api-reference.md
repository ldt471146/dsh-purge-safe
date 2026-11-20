# API 参考：磁盘取证调查

## pytsk3 库（The Sleuth Kit Python 绑定）

| 类/方法 | 说明 |
|---------|------|
| `pytsk3.Img_Info(path)` | 打开磁盘镜像（raw、E01、AFF） |
| `pytsk3.FS_Info(img_info)` | 从镜像解析文件系统 |
| `fs.open_dir(path)` | 打开目录以列出内容 |
| `fs.open_file(path)` | 打开文件以读取内容 |
| `entry.info.meta` | 访问文件元数据（时间戳、大小、标志） |
| `TSK_FS_META_FLAG_UNALLOC` | 表示已删除/未分配文件的标志 |

## 文件元数据字段

| 字段 | 说明 |
|------|------|
| `meta.crtime` | 文件创建时间（NTFS） |
| `meta.mtime` | 最后修改时间 |
| `meta.atime` | 最后访问时间 |
| `meta.ctime` | 元数据变更时间 |
| `meta.size` | 文件大小（字节） |
| `meta.addr` | Inode/MFT 条目编号 |
| `meta.flags` | 分配标志 |

## NTFS MFT 结构

| 偏移量 | 大小 | 说明 |
|--------|------|------|
| 0x00 | 4 字节 | 签名（"FILE"） |
| 0x16 | 2 字节 | 标志（使用中、目录） |
| 0x1C | 4 字节 | MFT 条目的实际大小 |

## 关键库

- **pytsk3**（`pip install pytsk3`）：The Sleuth Kit 的 Python 绑定
- **dfvfs**（`pip install dfvfs`）：数字取证虚拟文件系统
- **hashlib**（标准库）：镜像完整性验证（MD5、SHA-256）
- **struct**（标准库）：解析二进制 MFT 条目头部

## CLI 工具（参考）

| 工具 | 说明 |
|------|------|
| `fls -r image.dd` | 递归列出文件（TSK） |
| `icat image.dd inode` | 按 inode 编号提取文件 |
| `mmls image.dd` | 列出磁盘分区 |
| `fsstat image.dd` | 文件系统统计信息 |

## 配置

| 变量 | 说明 |
|------|------|
| 镜像路径 | 取证磁盘镜像路径（dd、E01、AFF） |
| MFT 导出 | 导出的 $MFT 文件，用于 NTFS 专项分析 |

## 参考资料

- The Sleuth Kit：https://www.sleuthkit.org/
- pytsk3 文档：https://github.com/py4n6/pytsk
- Autopsy 数字取证：https://www.autopsy.com/
- SANS 取证海报：https://www.sans.org/posters/windows-forensic-analysis/
