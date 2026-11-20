#!/usr/bin/env python3
"""
磁盘取证调查 Agent
使用 pytsk3 和 hashlib 进行磁盘取证分析，包括镜像验证、文件系统解析、
已删除文件恢复和时间线生成，以确保证据完整性。
"""

import csv
import hashlib
import json
import os
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import pytsk3
    HAS_PYTSK3 = True
except ImportError:
    HAS_PYTSK3 = False


def verify_image_integrity(image_path: str) -> dict:
    """计算并验证取证磁盘镜像的哈希值。"""
    if not os.path.exists(image_path):
        return {"error": f"镜像未找到: {image_path}"}

    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    size = 0

    with open(image_path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            md5.update(chunk)
            sha256.update(chunk)
            size += len(chunk)

    return {
        "image_path": image_path,
        "size_bytes": size,
        "size_gb": round(size / (1024**3), 2),
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest(),
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }


def parse_filesystem_pytsk3(image_path: str) -> dict:
    """使用 pytsk3 从磁盘镜像解析文件系统。"""
    if not HAS_PYTSK3:
        return {"error": "pytsk3 未安装。使用 pip install pytsk3 安装"}

    try:
        img = pytsk3.Img_Info(image_path)
        fs = pytsk3.FS_Info(img)
    except Exception as e:
        return {"error": f"打开镜像失败: {e}"}

    fs_info = {
        "fs_type": str(fs.info.ftype),
        "block_size": fs.info.block_size,
        "block_count": fs.info.block_count,
        "total_size_gb": round(fs.info.block_size * fs.info.block_count / (1024**3), 2),
    }

    return fs_info


def list_files_pytsk3(image_path: str, directory: str = "/") -> list[dict]:
    """列出磁盘镜像中指定目录的文件。"""
    if not HAS_PYTSK3:
        return [{"error": "pytsk3 未安装"}]

    try:
        img = pytsk3.Img_Info(image_path)
        fs = pytsk3.FS_Info(img)
        dir_obj = fs.open_dir(directory)
    except Exception as e:
        return [{"error": str(e)}]

    files = []
    for entry in dir_obj:
        name = entry.info.name.name.decode("utf-8", errors="ignore")
        if name in (".", ".."):
            continue

        meta = entry.info.meta
        if meta:
            files.append({
                "name": name,
                "type": "directory" if meta.type == pytsk3.TSK_FS_META_TYPE_DIR else "file",
                "size": meta.size,
                "created": datetime.fromtimestamp(meta.crtime, tz=timezone.utc).isoformat() if meta.crtime else "",
                "modified": datetime.fromtimestamp(meta.mtime, tz=timezone.utc).isoformat() if meta.mtime else "",
                "accessed": datetime.fromtimestamp(meta.atime, tz=timezone.utc).isoformat() if meta.atime else "",
                "inode": meta.addr,
                "flags": str(meta.flags),
            })

    return files


def find_deleted_files(image_path: str) -> list[dict]:
    """在磁盘镜像中搜索已删除文件。"""
    if not HAS_PYTSK3:
        return [{"error": "pytsk3 未安装"}]

    try:
        img = pytsk3.Img_Info(image_path)
        fs = pytsk3.FS_Info(img)
    except Exception as e:
        return [{"error": str(e)}]

    deleted = []

    def walk_directory(dir_obj, path="/"):
        for entry in dir_obj:
            name = entry.info.name.name.decode("utf-8", errors="ignore")
            if name in (".", ".."):
                continue

            meta = entry.info.meta
            if meta and meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC:
                deleted.append({
                    "name": name,
                    "path": f"{path}{name}",
                    "size": meta.size,
                    "deleted_approx": datetime.fromtimestamp(
                        meta.mtime, tz=timezone.utc
                    ).isoformat() if meta.mtime else "",
                    "inode": meta.addr,
                    "recoverable": meta.size > 0,
                })

            if meta and meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                try:
                    sub_dir = fs.open_dir(inode=meta.addr)
                    walk_directory(sub_dir, f"{path}{name}/")
                except Exception:
                    pass

    try:
        root = fs.open_dir("/")
        walk_directory(root)
    except Exception as e:
        deleted.append({"error": str(e)})

    return deleted


def parse_mft_entries(mft_path: str) -> list[dict]:
    """从导出的 $MFT 文件解析 MFT 条目，用于 NTFS 分析。"""
    entries = []
    if not os.path.exists(mft_path):
        return [{"error": f"MFT 文件未找到: {mft_path}"}]

    with open(mft_path, "rb") as f:
        entry_size = 1024
        entry_num = 0
        while True:
            data = f.read(entry_size)
            if len(data) < entry_size:
                break

            if data[:4] == b"FILE":
                flags = struct.unpack_from("<H", data, 22)[0]
                is_deleted = not (flags & 0x01)
                is_directory = bool(flags & 0x02)

                entries.append({
                    "entry_number": entry_num,
                    "is_deleted": is_deleted,
                    "is_directory": is_directory,
                    "flags": flags,
                })

            entry_num += 1
            if entry_num >= 10000:
                break

    total = len(entries)
    deleted = sum(1 for e in entries if e["is_deleted"])

    return entries[:100] if len(entries) > 100 else entries


def build_timeline(files: list[dict]) -> list[dict]:
    """从文件元数据构建文件系统活动时间线。"""
    events = []

    for f in files:
        if isinstance(f, dict) and "error" not in f:
            if f.get("created"):
                events.append({"timestamp": f["created"], "event": "created", "path": f.get("name", "")})
            if f.get("modified"):
                events.append({"timestamp": f["modified"], "event": "modified", "path": f.get("name", "")})
            if f.get("accessed"):
                events.append({"timestamp": f["accessed"], "event": "accessed", "path": f.get("name", "")})

    events.sort(key=lambda x: x.get("timestamp", ""))
    return events


def generate_report(
    integrity: dict, fs_info: dict, files: list, deleted: list, timeline: list
) -> str:
    """生成磁盘取证调查报告。"""
    lines = [
        "磁盘取证调查报告",
        "=" * 50,
        f"日期: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "镜像完整性：",
        f"  镜像: {integrity.get('image_path', 'N/A')}",
        f"  大小: {integrity.get('size_gb', 'N/A')} GB",
        f"  MD5: {integrity.get('md5', 'N/A')}",
        f"  SHA-256: {integrity.get('sha256', 'N/A')}",
        "",
        "文件系统：",
        f"  类型: {fs_info.get('fs_type', 'N/A')}",
        f"  总大小: {fs_info.get('total_size_gb', 'N/A')} GB",
        "",
        f"发现文件数: {len(files)}",
        f"已删除文件: {len([d for d in deleted if d.get('recoverable')])} 个可恢复",
        f"时间线事件: {len(timeline)}",
    ]

    if deleted:
        lines.extend(["", "已删除文件（示例）："])
        for d in deleted[:10]:
            if "error" not in d:
                lines.append(f"  {d.get('path', 'N/A')} ({d.get('size', 0)} 字节)")

    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} <磁盘镜像路径> [mft路径]")
        sys.exit(1)

    image_path = sys.argv[1]
    mft_path = sys.argv[2] if len(sys.argv) > 2 else None

    print(f"[*] 验证镜像完整性: {image_path}")
    integrity = verify_image_integrity(image_path)
    print(f"[*] SHA-256: {integrity.get('sha256', '错误')}")

    print("[*] 解析文件系统...")
    fs_info = parse_filesystem_pytsk3(image_path)

    print("[*] 列出文件...")
    files = list_files_pytsk3(image_path)

    print("[*] 搜索已删除文件...")
    deleted = find_deleted_files(image_path)

    timeline = build_timeline(files)

    report = generate_report(integrity, fs_info, files, deleted, timeline)
    print(report)

    output = f"disk_forensics_{datetime.now(timezone.utc).strftime('%Y%m%d')}.json"
    with open(output, "w") as f:
        json.dump({"integrity": integrity, "fs_info": fs_info, "deleted_files": deleted,
                    "timeline": timeline[:100]}, f, indent=2)
    print(f"\n[*] 结果已保存到 {output}")
