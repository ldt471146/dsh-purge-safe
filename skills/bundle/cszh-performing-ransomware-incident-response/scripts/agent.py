#!/usr/bin/env python3
"""勒索软件事件响应 Agent — 在勒索软件事件期间自动执行初始分类、IOC 采集和遏制措施。"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path


RANSOMWARE_EXTENSIONS = {
    ".encrypted", ".locked", ".crypt", ".cry", ".crypto", ".enc",
    ".locky", ".cerber", ".zepto", ".wncry", ".wnry", ".wcry",
    ".onion", ".aaa", ".abc", ".xyz", ".zzz", ".micro", ".r5a",
}

RANSOM_NOTE_PATTERNS = [
    "readme.txt", "how_to_decrypt.txt", "decrypt_instructions.html",
    "restore_files.txt", "help_decrypt.html", "recovery.txt",
    "_readme.txt", "how_to_recover.txt",
]


def scan_encrypted_files(target_dir: str, max_files: int = 5000) -> list[dict]:
    """扫描目录中带有勒索软件相关扩展名的文件。"""
    findings = []
    count = 0
    for root, dirs, files in os.walk(target_dir):
        for fname in files:
            if count >= max_files:
                return findings
            fpath = os.path.join(root, fname)
            ext = os.path.splitext(fname)[1].lower()
            if ext in RANSOMWARE_EXTENSIONS:
                try:
                    stat = os.stat(fpath)
                    findings.append({
                        "path": fpath,
                        "extension": ext,
                        "size_bytes": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    })
                except OSError:
                    pass
                count += 1
    return findings


def find_ransom_notes(target_dir: str) -> list[dict]:
    """搜索已知勒索信文件名。"""
    notes = []
    for root, dirs, files in os.walk(target_dir):
        for fname in files:
            if fname.lower() in RANSOM_NOTE_PATTERNS:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read(2048)
                    notes.append({"path": fpath, "preview": content[:500]})
                except OSError:
                    notes.append({"path": fpath, "preview": "[不可读]"})
    return notes


def collect_file_hashes(file_paths: list[str], max_hash: int = 100) -> list[dict]:
    """计算 SHA-256 哈希值用于 IOC 提交。"""
    hashes = []
    for fpath in file_paths[:max_hash]:
        try:
            sha = hashlib.sha256()
            with open(fpath, "rb") as fh:
                for chunk in iter(lambda: fh.read(8192), b""):
                    sha.update(chunk)
            hashes.append({"path": fpath, "sha256": sha.hexdigest()})
        except OSError:
            pass
    return hashes


def check_shadow_copies(platform: str = sys.platform) -> dict:
    """检查卷影副本是否完整（Windows）或快照是否存在。"""
    if platform == "win32":
        try:
            result = subprocess.run(
                ["vssadmin", "list", "shadows"],
                capture_output=True, text=True, timeout=30
            )
            shadow_count = result.stdout.count("Shadow Copy ID")
            return {"platform": "windows", "shadow_copies": shadow_count,
                    "intact": shadow_count > 0, "raw": result.stdout[:1000]}
        except (subprocess.SubprocessError, FileNotFoundError):
            return {"platform": "windows", "shadow_copies": 0, "intact": False, "error": "vssadmin 不可用"}
    return {"platform": platform, "shadow_copies": -1, "intact": False, "note": "需要手动检查"}


def generate_containment_actions(encrypted_count: int, notes_found: int) -> list[dict]:
    """根据发现结果生成建议的遏制措施。"""
    actions = [
        {"priority": 1, "action": "立即将受影响主机从网络隔离",
         "detail": "禁用网络适配器或迁移到隔离 VLAN"},
        {"priority": 2, "action": "修复前保全取证证据",
         "detail": "对受影响系统创建磁盘镜像"},
        {"priority": 3, "action": "重置所有特权账号的凭据",
         "detail": "包括 krbtgt、服务账号和域管理员"},
    ]
    if encrypted_count > 100:
        actions.append({"priority": 4, "action": "启动业务连续性计划",
                        "detail": f"检测到 {encrypted_count} 个加密文件 — 数据影响重大"})
    if notes_found > 0:
        actions.append({"priority": 5, "action": "采集并分析勒索信以识别变体",
                        "detail": "提交到 ID Ransomware（id-ransomware.malwarehunterteam.com）"})
    return actions


def generate_report(target_dir: str, max_files: int) -> dict:
    """运行所有检测项并构建综合事件报告。"""
    encrypted = scan_encrypted_files(target_dir, max_files)
    notes = find_ransom_notes(target_dir)
    file_hashes = collect_file_hashes([f["path"] for f in encrypted[:50]])
    shadow_status = check_shadow_copies()
    actions = generate_containment_actions(len(encrypted), len(notes))

    return {
        "report": "ransomware_incident_response",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "target_directory": target_dir,
        "encrypted_files_found": len(encrypted),
        "ransom_notes_found": len(notes),
        "shadow_copy_status": shadow_status,
        "containment_actions": actions,
        "encrypted_files_sample": encrypted[:20],
        "ransom_notes": notes[:10],
        "file_hashes": file_hashes,
    }


def main():
    parser = argparse.ArgumentParser(description="勒索软件事件响应 Agent")
    parser.add_argument("--target", required=True, help="扫描勒索软件产物的目录")
    parser.add_argument("--max-files", type=int, default=5000, help="最大扫描文件数（默认：5000）")
    parser.add_argument("--output", help="输出 JSON 文件路径")
    args = parser.parse_args()

    report = generate_report(args.target, args.max_files)
    output = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"报告已写入 {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
