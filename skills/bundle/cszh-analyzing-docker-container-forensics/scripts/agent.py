#!/usr/bin/env python3
"""用于调查受损容器的 Docker 容器取证 Agent。"""

import subprocess
import json
import os
import sys
import hashlib
import datetime


def run_cmd(cmd):
    """执行 shell 命令并返回输出。"""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def list_containers(all_containers=True):
    """列出 Docker 容器及详细信息。"""
    flags = "-a" if all_containers else ""
    cmd = f"docker ps {flags} --no-trunc --format '{{{{json .}}}}'"
    stdout, _, rc = run_cmd(cmd)
    containers = []
    if rc == 0 and stdout:
        for line in stdout.splitlines():
            try:
                containers.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return containers


def inspect_container(container_id):
    """获取详细的容器检查数据。"""
    stdout, _, rc = run_cmd(f"docker inspect {container_id}")
    if rc == 0 and stdout:
        return json.loads(stdout)
    return None


def analyze_security_config(inspect_data):
    """分析容器安全配置中的错误配置。"""
    if isinstance(inspect_data, list):
        inspect_data = inspect_data[0]
    findings = []
    host_config = inspect_data.get("HostConfig", {})
    config = inspect_data.get("Config", {})

    if host_config.get("Privileged"):
        findings.append({"severity": "严重", "finding": "容器以特权（PRIVILEGED）模式运行"})

    cap_add = host_config.get("CapAdd") or []
    dangerous_caps = ["SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "SYS_MODULE",
                      "DAC_OVERRIDE", "NET_RAW"]
    for cap in cap_add:
        if cap in dangerous_caps:
            findings.append({"severity": "高危", "finding": f"已添加危险能力: {cap}"})

    if host_config.get("PidMode") == "host":
        findings.append({"severity": "高危", "finding": "共享主机 PID 命名空间"})

    if host_config.get("NetworkMode") == "host":
        findings.append({"severity": "高危", "finding": "共享主机网络命名空间"})

    mounts = inspect_data.get("Mounts", [])
    sensitive_paths = ["/", "/etc", "/var", "/root", "/home", "/var/run/docker.sock"]
    for mount in mounts:
        src = mount.get("Source", "")
        rw = mount.get("RW", False)
        if src in sensitive_paths and rw:
            findings.append({
                "severity": "严重",
                "finding": f"敏感主机路径以读写方式挂载: {src} -> {mount.get('Destination')}"
            })
        if "docker.sock" in src:
            findings.append({
                "severity": "严重",
                "finding": "已挂载 Docker socket（容器可控制 Docker 守护进程）"
            })

    user = config.get("User", "")
    if not user or user == "root":
        findings.append({"severity": "中危", "finding": "以 root 用户运行"})

    env_vars = config.get("Env", [])
    secret_keywords = ["PASSWORD", "SECRET", "KEY", "TOKEN", "CREDENTIAL", "API_KEY"]
    for env in env_vars:
        key = env.split("=")[0]
        if any(s in key.upper() for s in secret_keywords):
            findings.append({"severity": "高危", "finding": f"敏感环境变量暴露: {key}"})

    return findings


def get_filesystem_changes(container_id):
    """获取容器与其镜像之间的文件系统变更。"""
    stdout, _, rc = run_cmd(f"docker diff {container_id}")
    changes = {"added": [], "changed": [], "deleted": []}
    if rc == 0 and stdout:
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("A "):
                changes["added"].append(line[2:])
            elif line.startswith("C "):
                changes["changed"].append(line[2:])
            elif line.startswith("D "):
                changes["deleted"].append(line[2:])
    return changes


def detect_suspicious_files(changes):
    """分析文件系统变更以发现失陷指标（IOC）。"""
    suspicious_patterns = [
        "/tmp/", "/dev/shm/", "/root/", ".sh", ".py", ".elf",
        "reverse", "shell", "backdoor", "miner", "xmr", "nc ",
        ".php", "webshell", "c2", "beacon",
    ]
    suspicious_changes = ["/etc/passwd", "/etc/shadow", "/etc/crontab",
                          "/etc/ssh", ".bashrc", "/etc/sudoers", "authorized_keys"]

    findings = []
    for f in changes["added"]:
        for pattern in suspicious_patterns:
            if pattern in f.lower():
                findings.append({"type": "新增", "path": f, "reason": f"匹配模式: {pattern}"})
                break
    for f in changes["changed"]:
        for pattern in suspicious_changes:
            if pattern in f.lower():
                findings.append({"type": "变更", "path": f, "reason": f"关键文件被修改"})
                break
    return findings


def export_container(container_id, output_path):
    """将容器文件系统导出为 tarball 用于离线分析。"""
    cmd = f"docker export {container_id} > {output_path}"
    _, _, rc = run_cmd(cmd)
    if rc == 0 and os.path.exists(output_path):
        sha256 = hashlib.sha256()
        with open(output_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return True, sha256.hexdigest()
    return False, None


def get_container_logs(container_id, tail=500):
    """获取带时间戳的容器日志。"""
    stdout, stderr, rc = run_cmd(f"docker logs --timestamps --tail {tail} {container_id}")
    return stdout + "\n" + stderr if rc == 0 else None


def scan_image_vulnerabilities(image_name):
    """对容器镜像运行 Trivy 漏洞扫描。"""
    cmd = f"trivy image --format json {image_name}"
    stdout, _, rc = run_cmd(cmd)
    if rc == 0 and stdout:
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            return None
    return None


def generate_report(container_id, inspect_data, security_findings,
                    fs_changes, suspicious_files):
    """生成取证分析报告。"""
    container_name = "unknown"
    image = "unknown"
    if inspect_data:
        data = inspect_data[0] if isinstance(inspect_data, list) else inspect_data
        container_name = data.get("Name", "").lstrip("/")
        image = data.get("Config", {}).get("Image", "unknown")

    report = {
        "report_type": "Docker 容器取证",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "container_id": container_id,
        "container_name": container_name,
        "image": image,
        "security_findings": security_findings,
        "filesystem_changes": {
            "added": len(fs_changes["added"]),
            "changed": len(fs_changes["changed"]),
            "deleted": len(fs_changes["deleted"]),
        },
        "suspicious_files": suspicious_files,
    }
    return report


if __name__ == "__main__":
    print("=" * 60)
    print("Docker 容器取证 Agent")
    print("安全分析、文件系统差异比对、证据收集")
    print("=" * 60)

    container_id = sys.argv[1] if len(sys.argv) > 1 else None

    if container_id:
        print(f"\n[*] 正在分析容器: {container_id}")

        inspect_data = inspect_container(container_id)
        if not inspect_data:
            print("[错误] 无法检查容器。Docker 是否正在运行?")
            sys.exit(1)

        print("\n--- 安全配置分析 ---")
        findings = analyze_security_config(inspect_data)
        for f in findings:
            print(f"[{f['severity']}] {f['finding']}")

        print("\n--- 文件系统变更 ---")
        changes = get_filesystem_changes(container_id)
        print(f"  新增: {len(changes['added'])}, 变更: {len(changes['changed'])}, "
              f"删除: {len(changes['deleted'])}")

        print("\n--- 可疑文件 ---")
        suspicious = detect_suspicious_files(changes)
        for s in suspicious:
            print(f"[!] {s['type']}: {s['path']} ({s['reason']})")

        report = generate_report(container_id, inspect_data, findings, changes, suspicious)
        print(f"\n[*] 报告:\n{json.dumps(report, indent=2, ensure_ascii=False)}")
    else:
        print("\n[*] 列出所有容器...")
        containers = list_containers()
        for c in containers:
            print(f"  {c.get('ID', '?')[:12]}  {c.get('Names', '?')}  {c.get('Status', '?')}")
        print(f"\n[演示] 用法: python agent.py <container_id>")
