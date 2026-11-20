#!/usr/bin/env python3
"""执行PLC固件安全分析的代理。"""

import json
import argparse
import subprocess
import hashlib
import re
from pathlib import Path
from datetime import datetime


def extract_firmware(firmware_file, output_dir="/tmp/fw_extract"):
    """使用binwalk提取固件镜像。"""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    cmd = ["binwalk", "-e", "-C", output_dir, firmware_file]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        extracted = list(Path(output_dir).rglob("*"))
        files = [str(f.relative_to(output_dir)) for f in extracted if f.is_file()]
        return {
            "firmware": firmware_file, "output_dir": output_dir,
            "files_extracted": len(files),
            "file_list": files[:50],
            "binwalk_output": result.stdout[:1000],
        }
    except FileNotFoundError:
        return {"error": "未安装binwalk — pip install binwalk"}
    except Exception as e:
        return {"error": str(e)}


def analyze_firmware_metadata(firmware_file):
    """分析固件文件元数据并计算哈希值。"""
    data = Path(firmware_file).read_bytes()
    magic_bytes = data[:16].hex()
    return {
        "firmware": firmware_file,
        "size_bytes": len(data),
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "magic_bytes": magic_bytes,
        "entropy": _calculate_entropy(data),
    }


def _calculate_entropy(data):
    """计算二进制数据的香农熵。"""
    import math
    if not data:
        return 0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    entropy = 0
    length = len(data)
    for f in freq:
        if f > 0:
            p = f / length
            entropy -= p * math.log2(p)
    return round(entropy, 2)


def scan_for_credentials(extract_dir):
    """扫描提取的固件中的硬编码凭据。"""
    findings = []
    patterns = {
        "hardcoded_password": re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{3,})', re.I),
        "default_credential": re.compile(r'(?:admin|root|user|operator)[:;]\s*([^\s:]{3,})', re.I),
        "private_key": re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
        "api_key": re.compile(r"(?:api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*[\"']?([a-zA-Z0-9_\-]{16,})", re.I),
        "connection_string": re.compile(r"(?:mysql|postgres|mongodb|redis)://[^\s\"']+", re.I),
    }
    p = Path(extract_dir)
    for f in p.rglob("*"):
        if f.is_file() and f.stat().st_size < 1_000_000:
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
                for pattern_name, pattern in patterns.items():
                    matches = pattern.findall(content)
                    if matches:
                        findings.append({
                            "file": str(f.relative_to(p)),
                            "type": pattern_name,
                            "matches": [m[:50] if isinstance(m, str) else str(m)[:50] for m in matches[:5]],
                        })
            except Exception:
                continue
    return {
        "extract_dir": extract_dir,
        "files_scanned": sum(1 for _ in p.rglob("*") if _.is_file()),
        "credential_findings": len(findings),
        "findings": findings[:30],
        "severity": "CRITICAL" if findings else "INFO",
    }


def scan_for_vulnerabilities(extract_dir):
    """扫描提取的固件中的常见漏洞模式。"""
    findings = []
    p = Path(extract_dir)
    vuln_patterns = {
        "command_injection": re.compile(r"(?:system|popen|exec)\s*\(", re.I),
        "buffer_overflow_risk": re.compile(r"(?:strcpy|strcat|sprintf|gets)\s*\("),
        "insecure_protocol": re.compile(r"(?:telnet|ftp|http://|tftp)", re.I),
        "debug_enabled": re.compile(r"(?:debug\s*=\s*(?:true|1|on)|DEBUG_MODE)", re.I),
        "backdoor_indicator": re.compile(r"(?:backdoor|rootkit|reverse.?shell)", re.I),
    }
    for f in p.rglob("*"):
        if f.is_file() and f.stat().st_size < 1_000_000 and f.suffix in (".c", ".h", ".py", ".sh", ".conf", ".cfg", ".xml", ".json", ".lua", ""):
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
                for vuln_name, pattern in vuln_patterns.items():
                    matches = pattern.findall(content)
                    if matches:
                        findings.append({
                            "file": str(f.relative_to(p)),
                            "vulnerability": vuln_name,
                            "count": len(matches),
                            "samples": matches[:3],
                        })
            except Exception:
                continue
    config_files = list(p.rglob("*.conf")) + list(p.rglob("*.cfg")) + list(p.rglob("*.ini"))
    return {
        "extract_dir": extract_dir,
        "vulnerability_findings": len(findings),
        "config_files_found": len(config_files),
        "findings": findings[:30],
    }


def full_analysis(firmware_file, output_dir="/tmp/fw_extract"):
    """运行完整的固件安全分析流水线。"""
    metadata = analyze_firmware_metadata(firmware_file)
    extraction = extract_firmware(firmware_file, output_dir)
    if extraction.get("error"):
        return {"metadata": metadata, "extraction": extraction}
    credentials = scan_for_credentials(output_dir)
    vulnerabilities = scan_for_vulnerabilities(output_dir)
    return {
        "generated": datetime.utcnow().isoformat(),
        "metadata": metadata,
        "extraction": {"files_extracted": extraction["files_extracted"]},
        "credentials": credentials,
        "vulnerabilities": vulnerabilities,
        "risk_level": "CRITICAL" if credentials["credential_findings"] > 0 else "HIGH" if vulnerabilities["vulnerability_findings"] > 5 else "MEDIUM",
    }


def main():
    parser = argparse.ArgumentParser(description="PLC固件安全分析代理")
    sub = parser.add_subparsers(dest="command")
    e = sub.add_parser("extract", help="提取固件镜像")
    e.add_argument("--firmware", required=True)
    e.add_argument("--output", default="/tmp/fw_extract")
    m = sub.add_parser("metadata", help="分析固件元数据")
    m.add_argument("--firmware", required=True)
    c = sub.add_parser("creds", help="扫描硬编码凭据")
    c.add_argument("--dir", required=True, help="提取的固件目录")
    v = sub.add_parser("vulns", help="扫描漏洞模式")
    v.add_argument("--dir", required=True)
    f = sub.add_parser("full", help="完整固件分析")
    f.add_argument("--firmware", required=True)
    f.add_argument("--output", default="/tmp/fw_extract")
    args = parser.parse_args()
    if args.command == "extract":
        result = extract_firmware(args.firmware, args.output)
    elif args.command == "metadata":
        result = analyze_firmware_metadata(args.firmware)
    elif args.command == "creds":
        result = scan_for_credentials(args.dir)
    elif args.command == "vulns":
        result = scan_for_vulnerabilities(args.dir)
    elif args.command == "full":
        result = full_analysis(args.firmware, args.output)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
