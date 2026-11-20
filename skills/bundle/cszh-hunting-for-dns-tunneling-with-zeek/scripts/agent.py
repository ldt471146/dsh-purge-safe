#!/usr/bin/env python3
"""使用 Zeek 日志分析检测 DNS 隧道的 agent。"""

import argparse
import csv
import json
import math
import sys
from collections import defaultdict
from datetime import datetime, timezone


ENTROPY_THRESHOLD = 3.5
MIN_QUERIES_PER_DOMAIN = 20
MAX_NORMAL_SUBDOMAIN_LEN = 30
TUNNEL_QUERY_TYPES = {"TXT", "NULL", "CNAME", "MX"}


def shannon_entropy(data):
    """计算字符串的 Shannon 熵值。"""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for c in data:
        freq[c] += 1
    n = len(data)
    return -sum((cnt/n) * math.log2(cnt/n) for cnt in freq.values())


def load_dns_log(filepath):
    """加载 Zeek dns.log（TSV 格式）。"""
    entries = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                parts = line.strip().split("\t")
                if len(parts) >= 10:
                    entries.append({
                        "ts": parts[0],
                        "uid": parts[1],
                        "src": parts[2],
                        "src_port": parts[3],
                        "dst": parts[4],
                        "dst_port": parts[5],
                        "query": parts[9] if len(parts) > 9 else "",
                        "qtype": parts[13] if len(parts) > 13 else "",
                        "answers": parts[21] if len(parts) > 21 else "",
                    })
    except (OSError, IndexError) as e:
        print(f"[!] 加载 DNS 日志出错：{e}")
    return entries


def analyze_domain_statistics(entries):
    """计算每个域名的统计数据，用于隧道检测。"""
    domain_data = defaultdict(lambda: {
        "queries": [], "subdomains": [], "qtypes": defaultdict(int),
        "sources": set(), "total_subdomain_len": 0,
    })

    for entry in entries:
        query = entry.get("query", "")
        if not query or query == "-":
            continue
        parts = query.rstrip(".").split(".")
        if len(parts) < 2:
            continue
        domain = ".".join(parts[-2:])
        subdomain = ".".join(parts[:-2])
        d = domain_data[domain]
        d["queries"].append(query)
        d["subdomains"].append(subdomain)
        d["qtypes"][entry.get("qtype", "")] += 1
        d["sources"].add(entry.get("src", ""))
        d["total_subdomain_len"] += len(subdomain)

    return domain_data


def detect_tunneling(domain_data):
    """应用隧道检测启发式规则。"""
    findings = []
    for domain, data in domain_data.items():
        query_count = len(data["queries"])
        if query_count < MIN_QUERIES_PER_DOMAIN:
            continue

        avg_subdomain_len = data["total_subdomain_len"] / query_count
        all_subdomain_text = "".join(data["subdomains"])
        entropy = shannon_entropy(all_subdomain_text)

        tunnel_qtype_count = sum(
            data["qtypes"].get(qt, 0) for qt in TUNNEL_QUERY_TYPES
        )
        tunnel_qtype_ratio = tunnel_qtype_count / query_count if query_count else 0

        score = 0
        if entropy > ENTROPY_THRESHOLD:
            score += 40
        if avg_subdomain_len > MAX_NORMAL_SUBDOMAIN_LEN:
            score += 30
        if tunnel_qtype_ratio > 0.5:
            score += 20
        if query_count > 500:
            score += 10

        if score >= 40:
            findings.append({
                "domain": domain,
                "query_count": query_count,
                "avg_subdomain_length": round(avg_subdomain_len, 1),
                "entropy": round(entropy, 3),
                "tunnel_qtype_ratio": round(tunnel_qtype_ratio, 3),
                "unique_sources": len(data["sources"]),
                "tunnel_score": score,
                "severity": "CRITICAL" if score >= 70 else "HIGH" if score >= 50 else "MEDIUM",
            })

    findings.sort(key=lambda f: f["tunnel_score"], reverse=True)
    return findings


def main():
    parser = argparse.ArgumentParser(
        description="使用 Zeek 日志检测 DNS 隧道的 agent"
    )
    parser.add_argument("dns_log", help="Zeek dns.log 路径")
    parser.add_argument("--min-queries", type=int, default=20)
    parser.add_argument("--entropy-threshold", type=float, default=3.5)
    parser.add_argument("--output", "-o", help="输出 JSON 报告路径")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    global MIN_QUERIES_PER_DOMAIN, ENTROPY_THRESHOLD
    MIN_QUERIES_PER_DOMAIN = args.min_queries
    ENTROPY_THRESHOLD = args.entropy_threshold

    print("[*] DNS 隧道检测 Agent（Zeek）")
    entries = load_dns_log(args.dns_log)
    if not entries:
        print("[!] 未加载到 DNS 条目")
        sys.exit(1)

    print(f"[*] 已加载 {len(entries)} 条 DNS 查询")
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_file": args.dns_log,
        "total_queries": len(entries),
        "findings": [],
    }

    domain_data = analyze_domain_statistics(entries)
    findings = detect_tunneling(domain_data)
    report["findings"] = findings
    report["risk_level"] = (
        "CRITICAL" if any(f["severity"] == "CRITICAL" for f in findings)
        else "HIGH" if findings else "LOW"
    )

    print(f"[*] 检测到 {len(findings)} 个疑似 DNS 隧道")
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] 报告已保存至 {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
