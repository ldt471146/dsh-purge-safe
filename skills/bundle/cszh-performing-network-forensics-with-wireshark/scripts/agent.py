#!/usr/bin/env python3
"""使用 Wireshark/pyshark 执行网络取证的 Agent。

分析 PCAP 文件以提取会话、DNS 查询、HTTP 对象，
检测信标模式并识别 C2 通信。
"""

import pyshark
import json
import sys
from collections import defaultdict
from pathlib import Path
from datetime import datetime


class NetworkForensicsAgent:
    """分析 PCAP 文件用于取证调查。"""

    def __init__(self, pcap_path, output_dir):
        self.pcap_path = pcap_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def get_capture_info(self):
        """获取捕获文件的基本统计信息。"""
        cap = pyshark.FileCapture(self.pcap_path, only_summaries=True)
        packet_count = 0
        first_time = None
        last_time = None
        for pkt in cap:
            packet_count += 1
            if first_time is None:
                first_time = pkt.time
            last_time = pkt.time
        cap.close()
        return {
            "file": self.pcap_path,
            "packets": packet_count,
            "first_packet": str(first_time),
            "last_packet": str(last_time),
        }

    def extract_dns_queries(self, limit=5000):
        """从捕获文件中提取 DNS 查询。"""
        cap = pyshark.FileCapture(self.pcap_path, display_filter="dns.qr==0")
        queries = []
        count = 0
        for pkt in cap:
            if count >= limit:
                break
            try:
                queries.append({
                    "timestamp": str(pkt.sniff_time),
                    "src_ip": pkt.ip.src,
                    "query": pkt.dns.qry_name,
                    "type": pkt.dns.qry_type,
                })
                count += 1
            except AttributeError:
                continue
        cap.close()
        return queries

    def detect_dns_tunneling(self, min_length=30):
        """通过子域名长度检测潜在的 DNS 隧道。"""
        queries = self.extract_dns_queries()
        suspicious = []
        for q in queries:
            domain = q.get("query", "")
            subdomain = domain.split(".")[0] if "." in domain else domain
            if len(subdomain) >= min_length:
                suspicious.append({
                    "query": domain,
                    "subdomain_length": len(subdomain),
                    "src_ip": q["src_ip"],
                    "timestamp": q["timestamp"],
                })
        return suspicious

    def extract_http_requests(self, limit=5000):
        """提取包含方法、主机、URI 和 User-Agent 的 HTTP 请求。"""
        cap = pyshark.FileCapture(self.pcap_path, display_filter="http.request")
        requests_list = []
        count = 0
        for pkt in cap:
            if count >= limit:
                break
            try:
                req = {
                    "timestamp": str(pkt.sniff_time),
                    "src_ip": pkt.ip.src,
                    "dst_ip": pkt.ip.dst,
                    "method": pkt.http.request_method,
                    "host": getattr(pkt.http, "host", ""),
                    "uri": getattr(pkt.http, "request_uri", ""),
                    "user_agent": getattr(pkt.http, "user_agent", ""),
                }
                requests_list.append(req)
                count += 1
            except AttributeError:
                continue
        cap.close()
        return requests_list

    def extract_tls_sni(self, limit=5000):
        """提取 TLS 服务器名称指示（SNI）值。"""
        cap = pyshark.FileCapture(
            self.pcap_path,
            display_filter="tls.handshake.extensions_server_name"
        )
        sni_list = []
        count = 0
        for pkt in cap:
            if count >= limit:
                break
            try:
                sni_list.append({
                    "timestamp": str(pkt.sniff_time),
                    "src_ip": pkt.ip.src,
                    "dst_ip": pkt.ip.dst,
                    "sni": pkt.tls.handshake_extensions_server_name,
                })
                count += 1
            except AttributeError:
                continue
        cap.close()
        return sni_list

    def get_top_talkers(self, limit=20):
        """按数据包数量识别最活跃的源 IP 和目的 IP。"""
        cap = pyshark.FileCapture(self.pcap_path, only_summaries=True)
        ip_counts = defaultdict(int)
        for pkt in cap:
            try:
                ip_counts[pkt.source] += 1
                ip_counts[pkt.destination] += 1
            except AttributeError:
                continue
        cap.close()
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        return [{"ip": ip, "packets": count} for ip, count in sorted_ips[:limit]]

    def detect_beaconing(self, target_ip, tolerance=5):
        """检测到特定 IP 的信标模式。"""
        cap = pyshark.FileCapture(
            self.pcap_path,
            display_filter=f"ip.dst=={target_ip} and tcp.flags.syn==1"
        )
        timestamps = []
        for pkt in cap:
            try:
                timestamps.append(float(pkt.sniff_timestamp))
            except (AttributeError, ValueError):
                continue
        cap.close()

        if len(timestamps) < 3:
            return {"beaconing": False, "connections": len(timestamps)}

        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        avg_interval = sum(intervals) / len(intervals)
        consistent = sum(1 for i in intervals if abs(i - avg_interval) < tolerance)

        return {
            "target_ip": target_ip,
            "connections": len(timestamps),
            "avg_interval_sec": round(avg_interval, 1),
            "consistent_intervals": consistent,
            "total_intervals": len(intervals),
            "beaconing": consistent / len(intervals) > 0.7 if intervals else False,
        }

    def find_suspicious_ports(self):
        """查找连接到常见恶意端口的流量。"""
        suspicious_ports = {"4444", "8080", "1337", "6667", "9001", "31337"}
        cap = pyshark.FileCapture(self.pcap_path, display_filter="tcp")
        findings = defaultdict(lambda: {"count": 0, "sources": set()})

        for pkt in cap:
            try:
                dport = pkt.tcp.dstport
                if dport in suspicious_ports:
                    findings[dport]["count"] += 1
                    findings[dport]["sources"].add(pkt.ip.src)
            except AttributeError:
                continue
        cap.close()

        return {
            port: {"count": data["count"], "sources": list(data["sources"])}
            for port, data in findings.items()
        }

    def generate_report(self, target_ip=None):
        """生成综合网络取证报告。"""
        report = {
            "capture_info": self.get_capture_info(),
            "top_talkers": self.get_top_talkers(),
            "dns_query_count": len(self.extract_dns_queries()),
            "dns_tunneling_suspects": self.detect_dns_tunneling(),
            "http_request_count": len(self.extract_http_requests()),
            "tls_sni_count": len(self.extract_tls_sni()),
            "suspicious_ports": self.find_suspicious_ports(),
        }

        if target_ip:
            report["beaconing_analysis"] = self.detect_beaconing(target_ip)

        report_path = self.output_dir / "network_forensics_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=list)
        print(json.dumps(report, indent=2, default=list))
        return report


def main():
    if len(sys.argv) < 3:
        print("用法：agent.py <pcap_file> <output_dir> [target_ip]")
        sys.exit(1)

    pcap_path = sys.argv[1]
    output_dir = sys.argv[2]
    target_ip = sys.argv[3] if len(sys.argv) > 3 else None

    agent = NetworkForensicsAgent(pcap_path, output_dir)
    agent.generate_report(target_ip)


if __name__ == "__main__":
    main()
