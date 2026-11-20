#!/usr/bin/env python3
"""
WMI 订阅持久化（WMI Subscription Persistence）检测脚本
分析 Sysmon Events 19/20/21 以及进程创建日志，
检测用于持久化的恶意 WMI 永久事件订阅。
"""

import json
import csv
import argparse
import datetime
import re
from pathlib import Path

DANGEROUS_CONSUMER_TYPES = {"ActiveScriptEventConsumer", "CommandLineEventConsumer"}

SUSPICIOUS_FILTER_PATTERNS = [
    (r"__InstanceCreationEvent.*Win32_Process", "process_start_trigger"),
    (r"__InstanceModificationEvent.*Win32_PerfFormattedData", "system_startup_trigger"),
    (r"__TimerEvent", "timer_based_trigger"),
    (r"__InstanceCreationEvent.*Win32_LogonSession", "user_logon_trigger"),
    (r"Win32_ProcessStartTrace", "process_trace_trigger"),
]

SUSPICIOUS_CONSUMER_PATTERNS = [
    (r"(?i)powershell", "powershell_execution"),
    (r"(?i)(cmd\.exe|cmd\s/c)", "command_execution"),
    (r"(?i)(http|https)://", "network_callback"),
    (r"(?i)(wscript|cscript)", "script_execution"),
    (r"(?i)(base64|encodedcommand|-enc\s)", "encoded_content"),
    (r"(?i)(invoke-expression|iex|downloadstring)", "download_cradle"),
]


def parse_events(input_path: str) -> list[dict]:
    """解析 Sysmon WMI 事件日志。"""
    path = Path(input_path)
    events = []
    if path.suffix == ".json":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            events = data if isinstance(data, list) else data.get("events", [])
    elif path.suffix == ".csv":
        with open(path, "r", encoding="utf-8-sig") as f:
            events = [dict(row) for row in csv.DictReader(f)]
    return events


def detect_wmi_persistence(events: list[dict]) -> list[dict]:
    """检测恶意 WMI 事件订阅。"""
    findings = []
    filters = {}
    consumers = {}

    for event in events:
        event_code = str(event.get("EventCode", event.get("EventID", "")))
        computer = event.get("Computer", event.get("host", ""))
        timestamp = event.get("UtcTime", event.get("_time", ""))
        user = event.get("User", event.get("user", ""))

        if event_code == "19":  # EventFilter（事件过滤器）
            name = event.get("Name", event.get("name", ""))
            query = event.get("Query", event.get("query", ""))
            filters[name] = {"query": query, "computer": computer, "timestamp": timestamp}

            for pattern, trigger_type in SUSPICIOUS_FILTER_PATTERNS:
                if re.search(pattern, query, re.IGNORECASE):
                    findings.append({
                        "timestamp": timestamp,
                        "computer": computer,
                        "user": user,
                        "event_type": "EventFilter",
                        "name": name,
                        "query": query,
                        "trigger_type": trigger_type,
                        "severity": "HIGH",
                        "technique": "T1546.003",
                    })
                    break

        elif event_code == "20":  # EventConsumer（事件消费者）
            name = event.get("Name", event.get("name", ""))
            consumer_type = event.get("Type", event.get("Destination", ""))
            destination = event.get("Destination", event.get("destination", ""))
            consumers[name] = {"type": consumer_type, "destination": destination}

            severity = "CRITICAL" if any(dt in str(consumer_type) for dt in DANGEROUS_CONSUMER_TYPES) else "MEDIUM"

            indicators = []
            for pattern, indicator in SUSPICIOUS_CONSUMER_PATTERNS:
                if re.search(pattern, str(destination)):
                    indicators.append(indicator)
                    severity = "CRITICAL"

            findings.append({
                "timestamp": timestamp,
                "computer": computer,
                "user": user,
                "event_type": "EventConsumer",
                "name": name,
                "consumer_type": str(consumer_type),
                "destination": destination,
                "indicators": indicators,
                "severity": severity,
                "technique": "T1546.003",
            })

        elif event_code == "21":  # 绑定（Binding）
            consumer = event.get("Consumer", event.get("consumer", ""))
            filter_ref = event.get("Filter", event.get("filter", ""))
            findings.append({
                "timestamp": timestamp,
                "computer": computer,
                "user": user,
                "event_type": "FilterToConsumerBinding",
                "consumer": consumer,
                "filter": filter_ref,
                "severity": "HIGH",
                "technique": "T1546.003",
            })

        elif event_code == "1":  # 进程创建
            parent = event.get("ParentImage", "")
            image = event.get("Image", "")
            cmdline = event.get("CommandLine", "")
            if "wmiprvse.exe" in parent.lower():
                image_name = image.split("\\")[-1].lower()
                if image_name in {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"}:
                    findings.append({
                        "timestamp": timestamp,
                        "computer": computer,
                        "user": user,
                        "event_type": "WmiPrvSe_Child_Process",
                        "child_process": image,
                        "command_line": cmdline,
                        "severity": "HIGH",
                        "technique": "T1546.003",
                    })

    return sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x["severity"], 3))


def run_hunt(input_path: str, output_dir: str) -> None:
    """执行 WMI 订阅持久化狩猎。"""
    print(f"[*] WMI 订阅持久化狩猎 - {datetime.datetime.now().isoformat()}")
    events = parse_events(input_path)
    print(f"[*] 已加载 {len(events)} 条事件")

    findings = detect_wmi_persistence(events)
    print(f"[!] WMI 持久化检测结果: {len(findings)} 条")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    with open(output_path / "wmi_persistence_findings.json", "w", encoding="utf-8") as f:
        json.dump({
            "hunt_id": f"TH-WMI-{datetime.date.today().isoformat()}",
            "total_events": len(events),
            "findings_count": len(findings),
            "findings": findings,
        }, f, indent=2)
    print(f"[+] 结果已写入 {output_dir}")


def main():
    parser = argparse.ArgumentParser(description="WMI 订阅持久化检测")
    parser.add_argument("--input", "-i", required=True)
    parser.add_argument("--output", "-o", default="./wmi_hunt_output")
    args = parser.parse_args()
    run_hunt(args.input, args.output)


if __name__ == "__main__":
    main()
