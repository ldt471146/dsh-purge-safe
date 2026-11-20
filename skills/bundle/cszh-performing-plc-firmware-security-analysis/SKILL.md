---
name: cszh-performing-plc-firmware-security-analysis
description: 本技能涵盖分析可编程逻辑控制器（PLC）固件的安全漏洞，包括硬编码凭据、不安全的更新机制、后门功能、内存损坏缺陷和未记录的调试接口。涉及从常见PLC平台（西门子S7、Allen-Bradley、施耐德Modicon）提取固件、固件镜像静态分析、仿真环境中的动态分析，以及与已知良好基线的对比以检测篡改。
---

> 来源：killvxk/cybersecurity-skills-zh 上游技能 `performing-plc-firmware-security-analysis`，正文为中文原文照录（仅剥离上游 frontmatter）。
> 定位：执行PLC固件安全分析。
> 用法：按正文的「工作流程 / 命令清单 / 输出格式」执行；本技能在 dsh 中的名字是 cszh-performing-plc-firmware-security-analysis。

# 执行PLC固件安全分析

## 适用场景

- 在IEC 62443组件安全评估（IEC 62443-4-2）中评估PLC安全性时
- 在疑似入侵或供应链攻击后验证固件完整性时
- 在关键基础设施部署前评估新PLC平台的安全性时
- 在授权实验室对工业控制系统设备进行漏洞研究时
- 响应疑似PLC逻辑或固件篡改的安全事件时

**不适用于**未经明确授权和安全控制措施到位的情况下对生产PLC进行操作。固件提取和分析应在实验室设备或离线备份上执行。切勿将PLC固件上传至公开分析服务。授权现场测试程序请参见performing-ics-penetration-testing。

## 前置条件

- 目标PLC硬件或仿真环境的隔离实验室环境
- 目标平台的PLC编程软件（西门子TIA Portal、Rockwell Studio 5000、施耐德EcoStruxure）
- 固件提取工具（binwalk、firmware-mod-kit、JTAG/SWD调试器）
- 静态分析工具（Ghidra、IDA Pro、支持ARM/MIPS/PowerPC的Binary Ninja）
- 了解PLC架构（实时操作系统、梯形图逻辑执行、I/O扫描）
- 用于完整性对比的已知良好固件参考副本

## 工作流程

### 步骤 1：获取PLC固件进行分析

通过授权方式提取或获取PLC固件。可通过从供应商下载、从实验室设备提取或从项目备份中获取。

```python
#!/usr/bin/env python3
"""PLC固件获取与完整性验证。

支持从项目文件、网络下载提取固件，
以及与已知良好基线进行二进制镜像对比。
"""

import hashlib
import json
import os
import struct
import sys
import zipfile
from datetime import datetime
from pathlib import Path


class PLCFirmwareAcquisition:
    """处理来自各种来源的PLC固件获取。"""

    def __init__(self, output_dir="firmware_analysis"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.manifest = {
            "acquisition_date": datetime.now().isoformat(),
            "firmware_samples": [],
        }

    def extract_from_siemens_project(self, project_path):
        """从西门子TIA Portal项目中提取固件/程序块。

        TIA Portal项目（.ap16/.ap17）是ZIP压缩包，包含
        XML编码的PLC程序块和系统配置。
        """
        print(f"[*] 正在分析西门子项目: {project_path}")
        results = {"platform": "Siemens", "blocks": []}

        if zipfile.is_zipfile(project_path):
            with zipfile.ZipFile(project_path, "r") as zf:
                for info in zf.infolist():
                    # 程序块以XML形式存储在特定路径中
                    if "ProgramBlocks" in info.filename or "SystemBlocks" in info.filename:
                        block_data = zf.read(info.filename)
                        block_hash = hashlib.sha256(block_data).hexdigest()

                        block_path = self.output_dir / info.filename.replace("/", "_")
                        block_path.write_bytes(block_data)

                        results["blocks"].append({
                            "name": info.filename,
                            "size": info.file_size,
                            "sha256": block_hash,
                            "extracted_to": str(block_path),
                        })
                        print(f"  [+] 已提取: {info.filename} ({info.file_size} 字节)")

        self.manifest["firmware_samples"].append(results)
        return results

    def extract_from_rockwell_project(self, acd_path):
        """从Rockwell Studio 5000 ACD文件中提取程序数据。

        ACD文件包含控制器程序、标签和配置。
        """
        print(f"[*] 正在分析Rockwell项目: {acd_path}")
        results = {"platform": "Rockwell/Allen-Bradley", "blocks": []}

        with open(acd_path, "rb") as f:
            header = f.read(256)
            # ACD文件具有特定签名
            if b"RSLogix" in header or b"Studio 5000" in header:
                f.seek(0)
                full_data = f.read()
                file_hash = hashlib.sha256(full_data).hexdigest()

                results["blocks"].append({
                    "name": os.path.basename(acd_path),
                    "size": len(full_data),
                    "sha256": file_hash,
                    "header_signature": header[:16].hex(),
                })
                print(f"  [+] 项目哈希: {file_hash}")

        self.manifest["firmware_samples"].append(results)
        return results

    def compute_firmware_hash(self, firmware_path):
        """计算固件镜像的多个哈希值用于完整性追踪。"""
        data = Path(firmware_path).read_bytes()
        return {
            "file": str(firmware_path),
            "size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest(),
        }

    def compare_firmware_integrity(self, current_fw, baseline_fw):
        """将当前固件与已知良好基线进行对比。"""
        current_hash = self.compute_firmware_hash(current_fw)
        baseline_hash = self.compute_firmware_hash(baseline_fw)

        match = current_hash["sha256"] == baseline_hash["sha256"]

        result = {
            "comparison_date": datetime.now().isoformat(),
            "current_firmware": current_hash,
            "baseline_firmware": baseline_hash,
            "integrity_match": match,
            "verdict": "通过 — 固件与基线匹配" if match else "失败 — 固件已被修改！",
        }

        if not match:
            # 查找文件开始出现差异的偏移量
            current_data = Path(current_fw).read_bytes()
            baseline_data = Path(baseline_fw).read_bytes()
            min_len = min(len(current_data), len(baseline_data))

            first_diff = None
            diff_count = 0
            for i in range(min_len):
                if current_data[i] != baseline_data[i]:
                    if first_diff is None:
                        first_diff = i
                    diff_count += 1

            result["first_difference_offset"] = f"0x{first_diff:08x}" if first_diff else None
            result["total_different_bytes"] = diff_count
            result["size_difference"] = len(current_data) - len(baseline_data)

        return result

    def save_manifest(self):
        """保存获取清单。"""
        manifest_path = self.output_dir / "acquisition_manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(self.manifest, f, indent=2)
        print(f"\n[*] 清单已保存: {manifest_path}")


if __name__ == "__main__":
    acq = PLCFirmwareAcquisition()

    if len(sys.argv) < 2:
        print("用法:")
        print("  python process.py extract-siemens <project.ap17>")
        print("  python process.py extract-rockwell <project.acd>")
        print("  python process.py compare <current.bin> <baseline.bin>")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "extract-siemens" and len(sys.argv) > 2:
        acq.extract_from_siemens_project(sys.argv[2])
    elif cmd == "extract-rockwell" and len(sys.argv) > 2:
        acq.extract_from_rockwell_project(sys.argv[2])
    elif cmd == "compare" and len(sys.argv) > 3:
        result = acq.compare_firmware_integrity(sys.argv[2], sys.argv[3])
        print(json.dumps(result, indent=2))
    else:
        print("无效命令")
        sys.exit(1)

    acq.save_manifest()
```

### 步骤 2：对固件镜像进行静态分析

使用binwalk进行固件解包，使用Ghidra进行反汇编，以识别固件二进制文件中的安全问题。

```bash
# 步骤 2a：使用binwalk解包固件镜像
binwalk -e firmware.bin
# 输出: _firmware.bin.extracted/

# 识别固件组件
binwalk firmware.bin
# 查找: 文件系统镜像、压缩段、引导加载程序、RTOS内核

# 提取字符串以进行凭据和配置分析
strings -n 8 firmware.bin > firmware_strings.txt

# 搜索硬编码凭据
grep -iE "(password|passwd|pwd|secret|key|credential|login|admin|root)" firmware_strings.txt

# 搜索网络配置
grep -iE "(http|ftp|telnet|ssh|snmp|modbus|192\.168|10\.|172\.)" firmware_strings.txt

# 搜索调试/后门指示符
grep -iE "(debug|backdoor|test_mode|factory|service_port|hidden)" firmware_strings.txt

# 搜索加密材料
grep -iE "(BEGIN RSA|BEGIN CERTIFICATE|AES|DES|private.key)" firmware_strings.txt

# 步骤 2b：熵分析检测加密/压缩段
binwalk -E firmware.bin
# 高熵段可能包含加密有效载荷或压缩数据

# 步骤 2c：使用Ghidra进行分析（无头模式）
analyzeHeadless /tmp/ghidra_project PLC_FW \
  -import firmware.bin \
  -processor ARM:LE:32:Cortex \
  -postScript FindCryptoConstants.java \
  -postScript FindHardcodedStrings.java \
  -log /tmp/ghidra_analysis.log
```

### 步骤 3：分析PLC通信协议栈安全性

检查PLC如何处理工业协议请求，重点关注认证绕过、数据包解析中的缓冲区溢出以及命令注入漏洞。

```python
#!/usr/bin/env python3
"""PLC协议安全分析器。

测试PLC协议实现中的常见漏洞，
包括认证绕过、畸形数据包处理
和功能码访问控制。

警告：只在实验室/测试PLC上运行，绝不对生产系统使用。
"""

import socket
import struct
import sys
import time
from dataclasses import dataclass


@dataclass
class ProtocolTestResult:
    test_name: str
    target: str
    protocol: str
    result: str  # PASS, FAIL, ERROR
    severity: str
    detail: str


class ModbusSecurityTester:
    """测试Modbus/TCP实现安全性。"""

    def __init__(self, target_ip, target_port=502):
        self.target = target_ip
        self.port = target_port
        self.results = []

    def _send_modbus(self, unit_id, func_code, data=b""):
        """发送Modbus/TCP请求并返回响应。"""
        # MBAP报头: transaction_id(2) + protocol_id(2) + length(2) + unit_id(1)
        mbap = struct.pack(">HHHB", 0x0001, 0x0000, len(data) + 2, unit_id)
        pdu = struct.pack("B", func_code) + data

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, self.port))
            sock.send(mbap + pdu)
            response = sock.recv(1024)
            sock.close()
            return response
        except Exception as e:
            return None

    def test_authentication_required(self):
        """测试PLC是否对读写操作要求认证。"""
        # 测试未认证读取
        read_data = struct.pack(">HH", 0, 10)  # 从地址0读取10个寄存器
        response = self._send_modbus(1, 3, read_data)

        if response and len(response) > 8 and response[7] != 0x83:
            self.results.append(ProtocolTestResult(
                test_name="Modbus认证 — 读取",
                target=self.target,
                protocol="Modbus/TCP",
                result="FAIL",
                severity="high",
                detail="PLC接受未认证的Modbus读取命令。不需要认证。",
            ))

        # 测试未认证写入
        write_data = struct.pack(">HH", 100, 0)  # 向寄存器100写入0
        response = self._send_modbus(1, 6, write_data)

        if response and len(response) > 8 and response[7] != 0x86:
            self.results.append(ProtocolTestResult(
                test_name="Modbus认证 — 写入",
                target=self.target,
                protocol="Modbus/TCP",
                result="FAIL",
                severity="critical",
                detail="PLC接受未认证的Modbus写入命令。任何主机都可以修改寄存器。",
            ))

    def test_function_code_access_control(self):
        """测试PLC是否限制危险功能码。"""
        dangerous_funcs = {
            8: "诊断（可重启通信）",
            17: "报告从站ID（信息泄露）",
            43: "封装接口传输（设备标识）",
        }

        for fc, desc in dangerous_funcs.items():
            response = self._send_modbus(1, fc, b"\x00\x00")
            if response and len(response) > 8:
                error_code = response[7]
                if error_code != (fc | 0x80):  # 非异常响应
                    self.results.append(ProtocolTestResult(
                        test_name=f"功能码访问 — FC{fc}",
                        target=self.target,
                        protocol="Modbus/TCP",
                        result="FAIL",
                        severity="medium",
                        detail=f"PLC在没有访问控制的情况下响应FC{fc}（{desc}）",
                    ))

    def test_invalid_unit_id(self):
        """测试PLC对广播和无效单元ID的响应。"""
        # 广播（单元ID 0）— 应谨慎处理
        read_data = struct.pack(">HH", 0, 1)
        response = self._send_modbus(0, 3, read_data)

        if response and len(response) > 8 and response[7] != 0x83:
            self.results.append(ProtocolTestResult(
                test_name="广播单元ID处理",
                target=self.target,
                protocol="Modbus/TCP",
                result="FAIL",
                severity="high",
                detail="PLC响应广播单元ID 0。这会导致广播写入攻击。",
            ))

    def test_malformed_packet_handling(self):
        """测试PLC对畸形Modbus数据包的抗性。"""
        # 过大的长度字段
        malformed = struct.pack(">HHH", 0x0001, 0x0000, 0xFFFF) + b"\x01\x03\x00\x00\x00\x01"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, self.port))
            sock.send(malformed)
            time.sleep(1)

            # 验证PLC是否仍可响应
            read_data = struct.pack(">HH", 0, 1)
            response = self._send_modbus(1, 3, read_data)
            sock.close()

            if response is None:
                self.results.append(ProtocolTestResult(
                    test_name="畸形数据包 — 过大长度字段",
                    target=self.target,
                    protocol="Modbus/TCP",
                    result="FAIL",
                    severity="critical",
                    detail="PLC在收到过大长度字段后无响应。可能存在DoS漏洞。",
                ))
            else:
                self.results.append(ProtocolTestResult(
                    test_name="畸形数据包 — 过大长度字段",
                    target=self.target,
                    protocol="Modbus/TCP",
                    result="PASS",
                    severity="info",
                    detail="PLC正确处理过大长度字段而不崩溃",
                ))
        except Exception as e:
            pass

    def run_all_tests(self):
        """运行所有Modbus安全测试。"""
        print(f"\n{'='*60}")
        print(f"PLC MODBUS安全分析 — {self.target}:{self.port}")
        print(f"{'='*60}")

        self.test_authentication_required()
        self.test_function_code_access_control()
        self.test_invalid_unit_id()
        self.test_malformed_packet_handling()

        for r in self.results:
            icon = "[失败]" if r.result == "FAIL" else "[通过]"
            print(f"\n  {icon} {r.test_name}")
            print(f"    严重程度: {r.severity}")
            print(f"    详情: {r.detail}")

        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python plc_protocol_tester.py <目标PLC IP> [端口]")
        print("警告：只对实验室/测试PLC使用！")
        sys.exit(1)

    target = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 502

    tester = ModbusSecurityTester(target, port)
    tester.run_all_tests()
```

## 核心概念

| 术语 | 定义 |
|------|------|
| PLC固件（PLC Firmware） | 运行在可编程逻辑控制器上的嵌入式软件，包括实时操作系统、协议栈和I/O驱动程序 |
| 梯形图逻辑（Ladder Logic） | PLC的图形化编程语言，以继电器逻辑电路形式表示，以程序块形式存储在PLC内存中 |
| 功能块（Function Block） | 可重用的PLC编程元素，封装了具有定义输入/输出的逻辑，可分析是否存在恶意修改 |
| 固件完整性（Firmware Integrity） | 使用密码学哈希对比，验证PLC固件未被从供应商提供或审批版本中修改 |
| IEC 62443-4-2 | IEC 62443标准中的组件安全要求，定义包括PLC在内的IACS组件所需的安全能力 |
| JTAG/SWD | 用于固件提取和底层分析的硬件调试接口（联合测试行动组/串行线调试） |

## 工具和系统

- **Binwalk**: 用于扫描、提取和分析嵌入式固件镜像的固件分析工具
- **Ghidra**: NSA开发的逆向工程框架，支持PLC中常用的ARM、MIPS、PowerPC架构
- **EMUX/FIRMADYNE**: 用于嵌入式设备固件动态分析的固件仿真框架
- **PLCinject**: 用于分析PLC逻辑注入漏洞的研究工具（仅在授权实验室环境中使用）
- **OpenPLC**: 开源PLC平台，可用作安全研究的测试目标

## 输出格式

```
PLC固件安全分析报告
=======================================
设备: [PLC型号和固件版本]
分析日期: YYYY-MM-DD
方法论: 静态 + 动态分析

固件完整性:
  SHA-256: [哈希值]
  基线匹配: [是/否]
  供应商签名有效: [是/否/未签名]

发现的漏洞:
  [PLC-001] [严重程度] [标题]
    CWE: [CWE-ID]
    详情: [技术描述]
    影响: [运营影响]
    修复: [修复或缓解措施]
```
