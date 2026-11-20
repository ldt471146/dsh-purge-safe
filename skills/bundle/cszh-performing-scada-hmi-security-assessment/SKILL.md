---
name: cszh-performing-scada-hmi-security-assessment
description: 对 SCADA 人机界面（HMI, Human-Machine Interface）系统进行安全评估，识别基于 Web 的 HMI、瘦客户端配置、认证机制以及 HMI 与 PLC 之间通信信道中的漏洞，符合 IEC 62443 和 NIST SP 800-82 指南要求。
---

> 来源：killvxk/cybersecurity-skills-zh 上游技能 `performing-scada-hmi-security-assessment`，正文为中文原文照录（仅剥离上游 frontmatter）。
> 定位：执行 SCADA HMI 安全评估。
> 用法：按正文的「工作流程 / 命令清单 / 输出格式」执行；本技能在 dsh 中的名字是 cszh-performing-scada-hmi-security-assessment。

# 执行 SCADA HMI 安全评估

## 适用场景

- 评估 SCADA/DCS 环境中 HMI 系统的安全态势
- 评估基于 Web 的 HMI 界面中的常见 Web 漏洞
- 审计 HMI 认证、授权和会话管理
- 测试 HMI 与 PLC/RTU 之间的通信安全
- 为 IEC 62443 或 NERC CIP 合规评估做准备

**不适用于**在没有维护窗口和回滚计划的情况下测试生产中的活跃 HMI、PLC 级别协议分析（参见 performing-s7comm-protocol-security-analysis），或在非 OT 系统上进行通用 Web 应用测试。

## 前置条件

- 包含供应商、版本和网络配置详情的 HMI 系统清单
- 镜像生产 HMI 配置的实验室或测试环境（首选用于主动测试）
- 来自工厂运营部门的在维护窗口期间进行测试的授权
- NIST SP 800-82 和 IEC 62443 安全要求文档
- HMI 到 PLC 通信网段上的网络捕获能力

## 工作流程

### 步骤 1：评估 HMI 攻击面

```python
#!/usr/bin/env python3
"""SCADA HMI 安全评估工具。

根据 IEC 62443 和 NIST SP 800-82 要求，
评估 HMI 在认证、通信、配置和 Web 界面等方面的安全性。
"""

import json
import sys
from datetime import datetime
from typing import Dict, List

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)


class HMISecurityAssessment:
    """对 SCADA HMI 系统进行安全评估。"""

    def __init__(self, hmi_info: dict):
        self.hmi_info = hmi_info
        self.findings = []
        self.checks_run = 0
        self.checks_passed = 0

    def check_authentication(self):
        """评估 HMI 认证机制。"""
        checks = [
            {
                "id": "AUTH-01",
                "name": "密码复杂度执行",
                "iec62443_ref": "ISA-62443-3-3 SR 1.7",
                "description": "HMI 必须执行最低密码复杂度要求",
                "test": "验证最小长度 >= 8，复杂度规则，历史记录 >= 5",
            },
            {
                "id": "AUTH-02",
                "name": "账户锁定策略",
                "iec62443_ref": "ISA-62443-3-3 SR 1.11",
                "description": "HMI 必须在登录失败尝试后锁定账户",
                "test": "验证 5 次失败尝试后锁定，锁定时长 >= 15 分钟",
            },
            {
                "id": "AUTH-03",
                "name": "已更改默认凭据",
                "iec62443_ref": "ISA-62443-3-3 SR 1.5",
                "description": "所有默认供应商凭据必须已更改",
                "test": "尝试使用已知供应商默认值登录（admin/admin，operator/operator）",
            },
            {
                "id": "AUTH-04",
                "name": "基于角色的访问控制",
                "iec62443_ref": "ISA-62443-3-3 SR 2.1",
                "description": "HMI 必须区分操作员、工程师和管理员角色",
                "test": "验证操作员角色无法访问工程功能",
            },
            {
                "id": "AUTH-05",
                "name": "会话超时执行",
                "iec62443_ref": "ISA-62443-3-3 SR 1.12",
                "description": "HMI 会话必须在不活跃后超时",
                "test": "验证操作员会话超时 <= 15 分钟，管理员 <= 5 分钟",
            },
            {
                "id": "AUTH-06",
                "name": "远程访问多因素认证",
                "iec62443_ref": "ISA-62443-3-3 SR 1.13",
                "description": "远程 HMI 访问需要 MFA",
                "test": "验证所有非本地 HMI 连接都强制执行 MFA",
            },
        ]

        print(f"\n--- 认证评估 ---")
        for check in checks:
            self.checks_run += 1
            print(f"  [{check['id']}] {check['name']}")
            print(f"    参考：{check['iec62443_ref']}")
            print(f"    测试：{check['test']}")

    def check_communication_security(self):
        """评估 HMI 到 PLC 的通信安全。"""
        checks = [
            {
                "id": "COMM-01",
                "name": "加密的 HMI-PLC 通信",
                "description": "HMI 与 PLC 之间的流量应使用加密协议（带 TLS 的 OPC UA）",
                "test": "捕获 HMI-PLC 流量并验证加密（Wireshark TLS 握手）",
            },
            {
                "id": "COMM-02",
                "name": "HMI 写命令认证",
                "description": "从 HMI 到 PLC 的写命令应经过认证",
                "test": "验证写操作需要操作员确认/认证",
            },
            {
                "id": "COMM-03",
                "name": "Web HMI 使用 HTTPS",
                "description": "基于 Web 的 HMI 界面必须使用 TLS 1.2+ 和有效证书",
                "test": "检查 TLS 版本、加密套件、证书有效性",
            },
            {
                "id": "COMM-04",
                "name": "未使用明文协议",
                "description": "Telnet、FTP、HTTP 不得用于 HMI 访问或管理",
                "test": "扫描 HMI 上的明文协议服务端口",
            },
        ]

        print(f"\n--- 通信安全评估 ---")
        for check in checks:
            self.checks_run += 1
            print(f"  [{check['id']}] {check['name']}")
            print(f"    测试：{check['test']}")

    def check_web_hmi_security(self):
        """评估基于 Web 的 HMI 中的常见 Web 漏洞。"""
        hmi_url = self.hmi_info.get("url", "")
        if not hmi_url:
            print(f"\n  [跳过] 未提供 Web HMI URL")
            return

        checks = [
            {
                "id": "WEB-01",
                "name": "跨站脚本（XSS）",
                "owasp": "A7:2017",
                "test": "在标签名称、告警消息的输入字段中测试 XSS 载荷",
            },
            {
                "id": "WEB-02",
                "name": "跨站请求伪造（CSRF）",
                "owasp": "A8:2013",
                "test": "验证状态更改操作（设定点更改）上的 CSRF 令牌",
            },
            {
                "id": "WEB-03",
                "name": "不安全的直接对象引用",
                "owasp": "A4:2013",
                "test": "操纵 URL 参数以访问其他用户的 HMI 视图",
            },
            {
                "id": "WEB-04",
                "name": "安全响应头",
                "test": "验证 X-Frame-Options、CSP、X-Content-Type-Options 头",
            },
            {
                "id": "WEB-05",
                "name": "特权文件系统访问（CVE-2025-0921）",
                "test": "检查 Ignition SCADA 是否存在通过项目文件触发的特权文件系统漏洞",
            },
        ]

        print(f"\n--- Web HMI 安全评估 ---")
        print(f"  目标：{hmi_url}")
        for check in checks:
            self.checks_run += 1
            print(f"  [{check['id']}] {check['name']}")
            print(f"    测试：{check['test']}")

    def check_hardening(self):
        """评估 HMI 操作系统和应用程序加固。"""
        checks = [
            {
                "id": "HARD-01",
                "name": "操作系统补丁级别",
                "test": "验证 HMI 操作系统在 SLA 内已打补丁（OT 通常为 90 天）",
            },
            {
                "id": "HARD-02",
                "name": "已禁用不必要的服务",
                "test": "验证未运行不必要的网络服务（如不需要的 RDP、SMB 等）",
            },
            {
                "id": "HARD-03",
                "name": "USB 端口限制",
                "test": "验证 HMI 终端上已阻止 USB 大容量存储",
            },
            {
                "id": "HARD-04",
                "name": "应用程序白名单",
                "test": "验证只有授权的 HMI 应用程序可以执行",
            },
            {
                "id": "HARD-05",
                "name": "已启用审计日志",
                "test": "验证操作员操作、登录事件和设定点更改已记录日志",
            },
        ]

        print(f"\n--- HMI 加固评估 ---")
        for check in checks:
            self.checks_run += 1
            print(f"  [{check['id']}] {check['name']}")
            print(f"    测试：{check['test']}")

    def generate_report(self):
        """生成评估报告。"""
        self.check_authentication()
        self.check_communication_security()
        self.check_web_hmi_security()
        self.check_hardening()

        print(f"\n{'='*70}")
        print("SCADA HMI 安全评估摘要")
        print(f"{'='*70}")
        print(f"日期：{datetime.now().isoformat()}")
        print(f"HMI：{self.hmi_info.get('name', '未知')}")
        print(f"供应商：{self.hmi_info.get('vendor', '未知')}")
        print(f"版本：{self.hmi_info.get('version', '未知')}")
        print(f"检查总数：{self.checks_run}")
        print(f"发现：{len(self.findings)}")


if __name__ == "__main__":
    assessment = HMISecurityAssessment(hmi_info={
        "name": "Plant-HMI-01",
        "vendor": "Siemens WinCC",
        "version": "7.5 SP2",
        "ip": "10.10.2.10",
        "url": "https://10.10.2.10:8080",
        "os": "Windows 10 LTSC 2021",
    })
    assessment.generate_report()
```

## 核心概念

| 术语 | 定义 |
|------|------|
| HMI | 人机界面（Human-Machine Interface），为操作员提供工业过程的可视化表示和控制 |
| Web HMI | 通过 HTTP/HTTPS 访问的基于浏览器的 HMI 界面，受标准 Web 漏洞影响 |
| 设定点（Setpoint） | 操作员可通过 HMI 更改的过程变量目标值；未授权更改可能导致过程中断 |
| 告警抑制（Alarm Suppression） | 攻击者禁用或隐藏 HMI 告警以掩盖恶意过程操纵的技术 |
| WinCC | 西门子 SCADA/HMI 软件，广泛部署于制造业和工艺行业 |
| CVE-2025-0921 | Ignition SCADA 特权文件系统漏洞，可通过恶意项目上传被利用 |

## 输出格式

```
HMI 安全评估报告
=================================
日期: YYYY-MM-DD
HMI: [名称] | 供应商: [供应商] | 版本: [版本]

按类别的发现:
  认证: [通过/失败数量]
  通信: [通过/失败数量]
  Web 安全: [通过/失败数量]
  加固: [通过/失败数量]

严重发现:
  1. [带整改措施的发现]

合规状态:
  IEC 62443 SL-T: [目标级别]
  IEC 62443 SL-A: [已达成级别]
```
