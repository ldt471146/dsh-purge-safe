# 标准与框架参考 — 勒索软件事件响应（Ransomware Incident Response）

## NIST SP 800-61 Rev. 3 — 勒索软件响应对齐

- **检测（DE）**：监控勒索软件指标
  - DE.CM-01：监控网络中的勒索软件 C2 流量
  - DE.AE-02：分析异常文件加密模式
- **响应（RS）**：遏制与根除
  - RS.AN-03：执行分析以确定勒索软件变种
  - RS.MI-01：通过网络隔离遏制勒索软件扩散
  - RS.MI-02：根除勒索软件持久化机制
- **恢复（RC）**：从备份中恢复
  - RC.RP-01：事件期间或事件后执行恢复计划
  - RC.CO-03：向相关方通报恢复活动

## CISA 勒索软件指南（StopRansomware.gov）
- 由 CISA、FBI、NSA、MS-ISAC 联合发布
- 关键建议：
  1. 维护离线加密备份
  2. 制定、维护并演练基本的网络事件响应计划
  3. 实施零信任架构（Zero Trust Architecture）
  4. 对网络进行分段以防止扩散
- 参考：https://www.cisa.gov/stopransomware

## NIST 勒索软件风险管理网络安全框架配置文件
- NISTIR 8374：提供映射到 CSF 的勒索软件配置文件
- 关键子类别：
  - PR.DS-01：静态数据受到保护（备份加密）
  - PR.IP-04：信息备份已被执行、维护并测试
  - DE.AE-05：已建立事件告警阈值
- 参考：https://csrc.nist.gov/publications/detail/nistir/8374/final

## MITRE ATT&CK — 勒索软件技术

### 加密前技术
| 技术 ID | 名称 | 描述 |
|-------------|------|-------------|
| T1486 | 为影响而加密数据（Data Encrypted for Impact） | 勒索软件核心加密活动 |
| T1490 | 阻止系统恢复（Inhibit System Recovery） | 删除卷影副本、禁用恢复 |
| T1489 | 停止服务（Service Stop） | 停止杀毒、备份、数据库服务 |
| T1562.001 | 禁用或修改工具（Disable or Modify Tools） | 加密前禁用安全工具 |
| T1047 | Windows 管理规范（Windows Management Instrumentation） | 用于横向部署的 WMI |

### 勒索软件部署技术
| 技术 ID | 名称 | 描述 |
|-------------|------|-------------|
| T1570 | 横向工具传输（Lateral Tool Transfer） | 跨网络复制勒索软件二进制文件 |
| T1053.005 | 计划任务（Scheduled Task） | 用于定时引爆的计划任务 |
| T1484.001 | 组策略修改（Group Policy Modification） | 滥用 GPO 进行大规模部署 |
| T1569.002 | 服务执行（Service Execution） | 将勒索软件作为服务运行 |

### 数据外泄（双重勒索）
| 技术 ID | 名称 | 描述 |
|-------------|------|-------------|
| T1567 | 通过 Web 服务外泄（Exfiltration Over Web Service） | 上传数据至云存储 |
| T1048 | 通过替代协议外泄（Exfiltration Over Alternative Protocol） | DNS/ICMP 隧道窃取数据 |
| T1041 | 通过 C2 渠道外泄（Exfiltration Over C2 Channel） | 通过 C2 基础设施发送数据 |

## SANS 勒索软件响应检查清单
1. 立即将受感染设备从网络隔离
2. 识别勒索软件变种
3. 检查是否有解密工具（No More Ransom、Emsisoft、Kaspersky）
4. 向执法机构报告（FBI IC3、当地 CISA 办公室）
5. 评估备份的可用性和完整性
6. 确认数据是否已被外泄（双重勒索）
7. 从干净备份中恢复
8. 记录经验教训

## FBI/CISA 联合建议
- 不建议支付赎金（支付不保证能够恢复）
- 向 FBI IC3（ic3.gov）和 CISA 报告攻击
- 为执法机构保留取证证据
- 联系 CISA 获取技术协助
- 与所在行业的 ISAC 共享 IOC

## 已知勒索软件家族参考
| 家族 | 首次出现 | 显著特征 | 是否有解密工具 |
|--------|-----------|----------------|-------------------|
| LockBit 3.0 | 2022 | RaaS，漏洞赏金计划 | 无 |
| BlackCat/ALPHV | 2021 | 基于 Rust，跨平台 | 部分（FBI 工具） |
| Cl0p | 2019 | 大规模利用活动 | 无 |
| Royal/BlackSuit | 2022 | 针对关键基础设施 | 无 |
| Play | 2022 | 间歇性加密 | 无 |
| Akira | 2023 | 针对 Linux/VMware | 部分 |
| Rhysida | 2023 | 针对医疗、教育行业 | 无 |
