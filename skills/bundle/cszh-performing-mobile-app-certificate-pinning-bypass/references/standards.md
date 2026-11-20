# 标准参考：证书固定绕过（Certificate Pinning Bypass）

## OWASP 移动端 Top 10 2024
| ID | 风险 | 相关性 |
|----|------|-----------|
| M5 | 不安全通信（Insecure Communication） | 作为网络安全评估的一部分进行固定评估 |
| M7 | 二进制保护不足（Insufficient Binary Protections） | 证书固定作为二进制级保护 |

## OWASP MASVS v2.0
| 控制项 | 描述 |
|---------|-------------|
| MASVS-NETWORK-1 | 应用使用 TLS 进行所有网络通信 |
| MASVS-NETWORK-2 | 应用对关键连接执行证书固定 |
| MASVS-RESILIENCE-1 | 应用检测并响应在检测环境中运行的情况 |

## CWE 映射
| CWE | 标题 |
|-----|-------|
| CWE-295 | 证书验证不当（Improper Certificate Validation） |
| CWE-297 | 主机名不匹配的证书验证不当（Improper Validation of Certificate with Host Mismatch） |
