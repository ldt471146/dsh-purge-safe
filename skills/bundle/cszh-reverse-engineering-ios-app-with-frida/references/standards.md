# 标准参考：使用 Frida 逆向 iOS 应用（iOS Reverse Engineering with Frida）

## OWASP 移动端 Top 10 2024 映射

| OWASP ID | 风险 | 逆向工程评估 |
|----------|------|---------------|
| M1 | 凭据使用不当（Improper Credential Usage） | 通过运行时钩子提取硬编码密钥 |
| M7 | 二进制保护不足（Insufficient Binary Protections） | 评估反逆向措施（混淆、反调试、反 Frida） |
| M10 | 加密不足（Insufficient Cryptography） | 钩取 CommonCrypto 以提取密钥并观察算法 |

## OWASP MASVS v2.0 — MASVS-RESILIENCE 控制项

| 控制项 | 描述 | Frida 测试方法 |
|---------|-------------|-------------------|
| MASVS-RESILIENCE-1 | 应用检测并响应逆向工程 | 使用 Frida 附加，观察检测响应 |
| MASVS-RESILIENCE-2 | 应用检测篡改 | 修改二进制，观察完整性检查 |
| MASVS-RESILIENCE-3 | 应用使用混淆 | 评估类/方法名称的可读性 |
| MASVS-RESILIENCE-4 | 应用检测调试器 | 附加调试器，检查 ptrace/sysctl 钩子 |

## CWE 映射

| CWE ID | 标题 | 逆向工程发现方法 |
|--------|-------|-------------------|
| CWE-798 | 使用硬编码凭据（Use of Hard-coded Credentials） | 钩取字符串初始化、NSUserDefaults 访问 |
| CWE-321 | 使用硬编码加密密钥（Use of Hard-coded Cryptographic Key） | 钩取 CCCrypt、SecKeyCreateWithData |
| CWE-327 | 使用已损坏或有风险的加密算法（Broken Crypto Algorithm） | 在 CCCrypt 调用中观察算法参数 |
| CWE-693 | 保护机制失效（Protection Mechanism Failure） | 绕过越狱检测、Frida 检测 |
