# 工作流程：证书固定（Certificate Pinning）绕过

## 工作流程 1：逐级升级的绕过方法
```
【配置 Burp 代理】 --> 【应用连接失败？】 --> 【是：证书固定已启用】
                                                              |
                                          【尝试 Objection 通用绕过】
                                                              |
                                                    【流量是否可见？】
                                                    /              \
                                              【是：完成】    【否：进阶方法】
                                                              |
                                          【识别证书固定库】
                                          【frida-trace *Trust* *Pin*】
                                                              |
                                          【编写自定义 Frida 脚本】
                                          【针对特定实现进行 Hook】
                                                              |
                                          【验证流量已成功捕获】
```

## 决策矩阵
| 固定方法 | 绕过工具 | 难度 |
|---------------|-------------|-----------|
| OkHttp CertificatePinner | Objection | 简单 |
| Network Security Config | 修改 Manifest 文件 | 简单 |
| 自定义 TrustManager | Frida Hook | 中等 |
| TrustKit | Objection 或 Frida | 中等 |
| Native C/C++ 验证 | Frida Interceptor.attach | 困难 |
| 证书透明度（Certificate Transparency） | 自定义 Frida 脚本 | 困难 |
