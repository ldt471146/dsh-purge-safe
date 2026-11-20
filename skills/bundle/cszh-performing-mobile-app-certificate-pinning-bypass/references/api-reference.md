# API 参考：执行移动应用证书固定绕过

## 使用的库
- **subprocess**：执行 frida、objection、apktool、adb 命令
- **pathlib**：读取反编译 APK 的 smali 文件

## CLI 接口
```
python agent.py detect --apk app.apk
python agent.py frida --package com.example.app [--device emulator-5554]
python agent.py objection --package com.example.app
python agent.py proxy
```

## 核心函数

### `detect_pinning_implementation(apk_path)` — 静态 APK 分析
使用 apktool 反编译 APK。在 smali 文件中搜索固定指标：
OkHttp CertificatePinner、X509TrustManager、network_security_config、
WebView SSL 错误处理器、Conscrypt TrustManagerImpl、证书透明度。

### `run_frida_bypass(package_name, device_id)` — Frida 动态绕过
注入 JavaScript 绕过：TrustManagerImpl.verifyChain、OkHttp CertificatePinner.check、
WebViewClient.onReceivedSslError。

### `run_objection_bypass(package_name)` — Objection 框架绕过
通过 objection 探测模式运行 `android sslpinning disable`。

### `check_proxy_setup()` — 验证拦截环境
检查：Android 代理设置、系统 CA 证书、用户安装的 CA 证书。

## 固定强度分类
| 级别 | 标准 |
|------|------|
| STRONG | 检测到 3 种以上固定实现 |
| MODERATE | 检测到 1-2 种实现 |
| NONE | 未发现固定指标 |

## 依赖项
```
pip install frida-tools objection
```
系统：apktool、adb（Android Debug Bridge）
