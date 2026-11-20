---
name: cszh-performing-mobile-app-certificate-pinning-bypass
description: 在授权安全评估期间，绕过 Android 和 iOS 应用中的 SSL/TLS 证书固定实现，以启用流量拦截。 涵盖使用 Frida、Objection 和自定义脚本对 OkHttp、TrustManager、NSURLSession 及第三方固定库的绕过技术。适合证书固定绕过、SSL 固定破解、移动 TLS 拦截 或代理抗性应用测试相关请求。
---

> 来源：killvxk/cybersecurity-skills-zh 上游技能 `performing-mobile-app-certificate-pinning-bypass`，正文为中文原文照录（仅剥离上游 frontmatter）。
> 定位：执行移动应用证书固定绕过。
> 用法：按正文的「工作流程 / 命令清单 / 输出格式」执行；本技能在 dsh 中的名字是 cszh-performing-mobile-app-certificate-pinning-bypass。

# 执行移动应用证书固定绕过

## 适用场景

适用于以下情况：
- 移动应用因证书固定而拒绝通过代理连接
- 进行需要 HTTPS 流量拦截的授权安全测试
- 评估固定实现的强度和绕过难度
- 评估移动应用网络安全的纵深防御

**不适用场景**：未经明确授权不得绕过应用的证书固定。

## 前置条件

- 已配置的 Burp Suite 代理，监听所有接口
- 已 root 的 Android 设备或已越狱的 iOS 设备
- 目标设备上运行 Frida 服务端
- 已安装 Objection（`pip install objection`）
- 目标应用已安装并表现出固定行为

## 工作流程

### 步骤 1：识别固定实现

**Android 固定方法识别：**
```
1. 网络安全配置（res/xml/network_security_config.xml）
   含证书哈希固定的 <pin-set>

2. OkHttp CertificatePinner
   CertificatePinner.Builder().add("api.target.com", "sha256/...")

3. 自定义 TrustManager
   代码中的 X509TrustManager 覆盖

4. 第三方库
   - TrustKit
   - 证书透明度检查
```

**iOS 固定方法：**
```
1. NSURLSession 委托（URLSession:didReceiveChallenge:）
2. ATS（应用传输安全）自定义信任评估
3. TrustKit 框架
4. Alamofire ServerTrustPolicy
5. 自定义 SecTrust 评估
```

### 步骤 2：使用 Objection 绕过（最快方案）

```bash
# Android
objection --gadget com.target.app explore
android sslpinning disable

# iOS
objection --gadget com.target.app explore
ios sslpinning disable
```

Objection 可 Hook 常见固定实现，包括 OkHttp CertificatePinner、TrustManagerImpl、NSURLSession 委托方法和 SecTrust 评估。

### 步骤 3：使用自定义 Frida 脚本绕过

**Android - 通用 SSL 固定绕过：**
```javascript
// android_ssl_bypass.js
Java.perform(function() {
    // 绕过 TrustManagerImpl
    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain,
        host, clientAuth, ocspData, tlsSctData) {
        console.log("[+] 已为以下主机绕过 TrustManagerImpl: " + host);
        return untrustedChain;
    };

    // 绕过 OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation =
            function(hostname, peerCertificates) {
                console.log("[+] 已绕过 OkHttp3 固定，主机: " + hostname);
                return;
            };
    } catch(e) {}

    // 绕过自定义 X509TrustManager
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var TrustManager = Java.registerClass({
        name: "com.bypass.TrustManager",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    // 绕过 SSLContext
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;",
        "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation =
        function(km, tm, sr) {
            console.log("[+] 正在 SSLContext.init 中替换 TrustManagers");
            this.init(km, [TrustManager.$new()], sr);
        };

    // 绕过 NetworkSecurityConfig（Android 7+）
    try {
        var NetworkSecurityConfig = Java.use(
            "android.security.net.config.NetworkSecurityConfig");
        NetworkSecurityConfig.isCleartextTrafficPermitted.implementation = function() {
            return true;
        };
    } catch(e) {}

    console.log("[*] SSL 固定绕过已加载");
});
```

```bash
frida -U -f com.target.app -l android_ssl_bypass.js --no-pause
```

**iOS - 通用 SSL 固定绕过：**
```javascript
// ios_ssl_bypass.js
if (ObjC.available) {
    // 绕过 NSURLSession 委托
    var resolver = new ApiResolver("objc");
    resolver.enumerateMatches(
        "-[* URLSession:didReceiveChallenge:completionHandler:]", {
        onMatch: function(match) {
            Interceptor.attach(match.address, {
                onEnter: function(args) {
                    var completionHandler = new ObjC.Block(args[4]);
                    var NSURLSessionAuthChallengeUseCredential = 0;
                    var trust = new ObjC.Object(args[3])
                        .protectionSpace().serverTrust();
                    var credential = ObjC.classes.NSURLCredential
                        .credentialForTrust_(trust);
                    completionHandler.invoke(NSURLSessionAuthChallengeUseCredential,
                        credential);
                }
            });
        },
        onComplete: function() {}
    });

    // 绕过 SecTrustEvaluate
    var SecTrustEvaluateWithError = Module.findExportByName(
        "Security", "SecTrustEvaluateWithError");
    if (SecTrustEvaluateWithError) {
        Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(
            function(trust, error) {
                return 1;  // 始终返回 true
            }, "bool", ["pointer", "pointer"]
        ));
    }

    console.log("[*] iOS SSL 固定绕过已加载");
}
```

### 步骤 4：处理高级固定

对于使用高级固定（TrustKit、自定义二进制检查）的应用：

```bash
# 识别特定固定库
frida-trace -U -n TargetApp -m "*[*Trust*]" -m "*[*Pin*]" -m "*[*SSL*]" -m "*[*Certificate*]"

# Hook 识别到的验证函数
# 针对特定实现的自定义 Frida 脚本
```

### 步骤 5：验证绕过成功

应用绕过后：
1. 将设备代理配置为 Burp Suite
2. 打开目标应用并浏览认证流程
3. 验证 HTTPS 流量出现在 Burp Suite HTTP History 中
4. 检查是否仍有未被捕获的固定连接

## 核心概念

| 术语 | 定义 |
|------|------|
| **证书固定** | 将可接受的服务器证书限制为已知集合，防止通过伪造 CA 证书进行 MITM 攻击 |
| **公钥固定** | 固定服务器公钥哈希而非完整证书，在证书轮换时仍然有效 |
| **网络安全配置** | Android XML 配置，用于按域名声明信任锚点、固定和明文策略 |
| **TrustKit** | 实现证书固定并带报告功能的开源库，同时支持 Android 和 iOS |
| **HPKP 弃用** | HTTP 公钥固定标头已在浏览器中弃用，但相关概念在移动应用中仍然存在 |

## 工具与系统

- **Objection**：对常见库（OkHttp、NSURLSession、TrustKit）的预置固定绕过
- **Frida**：针对特定固定实现的自定义 JavaScript Hook
- **apktool**：APK 反编译，用于识别网络安全配置中的固定
- **SSLUnpinning（Xposed）**：Android 系统级固定绕过的 Xposed 框架模块
- **ssl-kill-switch2**：在越狱设备上全局禁用 iOS SSL 固定的 tweak

## 常见问题

- **证书透明度**：某些应用除固定外还检查 CT 日志，可能需要单独绕过 CT 验证。
- **多层固定**：应用可能在多个层级（OkHttp + 自定义 TrustManager）实现固定，需绕过所有层级。
- **二进制级固定**：某些应用在原生 C/C++ 代码中验证证书，需要在原生函数地址使用 Interceptor.attach，而非 Java/ObjC Hook。
- **动态固定更新**：使用 TrustKit 或类似工具的应用可能从服务器获取更新的固定值，测试期间需监控固定轮换。
