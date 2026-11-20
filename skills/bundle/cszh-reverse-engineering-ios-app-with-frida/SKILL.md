---
name: cszh-reverse-engineering-ios-app-with-frida
description: 使用 Frida 动态插桩对 iOS 应用进行逆向工程，在无源代码的情况下理解内部逻辑、 提取加密密钥、绕过安全控制并发现隐藏功能。适用于授权 iOS 渗透测试、分析专有协议、 理解混淆逻辑或从 iOS 二进制文件中提取运行时机密。适合 iOS 逆向工程、Frida iOS Hook、 Objective-C/Swift 方法追踪或 iOS 二进制分析相关请求。
---

> 来源：killvxk/cybersecurity-skills-zh 上游技能 `reverse-engineering-ios-app-with-frida`，正文为中文原文照录（仅剥离上游 frontmatter）。
> 定位：使用 Frida 对 iOS 应用进行逆向工程。
> 用法：按正文的「工作流程 / 命令清单 / 输出格式」执行；本技能在 dsh 中的名字是 cszh-reverse-engineering-ios-app-with-frida。

# 使用 Frida 对 iOS 应用进行逆向工程

## 适用场景

适用于以下情况：
- 在无源代码的授权安全评估中分析 iOS 应用内部结构
- 从运行中的 iOS 应用提取加密密钥、API 机密或专有协议详情
- 通过运行时方法追踪理解混淆的 Swift/Objective-C 逻辑
- 绕过复杂安全机制（越狱检测、防篡改、反调试）

**不适用场景**：不得用于违反服务条款或知识产权法律的未授权逆向工程。

## 前置条件

- 已越狱的 iOS 设备（通过 Cydia/Sileo 安装 Frida 服务端），或已注入 Frida Gadget 的非越狱设备 IPA
- Python 3.10+ 及 `frida-tools`（`pip install frida-tools`）
- USB 连接 iOS 设备
- class-dump 或 dsdump 用于提取 Objective-C 头文件
- Hopper Disassembler 或 Ghidra 用于静态二进制分析（辅助工具）
- 了解 Objective-C 运行时和 Swift 名称混淆

## 工作流程

### 步骤 1：提取和分析二进制文件

```bash
# 在越狱设备上找到应用二进制文件
ssh root@<device_ip>
find /var/containers/Bundle/Application/ -name "TargetApp" -type f

# 拉取解密后的二进制文件（App Store 应用使用 FairPlay 加密）
# 使用 frida-ios-dump 或 Clutch 进行解密
pip install frida-ios-dump
dump.py com.target.app

# 提取 Objective-C 类头文件
class-dump -H decrypted_binary -o headers/
ls headers/  # 列出所有类头文件
```

### 步骤 2：在运行时枚举类和方法

```javascript
// enumerate_classes.js - 列出所有已加载的类
Java.perform(function() {});  // iOS 不适用

// iOS 使用 ObjC 运行时
if (ObjC.available) {
    var classes = ObjC.classes;
    for (var className in classes) {
        if (className.indexOf("Target") !== -1 ||
            className.indexOf("Auth") !== -1 ||
            className.indexOf("Crypto") !== -1) {
            console.log("[Class] " + className);

            // 列出方法
            var methods = classes[className].$ownMethods;
            for (var i = 0; i < methods.length; i++) {
                console.log("  [Method] " + methods[i]);
            }
        }
    }
}
```

```bash
frida -U -n TargetApp -l enumerate_classes.js
```

### 步骤 3：使用 frida-trace 追踪方法调用

```bash
# 追踪某个类的所有方法
frida-trace -U -n TargetApp -m "*[TargetAuth *]"

# 追踪特定模式
frida-trace -U -n TargetApp -m "*[*Crypto* *]"
frida-trace -U -n TargetApp -m "*[*KeyChain* *]"
frida-trace -U -n TargetApp -m "*[*Token* *]"

# 追踪 Swift 方法（混淆名称）
frida-trace -U -n TargetApp -m "*[*$s*Auth*]"
```

### 步骤 4：Hook 并修改方法行为

```javascript
// hook_auth.js - 拦截认证逻辑
if (ObjC.available) {
    // Hook Objective-C 方法
    var AuthManager = ObjC.classes.AuthManager;
    if (AuthManager) {
        Interceptor.attach(AuthManager["- validateToken:"].implementation, {
            onEnter: function(args) {
                // args[0]=self, args[1]=selector, args[2+]=方法参数
                var token = new ObjC.Object(args[2]);
                console.log("[Auth] validateToken 调用，参数: " + token.toString());
            },
            onLeave: function(retval) {
                console.log("[Auth] validateToken 返回: " + retval);
                // 可选：修改返回值
                // retval.replace(ptr(1));  // 强制返回 true
            }
        });
    }

    // Hook CommonCrypto 进行加密分析
    var CCCrypt = Module.findExportByName("libcommonCrypto.dylib", "CCCrypt");
    if (CCCrypt) {
        Interceptor.attach(CCCrypt, {
            onEnter: function(args) {
                this.operation = args[0].toInt32();  // 0=加密, 1=解密
                this.algorithm = args[1].toInt32();  // 0=AES128, 1=DES, 2=3DES
                this.keyLength = args[4].toInt32();
                this.key = Memory.readByteArray(args[3], this.keyLength);
                console.log("[CCCrypt] 操作:" + (this.operation === 0 ? "加密" : "解密"));
                console.log("[CCCrypt] 密钥: " + hexify(this.key));
            },
            onLeave: function(retval) {
                console.log("[CCCrypt] 状态: " + retval);
            }
        });
    }
}

function hexify(buffer) {
    var bytes = new Uint8Array(buffer);
    var hex = [];
    for (var i = 0; i < bytes.length; i++) {
        hex.push(("0" + bytes[i].toString(16)).slice(-2));
    }
    return hex.join("");
}
```

### 步骤 5：分析 Swift 代码

```javascript
// swift_analysis.js - Hook Swift 方法
// Swift 方法使用名称混淆：$s<模块><类><方法>
// 先用 frida-trace 发现实际混淆名称

if (ObjC.available) {
    // 继承自 NSObject 的 Swift 类可通过 ObjC 运行时访问
    var swiftClasses = Object.keys(ObjC.classes).filter(function(name) {
        return name.indexOf("_TtC") === 0 || name.indexOf("TargetApp.") !== -1;
    });

    swiftClasses.forEach(function(className) {
        console.log("[Swift] " + className);
        var methods = ObjC.classes[className].$ownMethods;
        methods.forEach(function(method) {
            console.log("  " + method);
        });
    });
}

// 对于纯 Swift（未桥接到 ObjC），使用 Module.enumerateExports
Module.enumerateExports("TargetApp", {
    onMatch: function(exp) {
        if (exp.name.indexOf("Auth") !== -1 || exp.name.indexOf("Crypto") !== -1) {
            console.log("[Export] " + exp.name + " @ " + exp.address);
        }
    },
    onComplete: function() {}
});
```

### 步骤 6：提取机密和专有数据

```javascript
// extract_secrets.js
if (ObjC.available) {
    // Hook NSUserDefaults
    var NSUserDefaults = ObjC.classes.NSUserDefaults;
    Interceptor.attach(NSUserDefaults["- objectForKey:"].implementation, {
        onEnter: function(args) {
            this.key = new ObjC.Object(args[2]).toString();
        },
        onLeave: function(retval) {
            if (retval.isNull()) return;
            var value = new ObjC.Object(retval);
            console.log("[NSUserDefaults] " + this.key + " = " + value.toString());
        }
    });

    // Hook 钥匙串访问
    var SecItemCopyMatching = Module.findExportByName("Security", "SecItemCopyMatching");
    Interceptor.attach(SecItemCopyMatching, {
        onEnter: function(args) {
            var query = new ObjC.Object(args[0]);
            console.log("[Keychain] 查询: " + query.toString());
        },
        onLeave: function(retval) {
            console.log("[Keychain] 结果: " + retval);
        }
    });
}
```

## 核心概念

| 术语 | 定义 |
|------|------|
| **Objective-C 运行时** | 支持运行时方法分发、类自省和方法替换（Method Swizzling）的动态运行时 |
| **Swift 名称混淆** | 编译器将 Swift 函数签名编码为链接器兼容符号名称的技术 |
| **FairPlay DRM** | Apple 对 App Store 二进制文件应用的加密；静态分析前必须先解密 |
| **class-dump** | 从 Mach-O 二进制文件提取 Objective-C 类声明的工具，用于头文件级分析 |
| **CommonCrypto** | Apple 的 C 级加密库；通过 Frida Hook 提取加密密钥的主要目标 |

## 工具与系统

- **Frida**：iOS 运行时 Hook 和方法拦截的动态插桩框架
- **frida-trace**：自动追踪工具，为匹配方法生成处理程序存根
- **frida-ios-dump**：通过内存转储解密受 FairPlay 保护的 iOS 应用
- **class-dump / dsdump**：从 Mach-O 二进制文件提取 Objective-C 头文件
- **Ghidra**：NSA 的逆向工程框架，用于 iOS 应用的 ARM64 静态二进制分析

## 常见问题

- **FairPlay 加密**：从 App Store 下载的应用已加密，必须先解密才能进行静态分析。在越狱设备上使用 frida-ios-dump。
- **纯 Swift 类**：没有 `@objc` 注解的纯 Swift 类无法通过 `ObjC.classes` 查看，改用 `Module.enumerateExports()`。
- **符号剥离的二进制文件**：发布版本会剥离调试符号。结合 frida-trace 和 class-dump 输出进行有效分析。
- **反 Frida 措施**：复杂应用会检查 Frida 痕迹（frida-server 进程、内存中的 Frida agent 字符串、dyld 中注入的库）。使用隐蔽的 Frida 构建版本或 Frida Gadget 注入。
