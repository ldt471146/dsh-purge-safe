# API 参考：使用 Frida 对 iOS 应用进行逆向工程

## Frida CLI 工具

| 命令 | 描述 |
|------|------|
| `frida-ps -Ua` | 列出 USB 设备上正在运行的应用 |
| `frida -U -n AppName -e "script"` | 附加到应用并运行脚本 |
| `frida -U -f com.app.bundle -l script.js` | 以脚本启动应用 |
| `frida-trace -U -n AppName -m "*[ClassName *]"` | 追踪 ObjC 方法 |
| `frida-discover -U -n AppName` | 发现可用函数 |

## Frida JavaScript API

| API | 描述 |
|-----|------|
| `ObjC.classes.ClassName` | 访问 Objective-C 类 |
| `ObjC.classes.Cls.$ownMethods` | 列出类方法 |
| `Interceptor.attach(target, callbacks)` | Hook 原生函数 |
| `Interceptor.replace(target, replacement)` | 替换函数实现 |
| `Module.findExportByName(null, "func")` | 查找导出的 C 函数 |
| `ObjC.Object(ptr)` | 将指针包装为 ObjC 对象 |
| `Memory.readUtf8String(ptr)` | 从内存读取字符串 |

## 常用 iOS 安全 Hook 目标

| 目标 | 用途 |
|------|------|
| `SSLSetPeerDomainName` | 绕过 SSL 固定 |
| `NSFileManager fileExistsAtPath:` | 越狱检测 |
| `CCCrypt` | 拦截加密调用 |
| `NSURLSession` | 监控网络请求 |
| `SecItemCopyMatching` | 钥匙串访问 |

## Python 库

| 库 | 版本 | 用途 |
|----|------|------|
| `subprocess` | 标准库 | 执行 frida CLI 工具 |
| `frida` | >=16.0 | Frida Python 绑定 |
| `json` | 标准库 | 报告生成 |

## 参考资料

- Frida 文档：https://frida.re/docs/home/
- Frida JavaScript API：https://frida.re/docs/javascript-api/
- objection：https://github.com/sensepost/objection
- OWASP 移动测试指南：https://mas.owasp.org/MASTG/
