---
name: hfh-mobile-security
description: 网络安全知识库「移动安全」分类技能包，源自 Hi-FullHouse/CyberSecurity-Skills 上游 10-移动安全-MobileSecurity。覆盖 Android 应用安全测试（aapt/apktool/jadx 信息收集与静态审计、adb 与 Frida 动态分析、Burp/mitmproxy 抓包与 SSL Pinning 绕过、备份与本地存储取证、drozer 组件与 Content Provider 探测、MobSF/QARK 自动化）与 iOS 应用安全测试（IPA 解包、Info.plist 与 cryptid 检查、class-dump/Ghidra 逆向、lldb 与 Cycript 运行时调试、越狱检测与反调试绕过、Keychain 与沙盒数据提取、URL Scheme 劫持），并对齐 OWASP MASVS/MSTG 检查清单（L1/L2 与 MSTG-STORAGE/NETWORK/PLATFORM/AUTH/CODE 条目），含 3 份中文原文 references。
---

# 移动安全（Mobile Security）

本技能用于对 Android / iOS 应用做**授权**移动端安全测试：静态审计 APK/IPA 与反编译产物、动态插桩调试、抓包与证书固定绕过、本地存储与凭据取证、组件与接口越权验证。判定标准统一对齐 **OWASP MASVS / MSTG**（L1 基础安全、L2 深度防御），而不是凭经验零散找问题。

关键工具：APKTool、jadx、aapt、drozer、MobSF、QARK、Frida、Objection、adb、Burp Suite、mitmproxy、class-dump、Ghidra、Hopper、lldb、Cycript、Keychain-Dumper、idb。国内真机通常需 root/Magisk 模块或越狱设备才能完整执行第 3–5 步。

## 一、Android 安全测试

### 1. APK 信息收集

```bash
# aapt 获取基本信息
aapt dump badging app.apk
aapt dump permissions app.apk
aapt dump configurations app.apk

# apktool 反编译（资源 + smali）
apktool d app.apk -o app_decompiled/
apktool d -f app.apk -o app_source/ --no-res   # 不反编译资源

cat app_decompiled/AndroidManifest.xml

# jadx 反编译 Java 源码
jadx -d jadx_output/ app.apk
jadx-gui app.apk
```

在线辅助：VirusTotal（<https://www.virustotal.com/>）、ANY.RUN（<https://app.any.run/>）。

### 2. 静态安全分析（grep 清单）

```bash
# 高危权限
grep -E "INTERNET|READ_EXTERNAL|WRITE_EXTERNAL|CAMERA|RECORD_AUDIO|READ_SMS|ACCESS_FINE_LOCATION" AndroidManifest.xml
# 导出组件：activity / service / receiver 上 android:exported="true"

# WebView 配置
grep -r "setJavaScriptEnabled\|addJavascriptInterface\|loadUrl\|setAllowFileAccess" jadx_output/
grep -r "WebView" jadx_output/

# 数据存储
grep -r "SharedPreferences\|getSharedPreferences\|SQLite\|openOrCreateDatabase\|getExternalStorageDir\|getCacheDir" jadx_output/

# 网络与 SSL
grep -r "HttpURLConnection\|OkHttp\|Retrofit\|HttpsURLConnection\|SSLSocketFactory" jadx_output/

# 硬编码密钥/令牌
grep -r "api_key\|secret\|token\|password\|aws\|azure\|firebase" jadx_output/
```

### 3. 动态安全分析（adb / Frida）

```bash
adb install app.apk
adb install -r app.apk     # 覆盖安装
adb install -t app.apk     # 测试 APK

adb logcat | grep -E "WebView|Javascript|JNI|Error|Exception"
adb shell dumpsys package com.example.app | grep -A 10 "Activity Resolver Table"
adb shell am start -n com.example.app/.MainActivity

adb shell screencap -p /sdcard/screen.png && adb pull /sdcard/screen.png
adb shell screenrecord /sdcard/demo.mp4    # 录屏

# 应用数据（debug 包可用 run-as）
adb shell run-as com.example.app cat /data/data/com.example.app/databases/app.db
adb backup -f backup.ab com.example.app

# Frida 挂钩
frida -U -l hook.js com.example.app
```

```javascript
// hook.js 模板
Java.perform(function() {
    var cls = Java.use("com.example.target.Class");
    cls.targetMethod.implementation = function() {
        console.log("Method called");
        return this.targetMethod();
    };
});
```

### 4. 网络流量分析

```bash
# 全局代理 + 证书安装（Android 7+ 需 root 或 Magisk 模块把用户证书移入系统证书）
adb shell settings put global http_proxy 192.168.1.100:8080
adb push burp_ca.der /sdcard/

mitmproxy -p 8080

# 全流量抓包
adb shell tcpdump -i any -p -s 0 -w /sdcard/capture.pcap
adb pull /sdcard/capture.pcap

# SSL Pinning 绕过
frida -U -l ssl_pinning_bypass.js com.example.app
objection -g com.example.app explore
#   android sslpinning disable
# Magisk 模块：TrustMeAlready
```

### 5. 本地数据存储分析

```bash
# 解包 adb backup（跳过 24 字节头部）
adb backup -f backup.ab com.example.app
dd if=backup.ab bs=1 skip=24 | openssl zlib -d > backup.tar
tar xvf backup.tar

sqlite3 /data/data/com.example.app/databases/database.db ".tables"
sqlite3 /data/data/com.example.app/databases/database.db "SELECT * FROM users;"
cat /data/data/com.example.app/shared_prefs/*.xml

adb shell ls -la /data/data/com.example.app/files/
adb shell cat /data/data/com.example.app/files/sensitive_data.txt
adb shell ls -la /sdcard/Android/data/com.example.app/
```

### 6. 漏洞检测（drozer / MobSF / QARK）

```bash
drozer console connect
dz> run app.package.list -f example
dz> run app.activity.info -a com.example.app
dz> run app.provider.info -a com.example.app
dz> run app.service.info -a com.example.app
dz> run app.broadcast.info -a com.example.app

# Content Provider 注入探测
dz> run scanner.provider.finduris -a com.example.app
dz> run app.provider.query content://com.example.app/users
dz> run app.provider.query content://com.example.app/database --selection "' OR '1'='1"

# 组件越权 / Intent 攻击
dz> run app.activity.start --component com.example.app com.example.app.SettingsActivity
dz> run app.broadcast.send --action com.example.action.SECRET --extra string secret xyz

# 自动化平台
docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf   # 上传 APK 到 http://localhost:8000
qark --apk app.apk
```

### 7. OWASP MASVS 检查清单

- **MASVS-L1（基础安全）**：① 安全数据存储 ② 网络通信安全 ③ 认证与授权 ④ 代码质量 ⑤ 隐私保护
- **MASVS-L2（深度防御）**：⑥ 防篡改 ⑦ 反逆向工程 ⑧ 完整性验证

```
MSTG-STORAGE-1  SharedPreferences 是否加密?
MSTG-STORAGE-2  数据库是否加密?
MSTG-STORAGE-3  敏感信息是否存储在外部存储?
MSTG-STORAGE-4  键盘输入是否泄露?
MSTG-NETWORK-1  是否使用 HTTPS?
MSTG-NETWORK-2  SSL Pinning 是否实现?
MSTG-NETWORK-3  是否使用证书透明度?
MSTG-PLATFORM-1 是否使用 WebView?
MSTG-PLATFORM-2 Intent 是否安全?
MSTG-AUTH-1     是否存在本地认证绕过?
MSTG-CODE-1     是否使用混淆?
MSTG-CODE-2     调试是否已禁用?
```

## 二、iOS 安全测试

### 1. IPA 分析与反编译

```bash
# 从越狱设备取包
scp -P 2222 root@localhost:/var/containers/Bundle/Application/UUID/App.app/ App.ipa

unzip App.ipa -d App_Payload/
plutil -p Info.plist

# 二进制加密检查：cryptid 0=未加密，1=已加密
otool -l App | grep -E "cryptid|crypt"

class-dump -H App -o headers/
ghidra App
strings App | grep -i "password\|secret\|key\|token\|api"
```

反汇编：Hopper Disassembler / IDA Pro。

### 2. 运行时调试（lldb / Cycript / Frida）

```bash
lldb -p PID
lldb -n AppName
```

```
(lldb) po [UIApplication sharedApplication]
(lldb) po [[[UIApplication sharedApplication] keyWindow] recursiveDescription]
(lldb) po [[NSUserDefaults standardUserDefaults] dictionaryRepresentation]
(lldb) br set -n "-[ViewController viewDidLoad]"
(lldb) memory read --format hex --count 32 0x100000000
```

```bash
cycript -p AppName
cy# UIApp
cy# [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/var/mobile/Containers/Data/Application" error:nil]
cy# [NSClassFromString(@"SecretClass") sharedInstance]

frida -U -l ios_hook.js AppName
```

```javascript
// iOS Frida 脚本要点
ObjC.classes.SecretManager.alloc().init()
var className = ObjC.classes["TargetClass"];
className["- secretMethod"].implementation = function() { /* ... */ };
```

### 3. 网络流量分析

```bash
# WiFi 代理指向 Burp，安装证书：设置 -> 通用 -> VPN与设备管理 -> 安装
scp burp_ca.der root@ios_device:/tmp/

# SSL Pinning 绕过
objection -g com.example.app explore
#   ios sslpinning disable
# 其他：SSL Kill Switch 2（Cydia）、Burp ProxySwitchy 插件

# 非 HTTP 流量（越狱设备）
tcpdump -i en0 -w capture.pcap
```

### 4. 本地存储分析

```bash
/var/mobile/Containers/Data/Application/UUID/      # 应用沙盒数据目录
scp -r root@ios_device:/var/mobile/Containers/Data/Application/UUID/Documents/ ./

plutil -p ~/Library/Preferences/com.example.app.plist
./keychain_dumper > keychain.txt                    # Keychain-Dumper
sqlite3 ~/Library/Application\ Support/App.sqlite ".tables"
defaults read com.example.app

# Keychain 访问组
otool -l App | grep -A 4 "keychain-access-groups"
security dump-keychain -d /path/to/keychain
```

### 5. 二进制保护绕过

常见越狱检测点：① `/Applications/Cydia.app` 路径 ② `/bin/bash`、`/usr/sbin/sshd` 文件 ③ dyld 中 `MobileSubstrate`、`SubstrateLoader` ④ `fork()` 测试。

```bash
frida -U -l jailbreak_bypass.js AppName
objection -g com.example.app explore
#   ios jailbreak disable
```

Cydia 绕过工具：Liberty Lite、Shadow、A-Bypass。反调试绕过针对 ptrace 检测、sysctl 检测、syscall 检测三类；完整性检查（`NSBundle.bundleIdentifier`、`NSBundle.mainBundle.infoDictionary`）同样用 Frida hook 覆盖。

### 6. 认证与逻辑测试

```bash
# IDOR：替换 User ID
curl -s "https://api.example.com/users/1001/profile" -H "Authorization: Bearer iOS_TOKEN"
```

```
cycript -p AppName
cy# [BiometricAuth authenticateWithReason:@"test"]        # 本地生物认证绕过
cy# [UIPasteboard generalPasteboard].string               # 剪贴板泄露
cy# [[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"appscheme://test"]]   # URL Scheme 劫持
```

```bash
grep -r "CFBundleURLSchemes" headers/                     # 自定义 Scheme
curl -s "https://example.com/apple-app-site-association"  # Universal Links 配置
```

其余风险面：Keychain 数据出现在 NSLog / Crashlytics 输出、剪贴板未清理。

### 7. OWASP MASVS iOS 检查清单

```
MSTG-PLATFORM-4  TouchID/FaceID 是否正确实现?
MSTG-PLATFORM-5  是否有屏幕截图泄露?
MSTG-STORAGE-6   Keychain 数据是否设置了正确的访问控制?
MSTG-STORAGE-7   剪贴板在使用后是否被清除?
MSTG-NETWORK-4   是否使用了 ATS (App Transport Security)?
MSTG-NETWORK-5   是否使用了 Certificate Pinning?
MSTG-IOS-1       UIWebView 还是 WKWebView?
MSTG-IOS-2       iCloud 备份是否包含敏感数据?
MSTG-IOS-3       是否启用了文件保护?
MSTG-IOS-4       键盘输入是否安全?
MSTG-IOS-5       是否正确处理远程通知?
MSTG-IOS-6       是否使用了 User Enrollment?
```

```bash
plutil -p Info.plist | grep -A 10 "NSAppTransportSecurity"   # NSAllowsArbitraryLoads 是否为 true
# UIFileSharingEnabled / LSSupportsOpeningDocumentsInPlace 检查 iCloud 与文件共享暴露
```

## 三、工具对照

| 工具 | 用途 | 链接 |
|:---|:---|:---|
| APKTool | APK 反编译 | https://ibotpeaches.github.io/Apktool/ |
| jadx | Java 反编译器 | https://github.com/skylot/jadx |
| Frida | 动态插桩 | https://frida.re/ |
| Drozer | Android 安全审计 | https://github.com/FSecureLABS/drozer |
| MobSF | 移动安全框架 | https://github.com/MobSF/Mobile-Security-Framework-MobSF |
| Objection | 运行时探索 | https://github.com/sensepost/objection |
| QARK | 快速 Android 审查 | https://github.com/linkedin/qark |
| APKLeaks | APK 信息泄露扫描 | https://github.com/dwisiswant0/apkleaks |
| Hopper Disassembler | 反汇编器 | https://www.hopperapp.com/ |
| class-dump | 头文件导出 | http://stevenygard.com/projects/class-dump/ |
| Cycript | Objective-C 脚本 | http://www.cycript.org/ |
| Keychain-Dumper | Keychain 导出 | https://github.com/ptoomey3/Keychain-Dumper |
| idb | iOS 调试桥 | https://github.com/dmayer/idb |

## 四、参考资源

- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [OWASP MASVS](https://mas.owasp.org/MASVS/)
- [Android Security Checklist](https://developer.android.com/topic/security/best-practices)
- [HackTricks - Android](https://book.hacktricks.xyz/mobile-apps-pentesting/android-app-pentesting)
- [HackTricks - iOS](https://book.hacktricks.xyz/mobile-apps-pentesting/ios-pentesting)
- [iOS Security Guide (Apple)](https://www.apple.com/business/docs/site/iOS_Security_Guide.pdf)
- [The iPhone Wiki](https://www.theiphonewiki.com/)
- [iOS Application Security](https://github.com/nsobject/ios-application-security)
- [NIST SP 800-163 — Mobile Application Security](https://csrc.nist.gov/publications/detail/sp/800-163/rev-1/final)

## 五、上游原文（references/）

| 上游文件 | 本包路径 |
|:---|:---|
| `README.md`（分类导读：目标与技能清单） | `references/README.md` |
| `skills/Android安全测试-AndroidSecurityTest.md` | `references/Android安全测试-AndroidSecurityTest.md` |
| `skills/iOS安全测试-iOSSecurityTest.md` | `references/iOS安全测试-iOSSecurityTest.md` |
