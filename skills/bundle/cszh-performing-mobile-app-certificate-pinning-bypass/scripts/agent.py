#!/usr/bin/env python3
"""移动应用证书固定绕过测试 Agent——仅限授权测试使用。"""

import json
import argparse
import subprocess
from datetime import datetime
from pathlib import Path


FRIDA_SSL_BYPASS_SCRIPT = """
Java.perform(function() {
    // 绕过 TrustManagerImpl
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function() {
        console.log('[*] 已绕过 TrustManagerImpl.verifyChain');
        return Java.use('java.util.ArrayList').$new();
    };
    // 绕过 OkHttp CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCerts) {
            console.log('[*] 已绕过 OkHttp CertificatePinner，主机: ' + hostname);
        };
    } catch(e) { console.log('[!] 未找到 OkHttp'); }
    // 绕过 WebViewClient
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            console.log('[*] 已绕过 WebView SSL 错误');
            handler.proceed();
        };
    } catch(e) {}
});
"""


def detect_pinning_implementation(apk_path):
    """检测 APK 中的证书固定实现。"""
    cmd = ["apktool", "d", apk_path, "-o", "/tmp/apk_decompile", "-f"]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        return {"error": "apktool 未安装"}
    pinning_indicators = {
        "okhttp_pinner": "CertificatePinner",
        "trustmanager": "X509TrustManager",
        "network_security_config": "network_security_config",
        "ssl_pinning_webview": "onReceivedSslError",
        "conscrypt": "TrustManagerImpl",
        "certificate_transparency": "CertificateTransparency",
    }
    findings = {}
    smali_dir = Path("/tmp/apk_decompile")
    for smali_file in smali_dir.rglob("*.smali"):
        content = smali_file.read_text(encoding="utf-8", errors="replace")
        for indicator_name, pattern in pinning_indicators.items():
            if pattern in content:
                findings.setdefault(indicator_name, []).append(str(smali_file.relative_to(smali_dir)))
    nsc_file = smali_dir / "res" / "xml" / "network_security_config.xml"
    nsc_content = None
    if nsc_file.exists():
        nsc_content = nsc_file.read_text()
    return {
        "apk": apk_path,
        "pinning_detected": bool(findings),
        "implementations": {k: v[:5] for k, v in findings.items()},
        "network_security_config": nsc_content[:500] if nsc_content else None,
        "pinning_strength": "STRONG" if len(findings) >= 3 else "MODERATE" if findings else "NONE",
    }


def run_frida_bypass(package_name, device_id=None):
    """对运行中的应用启动 Frida SSL 固定绕过。"""
    script_path = Path("/tmp/frida_ssl_bypass.js")
    script_path.write_text(FRIDA_SSL_BYPASS_SCRIPT)
    cmd = ["frida", "-U", "-l", str(script_path), "-f", package_name, "--no-pause"]
    if device_id:
        cmd = ["frida", "-D", device_id, "-l", str(script_path), "-f", package_name, "--no-pause"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {
            "package": package_name,
            "script": "ssl_pinning_bypass",
            "output": result.stdout[:1000],
            "errors": result.stderr[:500] if result.stderr else None,
            "success": result.returncode == 0,
        }
    except FileNotFoundError:
        return {"error": "frida 未安装——pip install frida-tools"}
    except subprocess.TimeoutExpired:
        return {"package": package_name, "status": "RUNNING", "note": "Frida 已附加——使用 Ctrl+C 分离"}


def run_objection_bypass(package_name):
    """使用 objection 禁用 Android/iOS 上的 SSL 固定。"""
    cmd = ["objection", "-g", package_name, "explore", "-s",
           "android sslpinning disable"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {
            "package": package_name,
            "tool": "objection",
            "output": result.stdout[:1000],
            "success": "disabled" in result.stdout.lower(),
        }
    except FileNotFoundError:
        return {"error": "objection 未安装——pip install objection"}
    except Exception as e:
        return {"error": str(e)}


def check_proxy_setup():
    """验证流量拦截的代理配置。"""
    checks = {}
    try:
        result = subprocess.run(["adb", "shell", "settings", "get", "global", "http_proxy"],
                                capture_output=True, text=True, timeout=10)
        proxy = result.stdout.strip()
        checks["android_proxy"] = proxy if proxy and proxy != "null" else "未设置"
    except Exception as e:
        checks["android_proxy_error"] = str(e)
    try:
        result = subprocess.run(["adb", "shell", "ls", "/system/etc/security/cacerts/"],
                                capture_output=True, text=True, timeout=10)
        cert_count = len(result.stdout.strip().splitlines())
        checks["system_ca_certs"] = cert_count
    except Exception as e:
        checks["ca_cert_error"] = str(e)
    try:
        result = subprocess.run(["adb", "shell", "su", "-c", "cat /data/misc/user/0/cacerts-added/ 2>/dev/null | wc -l"],
                                capture_output=True, text=True, timeout=10)
        checks["user_ca_certs"] = result.stdout.strip()
    except Exception:
        checks["user_ca_certs"] = "未知"
    return {"proxy_setup": checks}


def main():
    parser = argparse.ArgumentParser(description="移动应用证书固定绕过 Agent（仅限授权测试）")
    sub = parser.add_subparsers(dest="command")
    d = sub.add_parser("detect", help="检测 APK 中的固定")
    d.add_argument("--apk", required=True)
    f = sub.add_parser("frida", help="Frida SSL 绕过")
    f.add_argument("--package", required=True)
    f.add_argument("--device", help="设备 ID")
    o = sub.add_parser("objection", help="Objection SSL 绕过")
    o.add_argument("--package", required=True)
    sub.add_parser("proxy", help="检查代理配置")
    args = parser.parse_args()
    if args.command == "detect":
        result = detect_pinning_implementation(args.apk)
    elif args.command == "frida":
        result = run_frida_bypass(args.package, args.device)
    elif args.command == "objection":
        result = run_objection_bypass(args.package)
    elif args.command == "proxy":
        result = check_proxy_setup()
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
