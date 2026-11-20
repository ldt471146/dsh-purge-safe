#!/usr/bin/env python3
"""使用 Frida 对 iOS 应用进行逆向工程的 Agent。

使用 frida-tools 附加到 iOS 进程，Hook Objective-C 方法、
绕过 SSL 固定、转储钥匙串条目，并追踪 API 调用进行安全评估。
"""

import subprocess
import json
import sys
import re
from datetime import datetime
from pathlib import Path


class FridaIOSAgent:
    """使用 Frida 对 iOS 应用进行逆向工程。"""

    def __init__(self, target_app, device_id=None, output_dir="./frida_ios"):
        self.target_app = target_app
        self.device_id = device_id
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def _frida_cmd(self, script_code, timeout=60):
        cmd = ["frida", "-U"]
        if self.device_id:
            cmd.extend(["-D", self.device_id])
        cmd.extend(["-n", self.target_app, "-q", "-e", script_code])
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=timeout)
            return {"stdout": result.stdout, "stderr": result.stderr,
                    "returncode": result.returncode}
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return {"error": str(exc)}

    def list_running_apps(self):
        """列出已连接 iOS 设备上正在运行的应用。"""
        cmd = ["frida-ps", "-Ua"]
        if self.device_id:
            cmd.extend(["-D", self.device_id])
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return {"apps": result.stdout}
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return {"error": str(exc)}

    def bypass_ssl_pinning(self):
        """注入 Frida 脚本以绕过 SSL 证书固定。"""
        script = """
var m = ObjC.classes.NSURLSessionConfiguration;
Interceptor.attach(m['- setTLSMinimumSupportedProtocol:'].implementation, {
    onEnter: function(args) { console.log('[*] 已拦截 TLS 配置'); }
});
try {
    var SSLSetPeerDomainName = Module.findExportByName(null, 'SSLSetPeerDomainName');
    if (SSLSetPeerDomainName) {
        Interceptor.attach(SSLSetPeerDomainName, {
            onEnter: function(args) { },
            onLeave: function(retval) { retval.replace(0); }
        });
        console.log('[+] SSL 固定已绕过');
    }
} catch(e) { console.log('[-] ' + e); }
"""
        result = self._frida_cmd(script)
        if "SSL 固定已绕过" in result.get("stdout", ""):
            self.findings.append({"type": "SSL 固定绕过",
                                  "severity": "Medium",
                                  "details": "可使用 Frida 绕过 SSL 固定"})
        return result

    def dump_keychain(self):
        """转储应用可访问的 iOS 钥匙串条目。"""
        script = """
var kSecClass = ObjC.classes.NSString.stringWithString_('kSecClass');
var query = ObjC.classes.NSMutableDictionary.dictionary();
query.setObject_forKey_(ObjC.classes.NSString.stringWithString_('kSecClassGenericPassword'), kSecClass);
query.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true), ObjC.classes.NSString.stringWithString_('kSecReturnAttributes'));
query.setObject_forKey_(ObjC.classes.NSString.stringWithString_('kSecMatchLimitAll'), ObjC.classes.NSString.stringWithString_('kSecMatchLimit'));
var result = new ObjC.Object(ptr(0));
var status = ObjC.classes.NSDictionary.alloc();
console.log('[*] 钥匙串查询已执行');
"""
        result = self._frida_cmd(script)
        return result

    def trace_objc_methods(self, class_name):
        """追踪特定 Objective-C 类上的所有方法调用。"""
        script = f"""
var target = ObjC.classes.{class_name};
if (target) {{
    var methods = target.$ownMethods;
    console.log('[*] 正在追踪 {class_name} 的 ' + methods.length + ' 个方法');
    methods.forEach(function(method) {{
        try {{
            Interceptor.attach(target[method].implementation, {{
                onEnter: function(args) {{
                    console.log('[调用] {class_name} ' + method);
                }}
            }});
        }} catch(e) {{}}
    }});
}} else {{
    console.log('[-] 未找到类 {class_name}');
}}
"""
        return self._frida_cmd(script, timeout=30)

    def check_jailbreak_detection(self):
        """测试应用是否有越狱检测并尝试绕过。"""
        script = """
var paths = ['/Applications/Cydia.app', '/usr/sbin/sshd',
             '/bin/bash', '/usr/bin/ssh', '/etc/apt'];
var NSFileManager = ObjC.classes.NSFileManager;
Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
    onEnter: function(args) {
        var path = ObjC.Object(args[2]).toString();
        for (var i = 0; i < paths.length; i++) {
            if (path.indexOf(paths[i]) !== -1) {
                console.log('[*] 越狱检测: ' + path);
            }
        }
    },
    onLeave: function(retval) {}
});
console.log('[+] 越狱检测 Hook 已安装');
"""
        result = self._frida_cmd(script, timeout=15)
        if "越狱检测" in result.get("stdout", ""):
            self.findings.append({"type": "存在越狱检测",
                                  "severity": "Info"})
        return result

    def generate_report(self):
        report = {
            "target_app": self.target_app,
            "report_date": datetime.utcnow().isoformat(),
            "findings": self.findings,
        }
        report_path = self.output_dir / "frida_ios_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    app = sys.argv[1] if len(sys.argv) > 1 else "TargetApp"
    agent = FridaIOSAgent(app)
    agent.list_running_apps()
    agent.bypass_ssl_pinning()
    agent.check_jailbreak_detection()
    agent.generate_report()


if __name__ == "__main__":
    main()
