# iOS 免商店分发链审计：IPA 内 embedded.mobileprovision 暴露第三方企业 in-house 证书借用 + 通配 associated-domains

- **code**: ios-免商店分发链审计-ipa-内-embedded.mobileprovision-暴露第三方企业-in-house
- **kind**: script
- **category**: app-audit
- **component**: iOS IPA / embedded.mobileprovision（企业 in-house 分发描述文件）+ itms-services 分发链
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: task#614（2026-11-04）实测：curl -k --path-as-is -o ios.ipa https://e9sj.vz4wu8.com/IOSDownload_1/ios.ipa 返回 200 / Content-Length=247809106（ETag 6ad87b3a-ec54452，Last-Modified 2026-10-21），无需鉴权；Python 3.13 标准库 zipfile 取 Payload/*.app/embedded.mobileprovision（12462B，CMS 内含 XML），plistlib 解析得 TeamIdentifier=['<第三方 TEAMID>']、ProvisionsAllDevices=True、ProvisionedDevices=None、ExpirationDate=2027-03-31、application-identifier=<TEAMID>.com.<第三方>.LEARN（第三方企业 in-house 标识，与 App 自身 bundle id com.poker.wsc 不一致）、com.apple.developer.associated-domains="*"、keychain-access-groups=['<TEAMID>.*','com.apple.token']、get-task-allow=false；同包 Info.plist 为 CFBundleIdentifier=com.poker.wsc / 1.0.0.8 / NSAllowsArbitraryLoads=true / schemes=[winnersclub]；manifest 声明版本 1.0.0.2 与包内 1.0.0.8 不一致。判定成立依据：企业 in-house + 无 UDID 白名单 ⇒ 任意 iOS 设备可装、绕过 App Store 审核；签名身份归属第三方 ⇒ 包来源不可自证且可被同证书持有者仿签。未做真机安装、未验证证书私钥（只读到公钥证书 1492B）、未向域外主机发请求。
- **path**: pocs/ios-免商店分发链审计-ipa-内-embedded.mobileprovision-暴露第三方企业-in-house/ipa_provision_audit.py
- **tags**: ios,ipa,mobileprovision,enterprise-cert,itms-services,associated-domains,ats,client-audit,supply-chain,re-sign
- **created_at**: 2026-11-04T13:59:17.618Z
- **engine**: https://e9sj.vz4wu8.com/IOSDownload_1/ios.ipa
- **found_by**: recon

## 描述

对授权域上公开的 iOS 分发链做静态审计：取 itms-services manifest（.plist）→ 下载 IPA → 解包 embedded.mobileprovision（CMS/PKCS#7，需 carve 内嵌 XML plist）→ 读 TeamIdentifier / ProvisionsAllDevices / application-identifier / Entitlements，再读 Info.plist 对照。适用于判定「App 是否借第三方企业证书免商店分发」「通用链接归属面是否被通配 associated-domains 放大」「是否关闭 ATS」。前提：能得到 IPA 文件（授权分发直链），全程离线解析。

## 用法

```
python ipa_provision_audit.py https://<分发域>/<path>/ios.ipa
或先拿 manifest：curl -k --path-as-is https://<分发域>/IOSDownload_1/ios.plist （application/x-plist，含 bundle-identifier / bundle-version / 指向 IPA 的 URL）
探活：curl -k --path-as-is -H 'Range: bytes=0-0' -I https://<分发域>/<path>/ios.ipa
判据（三条同时成立才算「第三方企业证书滥用」）：
  1) ProvisionsAllDevices=True 且 ProvisionedDevices=None（企业 in-house，无 UDID 白名单，任意设备可装）；
  2) 描述文件的 application-identifier 前缀 TeamIdentifier 与 App 自身的 CFBundleIdentifier 不一致（典型借用/代签特征）；
  3) Name/AppIDName/TeamName 指向与 App 业务无关的第三方组织，且 ExpirationDate 为一年期企业证书。
附加风险项：Entitlements.com.apple.developer.associated-domains=="*"（通用链接归属面放大）、keychain-access-groups 含外部团队前缀、Info.plist 的 NSAllowsArbitraryLoads=true（关 ATS）、manifest 版本与 Info.plist 版本不一致（分发链版本管理失序）。
常见失败原因：mobileprovision 是 CMS 二进制，直接 plistlib.load 会报 InvalidFileException（必须 carve "<?xml" 到 "</plist>"）；Info.plist 可能是 bplist00（plistlib 可直接读）；部分重签包/越狱包没有 embedded.mobileprovision（改看 _CodeSignature/CodeResources 与 codesign -d --entitlements）；下载站常挂在 CDN/LB 后，直连失败时换代理或 --resolve。
```

## 正文

```
# iOS 分发链 / 签名身份审计（IPA + embedded.mobileprovision）

## 0. 适用场景与结论口径

对授权域上**公开分发**的 iOS 客户端做静态审计，回答三个问题：

1. 这个 App 是不是绕过 App Store，用**企业 in-house 证书**分发的？任意设备能否直接装？
2. 签名身份是不是**第三方组织**的（即"借用/代签"，包来源无法自证）？
3. 客户端的**安全配置**是否被放大风险（通配 `associated-domains`、关闭 ATS、外团队 keychain 组）？

判定成立的最低组合（本次实操命中）：
`ProvisionsAllDevices=True` + `ProvisionedDevices=None`（企业 in-house、无 UDID 白名单）
+ 描述文件 `application-identifier` 与 App 自身 `CFBundleIdentifier` 不一致。

## 1. 前置条件

- 能访问分发主机取到 `.plist`（itms-services manifest）与 `.ipa`；直连失败时走代理 / `--resolve` / `-k`，分发站常挂 CloudFront、GCP HTTP(S) LB 之后。
- 本地 Python 3 标准库即可（`zipfile` + `plistlib`），不依赖 Xcode / openssl。

## 2. 取分发清单（itms-services）

```bash
curl -k --path-as-is -H 'User-Agent: curl/8.21' \
     https://<分发域>/IOSDownload_1/ios.plist
```

通常返回 `Content-Type: application/x-plist`，形如：

```xml
<key>bundle-identifier</key><string>com.xxx.yyy</string>
<key>bundle-version</key><string>1.0.0.2</string>
<key>kind</key><string>software</string>
<key>title</key><string>...</string>
<key>url</key><string>https://<分发域>/IOSDownload_1/ios.ipa</string>
```

记下 manifest 里的 `bundle-identifier` / `bundle-version`，后面要和 IPA 内 Info.plist 对账（不一致 = 分发链版本管理失序）。

## 3. 探活并下载 IPA

```bash
curl -k --path-as-is -H 'Range: bytes=0-0' -I https://<分发域>/IOSDownload_1/ios.ipa
# 期望 HTTP/1.1 200（或 206）+ Content-Length: <总字节数> + ETag / Last-Modified
curl -k --path-as-is -H 'User-Agent: curl/8.21' \
     -o ios.ipa https://<分发域>/IOSDownload_1/ios.ipa
```

`file ios.ipa` / 头 4 字节应为 `PK\x03\x04`。无需任何鉴权。

## 4. 解包与解析（脚本）

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ipa_provision_audit.py —— iOS 分发链 / 签名身份审计（纯标准库）
用法:
    python ipa_provision_audit.py https://host/IOSDownload_1/ios.ipa
    python ipa_provision_audit.py ./ios.ipa
"""
import os, plistlib, sys, urllib.request, zipfile

UA = {"User-Agent": "curl/8.21"}
XML_START, XML_END = b"<?xml", b"</plist>"


def probe(url):
    req = urllib.request.Request(url, headers={**UA, "Range": "bytes=0-0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        print("[probe] status=%s len=%s etag=%s lastmod=%s" % (
            r.status, r.headers.get("Content-Length"),
            r.headers.get("Etag"), r.headers.get("Last-Modified")))


def fetch(url, path="ios.ipa"):
    if os.path.exists(path) and os.path.getsize(path) > 0:
        print("[cache]", path, os.path.getsize(path))
        return path
    req = urllib.request.Request(url, headers=UA)
    n = 0
    with urllib.request.urlopen(req, timeout=300) as r, open(path, "wb") as f:
        while True:
            b = r.read(1 << 20)
            if not b:
                break
            f.write(b)
            n += len(b)
    print("[dl]", path, n)
    return path


def carve_plist(raw):
    """mobileprovision 是 CMS(PKCS#7) 容器，plistlib 不能直接吃，必须 carve 内嵌 XML。"""
    i = raw.find(XML_START)
    j = raw.rfind(XML_END)
    if i < 0 or j < 0:
        raise ValueError("no embedded XML plist in mobileprovision")
    return plistlib.loads(raw[i:j + len(XML_END)])


def audit(ipa_path):
    with zipfile.ZipFile(ipa_path) as zf:
        names = zf.namelist()
        prof = [n for n in names if n.endswith(".app/embedded.mobileprovision")]
        info = [n for n in names if n.endswith(".app/Info.plist")]
        if not prof:
            print("[!] 无 embedded.mobileprovision（App Store 包 / 越狱包？改看 _CodeSignature/CodeResources）")
            return
        prof_name, info_name = prof[0], info[0]
        raw = zf.read(prof_name)
        print("[profile]", prof_name, len(raw), "bytes (CMS)")
        pl = carve_plist(raw)
        inf = plistlib.loads(zf.read(info_name))

    ent = pl.get("Entitlements", {})
    fields = {
        "Name": pl.get("Name"),
        "AppIDName": pl.get("AppIDName"),
        "TeamIdentifier": pl.get("TeamIdentifier"),
        "TeamName": pl.get("TeamName"),
        "application-identifier": ent.get("application-identifier"),
        "ProvisionsAllDevices": pl.get("ProvisionsAllDevices"),
        "ProvisionedDevices": pl.get("ProvisionedDevices"),
        "ExpirationDate": pl.get("ExpirationDate"),
        "associated-domains": ent.get("com.apple.developer.associated-domains"),
        "keychain-access-groups": ent.get("keychain-access-groups"),
        "get-task-allow": ent.get("get-task-allow"),
    }
    for k, v in fields.items():
        print("%-22s = %r" % (k, v))

    bid = inf.get("CFBundleIdentifier")
    ver = inf.get("CFBundleShortVersionString")
    ats = (inf.get("NSAppTransportSecurity") or {}).get("NSAllowsArbitraryLoads")
    schemes = [s for d in inf.get("CFBundleURLTypes", []) for s in d.get("CFBundleURLSchemes", [])]
    print("\n[Info.plist] bundle=%s version=%s ATS_arbitrary=%r schemes=%r" % (bid, ver, ats, schemes))

    print("\n[判定]")
    inhouse = pl.get("ProvisionsAllDevices") is True and not pl.get("ProvisionedDevices")
    print("  企业 in-house 且无 UDID 白名单（任意设备可装）:", inhouse)
    appid = ent.get("application-identifier") or ""
    prefix = (pl.get("TeamIdentifier") or [""])[0]
    print("  签名身份与 App 包名不一致（借用/代签特征）:",
          bool(prefix) and not appid.endswith("." + str(bid)))
    print("  通配 associated-domains（通用链接归属面放大）:",
          ent.get("com.apple.developer.associated-domains") == "*")
    print("  关闭 ATS:", ats is True)


if __name__ == "__main__":
    a = sys.argv[1]
    if a.startswith("http"):
        probe(a)
        a = fetch(a)
    audit(a)
```

## 5. 本次实操的真实读数（第三方组织名与 TeamID 已替换为占位）

```
Name                = com.<第三方>.LEARN<YYYYMMDD>   # 第三方组织命名空间，非本 App
AppIDName           = <第三方>Help
TeamIdentifier      = ['<TEAMID>']
TeamName            = <第三方企业名>
application-identifier = <TEAMID>.com.<第三方>.LEARN
ProvisionsAllDevices= True
ProvisionedDevices  = None
ExpirationDate      = <一年期>
associated-domains  = "*"
keychain-access-groups = ['<TEAMID>.*', 'com.apple.token']
get-task-allow      = False

[Info.plist] bundle=<本 App 反向域名> version=1.0.0.8 ATS_arbitrary=True schemes=[<本 App deeplink>]
```

要点：**App 自己的 bundle id 与签名 profile 的 App ID 根本不是一个东西**，且 TeamName / AppIDName 与业务无关 —— 这就是"第三方企业证书借用"的硬证据。

## 6. 影响与定级

| 现象 | 影响 |
|---|---|
| 企业 in-house + `ProvisionsAllDevices=True` + 无 UDID 白名单 | 完全绕过 App Store 审核，任意 iOS 设备可直接安装；劣质/恶意包可无门槛扩散 |
| 签名身份归第三方组织 | 包来源不可自证（运营方无法证明是自己签的）；任何持有该企业证书者都能签发同身份可信 App；Apple 或证书持有方任一吊销，全部存量用户无法更新/重装 |
| `associated-domains = "*"` | 通用链接（Universal Link）归属面被放大，钓鱼 / 口令劫持面扩大（需真机另验） |
| `NSAllowsArbitraryLoads = true` | 全明文 HTTP 放行，MITM 面扩大 |
| manifest 版本（如 1.0.0.2）≠ Info.plist 版本（如 1.0.0.8） | 分发链版本管理失序，可被用来投递旧版/降级包 |

定级 high：属于供应链/分发链缺陷，不是单点 RCE，但为后续投毒、仿签、强制下线提供了结构性条件。

## 7. 常见踩坑

1. **`plistlib.loads(mobileprovision)` 直接报 `InvalidFileException`** —— 它是 CMS/PKCS#7 二进制，必须 carve 内嵌 `<?xml ... </plist>`（本脚本 `carve_plist`）。
2. **`Info.plist` 是 `bplist00`** —— `plistlib` 自动识别，不用转格式。
3. **包里没有 `embedded.mobileprovision`** —— App Store 重签包或越狱包；改看 `Payload/*.app/_CodeSignature/CodeResources`，或在 macOS 上 `codesign -d --entitlements :- <app>`。
4. **`.ipa` 下不下来** —— 先 `Range: bytes=0-0` 探活；分发站常挂 CDN/LB，直连被拒时换出口代理或 `--resolve <domain>:443:<ip>`，并保留 `--path-as-is`、`-k`。
5. **zip 里 `Payload/` 下有多个 `.app`** —— 取与 manifest `bundle-identifier` 匹配的那个，别拿 framework 里的 `Info.plist`。
6. **别只看 entitlements 下结论** —— `get-task-allow=false` 是正常发布配置，不构成问题；真正的判据是 Team 身份、设备白名单、App ID 归属三者。

```
