# Unity/ILRuntime iOS 热更链无签名校验 → 客户端代码执行（iOS 复用手册）

> 同源 Android 条目：`unity-ilruntime-hotupdate-selfref-md5-no-signature-client-co`（id 513）。
> 本条只记 **iOS 差异面**：样本载体（IPA → Asset.upk → UnityFS TextAsset）、基址来源（native 硬编码 http）、
> ATS 关闭、以及“远程不可利用”的判定边界。IL 解析脚本与通用失败排查沿用 513。

## 0. 结论形态

热更信任根 = 传输通道本身：

- 期望补丁 MD5 来自服务端 `PatchVersionData.iosVersion[k].md5`，对比对象 `lastVersionMd5` 也是上一轮
  服务端下发的值 → **自引用比对，永远成立**；
- 文件完整性只用 `GameUtils.GetFileHash` 对比同一份清单里的 `ABPackageData.mainList[i].md5`；
- 下载基址 = `abUrl[i] + '/v2/' + GameUtils.packageVersion (+ '/' + onlineVersion + '/' + curPlatformName)`，
  `abUrl` 在 **native 层硬编码为明文 http**（不是从本地配置读）；
- 全链路无 RSA/ECDSA、无 X509/SecTrust、无证书钉扎、无包体签名；
- `Info.plist` 关闭 ATS（`NSAllowsArbitraryLoads = true`）。

即：**谁能应答那条明文 HTTP 热更请求，谁就能让客户端 ILRuntime 加载任意热更 C# 程序集，
等价于客户端任意代码执行**；同时服务端后续"必须更新到 spX.X"的版本校验一并失效。

## 1. 前置条件 / 指纹

- Unity 出包，iOS 侧资源在 `Payload/<App>.app/Asset.upk`（或同名 AB）；
- 热更框架 ILRuntime（存在 `Unity.Update.dll` TextAsset、`config.ab`、`Assembly-CSharp` 补丁程序集）；
- Info.plist：`NSAppTransportSecurity → NSAllowsArbitraryLoads = true`；
- native 层可见明文 http 的补丁基址（形如 `http://<update-domain>/v2/<pkgver>/<spver>/Ios/*.upk`）；
- 托管程序集里存在 `Update_Project` 命名空间下的 `UpdateMgr` / `DownLoadMgr`。

## 2. 取样本（离线，无需真机）

```bash
# 1) 解 IPA（zip），进 .app
python -m zipfile -e ios.ipa out/
ls out/Payload/*.app | grep -i -E 'upk|\.ab$'

# 2) 解析 Asset.upk（UnityFS v8），导出 updatecode 下的 TextAsset
#    UnityPy 示例（按实际包结构定位 offset/长度）
python upk_unitypy.py out/Payload/App.app/Asset.upk --dump
# 目标：updatecode/unity.update.dll.bytes
#   TextAsset 名 'Unity.Update.dll'，164864B，
#   前 4 字节 4d5a9000（MZ），SHA256 EEA70BA3BF5D9310CA87CD3FEF17991C3DC91CD1D5075BDA954A3D46C40A43E
```

判据：carve 出的字节是 PE（`MZ` + `PE\0\0` + CLI Header 非零），`file` 报 `PE32 executable (DLL)`。

## 3. 反编译 IL（dnfile + dncil）

```bash
pip install dnfile==0.18.0 dncil
python il_dump.py unity.update.dll UpdateMgr DownLoadMgr > il_out.txt
```

（`il_dump.py` 见条目 513 §3；要点是用 `dnfile.dnPE` 打开，按 `TypeDef.MethodList` 取
`MethodDef.Rva`，用 `CilMethodBody` + 自定义 reader（`read` 从 `pe.__data__[offset:]` 取字节）解析。）

样本统计：207 TypeDef / 1528 MethodDef，`assembly = Update_Project`，PE + CLI v4.0.30319。

## 4. 关键 IL 判据（逐条核对）

### 4.1 GetDownloadFileList（rva 0x8fbc）——补丁期望值自引用

```
ldstr 'lastVersionMd5' → call IFix.Pksj.GameUtils::GetString → stfld localPatchVersionMD5
ldfld PatchVersionData::iosVersion … ldfld ABPatchInfo::md5
  → call System.String::op_Inequality → stfld onlinePatchVersionMD5
```

期望 MD5 的来源是服务端清单；比对基准是上一轮服务端写下的本地值。**没有任何独立可信锚参与。**

### 4.2 GetFixPackage（rva 0x9584）——完整性校验同源

```
call IFix.Pksj.GameUtils::GetFileHash
  → ldfld ABInfoData::md5 → op_Inequality → 失败列表
```

待验文件的哈希与"期望哈希"来自同一份可被中间人改写的清单。

### 4.3 DownLoadMgr.get_OnlineABRootPath（rva 0x98d8）——URL 拼接

```
ldfld F:resServerUrl
+ ldstr '/v2/'
+ GameUtils::packageVersion
+ UpdateMgr::onlineVersion
+ AbConfigs::curPlatformName
```

### 4.4 DownLoadMgr.DownLoadFileAB（rva 0x99cc）——直接起下载

```
拼 downloadName → newobj IFix.Pksj.MultiDownload::.ctor → call Start
```

### 4.5 否定项（必须搜完才能下结论）

在 IL 文本与字符串表中搜：

```
VerifyData | CheckSignature | RSA | ECDSA | X509 | SecTrust
| ServerCertificateCustomValidation | CertificateHandler | certificateHandler
| PublicKey | Modulus | Exponent
```

本样本：**全部零命中**。即无包体验签、无证书钉扎、无清单签名。

### 4.6 iOS 特有面

- `Info.plist`：`NSAllowsArbitraryLoads = true` → 明文 HTTP 不被 ATS 拦截；
- 补丁基址在 **native 层硬编码**（形如 `http://<update-domain>/v2/1.0.0.4/sp3.4/Ios/<md5>_sp3.4.upk`），
  与 Android 侧"abUrl 存在 PlayerPrefs"不同，iOS 侧没有本地改配置这条捷径，**只剩 MITM 一条**。

## 5. 利用路径

只有两条前置路径：

1. **客户端网络中间人**（唯一现实路径）：在受害者 Wi-Fi / 运营商链路上应答那条明文 HTTP 请求，
   返回自造补丁清单 + 恶意 AB/ILRuntime 程序集。清单字段与原格式一致，
   `md5` 指向自造文件真实哈希，版本号抬到高于本地 `spversion`。
2. **控制热更域**：接管其 DNS/源站后可对全体存量用户下发任意热更代码（危害更大，但通常不属授权范围）。

投递物最小化：先只放"回连 canary / 写日志"的程序集验证执行链，不要一上来放破坏性代码。

## 6. 可利用性判定（重要，避免误报）

- **远程、无中间人位置 → 不可实际利用**：拿不到服务器侧任何权限、会话、凭据、数据，
  也就没有 WebShell/隧道可登记。
- 本条性质是**客户端供应链/信任链缺陷**（client-side code execution），不是服务端 RCE。
- 若热更域是范围外第三方域（独立注册、Cloudflare 托管、`clientTransferProhibited`），
  只允许只读确认（GET/HEAD），**严禁写操作、爆破、接管**；亦不得对其做 PUT/上传。
- 实测参考：热更上游 HTTP 与 HTTPS 均返回 `520`（`Server: cloudflare`，`Content-Length: 16`），
  说明边缘在线但回源失败，当前热更内容不可获取；授权域 CDN 也不镜像 `/v2` 更新目录
  （`/v2/...` 返回 448/404）。若该状态持续，存量客户端无法更新，属**可用性风险**。

## 7. 失败时的常见原因

| 现象 | 原因 |
|---|---|
| 清单 200 但客户端不下载 | 版本号（`onlineVersion` / `mustUpdataVersion`）未高于本地，未进入更新分支 |
| 下载了但没执行 | 只替换了 AB，没替换 ILRuntime 热更程序集；或路径大小写/`downloadName` 拼接不符 |
| 报 MD5 不匹配 | 清单 md5 与实际文件不一致；须按 `GameUtils.GetFileHash` 同算法离线算好 |
| 明文流量被拦 | 目标侧若改为 https 且启用钉扎则本路径失效（见 §8 证伪条件） |
| 依赖缺失导致加载失败 | 需连同 `config.ab`、`config/Language/*.ab` 一起投递 |
| 上游 520 / 超时 | 回源失败，客户端拿不到清单；不是客户端校验导致 |

## 8. 证伪条件（出现任一则本条不成立）

- native 层实际强制 https **且**实现并强制证书钉扎（SecTrust/`ServerCertificateCustomValidation`）；
- IL 中存在基于**包内硬编码公钥**的 ECDSA/RSA 验签，且期望值不来自同一份待验清单；
- 热更程序集不由该 AB 通道下发（另有系统更新签名链路）。

## 9. 报告口径

- 归类：客户端热更新未校验（不安全更新通道 → 客户端代码执行），高危；
- 证据等级：静态 IL 证据链（可复现到指令级）> 真机投递（需授权 + canary）；
- 影响面：所有安装该版本的 iOS 用户；被利用即客户端本地任意代码执行（读通讯录/相册/剪贴板、
  劫持登录与支付流程、作为内网跳板），攻击者无需 App Store 或企业证书；
- 修复：①清单与 AB/程序集改 HTTPS + 证书钉扎；②包内硬编码公钥做 ECDSA/RSA 签名，
  期望值不得来自待验清单本身；③ILRuntime 加载前校验签名与白名单；④移除对第三方更新域的硬编码依赖。
