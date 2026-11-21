# Unity/ILRuntime 热更链无签名校验 → 客户端代码执行（判定 + 复现手册）

## 0. 结论形态
漏洞不是“某个接口能打”，而是**热更通道的信任根 = 传输通道本身**：
- 客户端只在“服务端下发的 md5”和“本地 PlayerPrefs 里上一轮存下的 md5”之间做自引用比对；
- 清单(md5/版本号/文件列表)、版本门限(mustUpdataVersion)、补丁 md5 全部来自同一份服务端数据；
- 下载用 `UnityWebRequest.Get`，无证书钉扎、无 RSA/ECDSA 验签、无包体/APK 签名校验；
- 热更基址 `abUrl` 取自本地 `PlayerPrefs`（`GameUtils.GetString("abUrl")`）；
- ILRuntime 热更程序集（`ifix/assembly-csharppatch.bytes`）与 `config.ab`、`config/Language/*.ab` 走同一条下载/落地通道。

于是一旦处于 MITM 位置（同 Wi-Fi / 恶意 AP / 劫持 DNS）或能改写本地 `abUrl`，即可向客户端投放任意 AssetBundle 与热更 C# 程序集 → 客户端代码执行；且因为 md5 也来自攻击者清单，服务端后续“必须更新到 spX.X”的校验同步失效。

## 1. 前置条件 / 指纹
- 目标是 Unity 出包，`assets/` 下存在 `Asset.upk`、`updatecode.ab` 之类打包的托管代码；
- 热更框架为 ILRuntime（有 `assembly-csharppatch.bytes`、`config.ab`、`AssetBundle manifest`）；
- Android 清单 `usesCleartextTraffic=true` 且无 `networkSecurityConfig`（明文下载 AB 的口子）；
- 客户端本地存有 `abUrl` / `lastVersionMd5` / `spversion` 三个 PlayerPrefs 键。

## 2. 取样本（离线，无需真机）
```bash
# 1) 解 APK
python -m zipfile -e target.apk out/
ls out/assets | head            # 找 Asset.upk / updatecode.ab / 类似打包文件

# 2) 从 AB/upk 中 carve 出 PE（托管 DLL）。按 'MZ' 魔数切、按 e_lfanew 校验 PE\0\0，
#    再确认可选头 Magic=0x10b 且数据目录[14] (CLI Header) 非零。
python carve_pe.py out/assets/updatecode.ab  out/carved/    # 见 §3 脚本
file out/carved/*.dll           # 期望: PE32 executable (DLL) (console) Intel 80386, for MS Windows
```
判据：命中 `assembly=Update_Project`（或同类更新程序集名）、`PE+CLI v4.0.30319`。

## 3. 反编译 IL（dnfile + dncil）
```bash
pip install dnfile==0.18.0 dncil
```
```python
# il_dump.py —— 打印选定 TypeDef 下所有方法体的 IL
import sys, dnfile
from dncil.cil.body import CilMethodBody
from dncil.cil.body.reader import CilMethodBodyReaderBase

class Reader(CilMethodBodyReaderBase):
    def __init__(self, pe, offset):
        self.pe, self.offset = pe, offset
    def read(self, n):
        d = self.pe.__data__[self.offset:self.offset + n]
        if len(d) != n:
            raise IOError("short read")
        self.offset += n
        return d
    def seek(self, offset): self.offset = offset
    def tell(self): return self.offset

pe = dnfile.dnPE(sys.argv[1])
want = set(sys.argv[2:])  # 例如 UpdateMgr DownLoadMgr
for t in pe.net.mdtables.TypeDef:
    if t.TypeName not in want:
        continue
    print(f"\n=== {t.TypeNamespace}.{t.TypeName} ===")
    for m in t.MethodList:
        if not m or m.Rva == 0:
            continue
        try:
            body = CilMethodBody(Reader(pe, pe.get_offset_from_rva(m.Rva)))
        except Exception as e:
            print(f"-- {m.Name}: <无法解析 {e}>")
            continue
        print(f"\n-- {m.Name}  rva=0x{m.Rva:x}")
        for insn in body.instructions:
            print(f"   {insn.offset:06x}  {insn.opcode}  {insn.operand}")
```
```bash
python il_dump.py out/carved/unity.update_*.dll UpdateMgr DownLoadMgr > il_all.txt
```
编译器生成的迭代器是真正逻辑所在，用 TypeDef 索引定位（同程序集内序号会变，按名字 grep）：
`<CheckUpdate>d__NN`、`<GetABList>d__NN`、`<GetPatchVersion>d__NN`、`<DownLoadAB>d__NN`、`<DownloadAsset>d__NN`。

## 4. 关键 IL 判据（照此逐条核对）

### 4.1 <GetPatchVersion>：补丁 md5 的唯一来源是服务端自己
```
UnityWebRequest.Get(AbConfigs.get_OnlinePatchVersionPath() + "?" + Random(0,11000))
  → 200 → 反序列化 PatchVersionData
  → 按 GameUtils.UNITY_IOS 选 iosVersion / androidVersion
  → onlineVersion[tmpVersion]
  → ldstr 'lastVersionMd5' ; ABPatchInfo::md5 ; GameUtils::GetString
  → stfld onlinePatchVersionMD5
```
**没有**任何硬编码公钥/系统签名参与期望值的计算 —— 期望 md5 与待下载文件同源，攻击者可控。

### 4.2 <CheckUpdate>：清单无签名，只比版本号大小
```
GameUtils.GetString('abUrl','')            // 本地 PlayerPrefs 即热更基址
  → 赋给 AbConfigs.resServerdomain
UnityWebRequest.Get(AbConfigs.get_OnlineManifestPath())
  → 200 → writeFile(LocalManifestPath + 'TMP')
  → GameUtils.GetFileHash(...)  → stfld onlineManifestMD5
  → AssetBundle.LoadFromMemory(下载字节)   // 直接当 trusted manifest 用
  → GetAsset('AssetBundlemanifest') → onlineManifest
  → 仅比较 float(mustUpdataVersion) > float(localVersion from PlayerPrefs 'spversion')
```
注意：`GetFileHash` 算出来的 `onlineManifestMD5` **不用于和任何独立基准比对**，等于无校验。

### 4.3 <DownLoadAB>：服务端清单原样落盘
```
if (totalCount <= 0) { writeFile(AbConfigs.LocalManifestPath, data); /* 重新加载 */ }
```
本地清单被服务端（或中间人）数据全覆盖，没有本地二次确认。

### 4.4 <DownloadAsset>：md5 自覆盖 + 热更程序集走同一通道
```
对 ifix/assembly-csharppatch.bytes、config.ab、config/Language/*.ab 逐个 CleanAssetBundleByName 后下载
末尾: if (onlinePatchVersionMD5 非空) {
    stfld localPatchVersionMD5;
    GameUtils.SetString('lastVersionMd5', onlinePatchVersionMD5);
    CheckPackage();
}
```
→ 下一轮 `lastVersionMd5` 已是攻击者清单里的值，自引用比对永远成立。

### 4.5 全程序集否定项（必须搜完才能下结论）
在 IL 文本/字符串表里搜：
```
VerifyData | CheckSignature | RSA | ECDSA | X509 | ServerCertificateCustomValidationCallback
| CertificateHandler | certificateHandler | PublicKey | Modulus | Exponent
```
本次样本：**全部未命中**；唯一命中 `RSADecryptCards`（卡牌资源解密），与更新链无关。
即：无包体验签、无证书钉扎、无清单签名。

## 5. 利用路径（两种，任选）
**A. 中间人**（优先，零落地）：
- 条件：客户端明文下载 + 无钉扎。同 Wi-Fi / 恶意热点 / DNS 劫持 / 上游设备接管均可；
- 动作：拦截 `OnlinePatchVersionPath`、`OnlineManifestPath` 与 AB 下载请求，返回攻击者构造的补丁清单 + `assembly-csharppatch.bytes` + `config.ab`；
- 清单里的 md5 填成攻击者文件真实 md5，`mustUpdataVersion` 抬到高于本地 `spversion`。
- 结果：客户端走完 DownloadAsset → CheckPackage → 加载并执行 ILRuntime 程序集。

**B. 本地配置改写**（需一次本地写原语 / 备份恢复 / 调试接口）：
- 改 `PlayerPrefs` 中的 `abUrl` 指向攻击者 HTTP(S) 服务器，其余同上；
- 适用于已经有本地文件写、adb、或恶意 App 同设备等前置。

**投递物最小化**：先只放一个“写文件/打日志/回连 canary”的程序集，验证执行链通，不要一上来放破坏性代码。

## 6. 失败时的常见原因
| 现象 | 原因 |
|---|---|
| 清单请求回 200 但客户端不下载 | `mustUpdataVersion` 不大于本地 `spversion`；要同时改版本号 |
| 下载了但没执行 | 只替换了 AB 没替换 `assembly-csharppatch.bytes`，或 ILRuntime 加载的是 DLL 而非 AB 内 asset，需确认路径大小写 |
| 报 md5 不匹配 | 常见于清单 md5 与实际文件不一致；先用同算法（`GameUtils.GetFileHash` 通常是 MD5）离线算好 |
| 明文流量被拦 | 目标可能强制 https；仍需检查是否有钉扎（本手册 §4.5），无钉扎则可用自签证书 MITM |
| 目录/语言包加载失败 | `CleanAssetBundleByName` 会先删旧文件，投递时要连同 `config/Language/*.ab` 的依赖一起给全 |
| 更新后又被服务端“纠正” | 检查是否还有一条独立于热更清单的 APK 版本强更逻辑（不在本程序集内） |

## 7. 证伪条件（出现任一则本结论不成立）
- `CheckPackage` / `DowloadPatch` / `DowloadFile` 中存在基于**独立可信源**的补丁验签（硬编码公钥、Android 系统签名、APK 签名校验）；
- `OnlineManifestPath` 强制 https 且实现证书钉扎，并在加载前验证清单签名；
- 热更程序集不由该 AB 通道下发（另有走系统更新的签名链路）。

## 8. 报告口径
- 归类：客户端热更新未校验（不安全更新通道 → 客户端代码执行），高危；
- 证据等级：静态 IL 证据链（可完整复现到指令级）> 真机投递（需授权且用 canary）；
- 不要写成“服务端 RCE”：影响面是**客户端**任意代码执行 + 更新完整性失效。
