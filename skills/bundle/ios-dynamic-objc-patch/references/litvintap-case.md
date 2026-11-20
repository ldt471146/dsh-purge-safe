# 案例：LitvinTap（kurwa.tipa）—— 卡密门禁绕过 v2

样本：iOS arm64 Mach-O，30.9 MB，bundle `com.Litvin.TapS`，iOS 15+。
App 是手游外挂（ImGui + Metal），启动时弹 “Welcome back / LICENSE KEY” 卡密面板。

## 一、加固特征（决定打法）

- `__TEXT,__objc_methname` 有选择器，但**类没有 method list**：约 2390 次
  `class_replaceMethod(cls, sel, IMP, types)` 在启动时装方法；
- 类名是 16 进制乱码（`objc_getClass("a9e81931783742210a47a")`），selector 字符串在 `__DATA` 加密；
- 函数全是 CFF 状态机 + MBA；
- 诱饵 section：`__ai_notice` / `__compliance` / `__legal` / `__secrets` / `__config`(`BYPASS_DRM=0`) / `__easteregg`，
  域名一律 `.invalid`，`_LTDRMServer_get_server_public_key` 返回 base64 的 "Never gonna give you up…"。

## 二、定位到的关键 IMP（VA，基址 0x100000000）

| 方法 | IMP | 怎么定位的 |
|---|---|---|
| `-[LTGateViewController loginTapped:]` | `0x1005D3328` | 引用其 block invoke `0x10101C624` 的宿主函数 |
| `-[LTGateViewController acceptKey:]` | `0x1005D77AC` | 引用 block invoke `0x101022B40`；函数体发 `rememberKey:` / `startHeartbeat` / `successPulse` / `tearDownAnimated:` |
| `-[LTAccessGateContainer installGate:fading:]` | `0x10033B8FC` | block invoke `0x100DC861C`；函数体发 `addChildViewController:` / `setAlpha:` / `animateWithDuration:...` |
| `-[LTAccessGateContainer resumeWithKey:]` | `0x100332414` | block invoke `0x100DBEC20`；函数体建 `UIActivityIndicatorView` |
| `-[LTAccessGateContainer switchToLaunchpad]` | `0x100340434` | block invoke `0x100DCD9C0`；函数体 `insertSubview:atIndex:` / `insertSubview:belowSubview:` |
| `-[LTAccessGateContainer lockOut]` | `0x10033E680` | block invoke `0x100DCBDEC` |
| `-[LTAccessGateContainer showJailbreakAlert]` | `0x100345518` | block invoke `0x100DCFC20` |
| `_LTDRMServer_check_premium_status_cached` | `0x100FC7E3C` | 符号名；尾部 `ldr w0,[sp,#4]` → 返回 int |

启动编排在 `0x10032394C`（0x7100 字节巨型方法），同时发 `installGate:fading:`(0x100327FBC)、
`makeGate`、`resumeWithKey:`(0x10032818C)、`lockOut`、`showJailbreakAlert`。

## 三、选择器槽（写 stub 用）

| selector | selref 槽 |
|---|---|
| `keyField` | `0x101A471F0` |
| `text` | `0x101A450C8` |
| `acceptKey:` | `0x101A47388` |
| `resumeWithKey:` | `0x101A453F8` |

`_objc_msgSend` stub：`0x101516B78`（`__stubs` + `__got` chained-fixup ordinal 解出）

## 四、代码洞

`0x101A006BC`（`__eh_frame` 结束后、`__DATA_CONST` 之前的页内零填充，仍在可执行段内）。
本 App 有 7 处 ≥0x120 连续零区，都可用。

## 五、v1（错）与 v2（对）

```
v1:  installGate:fading: -> b switchToLaunchpad      # 跳过初始化 -> 能进但白屏/无菜单
     check_premium_status_cached -> mov w0,#1; ret  # 启动即判定已授权 -> 同样白屏
v2:  loginTapped: -> b 0x101A006BC (stub)            # 只换“点登录”这一下的行为
     stub: [self acceptKey:self.keyField.text]
     resumeWithKey: -> b switchToLaunchpad           # 成功链下游放行
     lockOut -> ret
     showJailbreakAlert -> b switchToLaunchpad
```

v2 stub 字节（0x101A006BC 起 0x5C 字节，capstone 已回读校验）：

```
fd7bbea9 fd030091 f35301a9 f30300aa 210200f0 21f840f9 2959ec97 a00100b4
f40300aa 210200b0 216440f9 e00314aa 2359ec97 e00000b4 e20300aa 210200f0
21c441f9 e00313aa 1d59ec97 1f2003d5 f35341a9 fd7bc2a8 c0035fd6
```
（`0x101A006BC` 处实测字节，小端 32 位字）

反汇编：

```
stp  x29,x30,[sp,#-0x20]! ; mov x29,sp ; stp x19,x20,[sp,#0x10]
mov  x19,x0
adrp x1,0x101a47000 ; ldr x1,[x1,#0x1f0]   @selector(keyField)
bl   0x101516b78 (objc_msgSend) ; cbz x0, bail
mov  x20,x0
adrp x1,0x101a45000 ; ldr x1,[x1,#0xc8]    @selector(text)
mov  x0,x20 ; bl objc_msgSend ; cbz x0, bail
mov  x2,x0
adrp x1,0x101a47000 ; ldr x1,[x1,#0x388]   @selector(acceptKey:)
mov  x0,x19 ; bl objc_msgSend
bail: ldp x19,x20,[sp,#0x10] ; ldp x29,x30,[sp],#0x20 ; ret
```

## 六、打包与使用

- 反汇编校验 → 重新 zip（`Payload/LitvinTap.app/…`，20 个文件条目即可）
- 必须重签：Sideloadly / AltStore / TrollOS / `codesign -f -s -`
- 使用：进面板 → 输入框随便打 1 个字符（空值被 `cbz` 挡回原逻辑）→ Login

## 七、遗留风险

`acceptKey:` 内部同时有 `successPulse` 与 `errorPulse` 两条分支；若仍有二次校验，
下一个补丁点就是它内部那条判定（或 `-[LTAuth redeemKey:completion:]` 的完成回调用到的
`LTAuthResponse` 属性 getter）。
内容密钥 `_LTDRMServer_derive_content_key` 从正版 token 派生，绕过门禁 ≠ 拿到内容密钥。
