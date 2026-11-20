# 前端混淆/Dart AOT 双路还原 WebSocket 上行协议（含心跳与可达性判定）

- **code**: 前端混淆-dart-aot-双路还原-websocket-上行协议-含心跳与可达性判定
- **kind**: script
- **category**: frontend-reverse
- **component**: 菠菜站群 /chatWs WebSocket（Flutter aocai_love_v3 + Vue wap 前端）
- **severity**: medium
- **language**: javascript
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com 上完整验证：① Node vm 沙箱成功执行 a10h 解码器并导出 4254 条明文字符串（runs/wap-decoded-full.txt）；② 逐索引还原出 sendMessage/socketOpen/initWebSocket 真实代码，拿到心跳内容 `"pong"`（0x100b）与 30 秒周期、Body/Target/Build 发送签名；③ APK 锚点法还原出 ChatSendEntity 等实体类与 312 条 API 路径；④ D 段判据实测有效：发 WS PING 后服务端回 op=10 (PONG)，证明帧格式正确，据此把「9 种格式全失败」的误判修正为「/chatWs 是纯下行通道」。适用于所有 obfuscator.io 型前端与 Flutter 应用的协议逆向。
- **path**: pocs/前端混淆-dart-aot-双路还原-websocket-上行协议-含心跳与可达性判定/ws_protocol_recover.md
- **tags**: websocket,混淆还原,flutter,dart-aot,协议逆向,obfuscator.io,心跳
- **created_at**: 2026-10-04T10:20:10.524Z
- **found_by**: exploit

## 描述

一整套「前端混淆解码器提取 + Flutter Dart AOT 协议还原 + WebSocket 上行可达性判定」方法：从混淆 JS/APK 还原客户端真实 WebSocket 协议（地址拼接、心跳、发送实体、消息类型），并用控制帧判据区分「格式错」与「服务端只推不收」。

## 用法

```
1) 存混淆 JS 为 wap-app.js，跑 A 段骨架脚本 → 得到 a10h 解码函数；
2) 对关注索引批量解码（`d(0x1234)`）→ 拼回混淆代码里的字符串片段 → 还原业务逻辑；
3) 关键索引先看：心跳内容、WS 地址拼接、cookie 名、发送方法名、messageType 枚举；
4) APK 场景改用 C 段锚点法（按 `package:<app>/xxx` 路径与 `_$XxxToJson@` 符号定位）；
5) 实测阶段用 D 段判据：先发 WS 控制帧 PING 验证协议层，再按还原格式发业务帧搜唯一标记。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""obfuscator.io 型前端混淆字符串解码器通用提取法 + Flutter Dart AOT 协议还原法。

== A. Web 前端混淆解码器提取（Node vm 沙箱执行）==
适用于 obfuscator.io（a1d/a10h 型字符串表 + base64 + 十六进制位移）：
  1. 从混淆 JS 中定位 `function aXXh(` 起点，到下一个顶层 `function aXXg(` 之后结束
  2. 用 Node vm 沙箱执行这段代码（注意：需要注入 window/document/navigator/location
     等假对象，否则整段 bundle 会因 `window is not defined` 抛错；但解码器本身已定义）
  3. 沙箱内 `sandbox.a10h` 即为解码函数，`sandbox.a10h(0x1234)` -> 明文字符串
  4. 批量导出：`for (i=0;i<sandbox.a10g().length;i++) lines.push(i+"\t"+a10h(i))`

代码骨架：
```js
const fs = require('fs'), vm = require('vm');
const src = fs.readFileSync('wap-app.js', 'utf8');
const s1 = src.indexOf('function a10h');
const s2 = src.indexOf('function a10g(');
let s3 = src.indexOf('\nfunction ', s2 + 10); if (s3 < 0) s3 = src.length;
const sandbox = { console, window:{}, document:{}, navigator:{}, location:{},
                  localStorage:{}, self:{}, globalThis:{} };
vm.createContext(sandbox);
vm.runInContext(src.slice(s1, s3), sandbox, { timeout: 30000 });
const d = sandbox.a10h;
console.log(d(0x100b));   // -> 还原出真实字符串
```

== B. 从解码结果还原业务逻辑（本例的 killer move）==
混淆代码里字符串被拆成 `gO(0x1234)+'NTERVAL'` 形式，逐索引解码后拼回原文即得客户端真实代码。
本例还原出：
```js
'sendMessage':function(){
  as['send'](
    new Y()['d19']({'msg': this['getTextMessage'](this.text)})   // d19='Body'
      ['setTarget'](this['getTargetUser']())                     // 1072='Target'
      ['setType']('ROOM_TEXT_MESSAGE')                           // 1187='Build'
  );
}
'socketOpen':function(){ ... setInterval(function(){ as['send']("pong"); }, 30000); }  // 100b='pong'
'initWebSocket':function(){ ... new Z['a'](CHAT_SERVER_URL+'/chatWs?token='+cookieToken, null, {reconnectInterval:3000}) }
```
→ 一次性拿到 WS 地址拼接、cookie 名、心跳内容与周期、发送方法签名、消息类型枚举。

== C. Flutter Dart AOT（libapp.so）协议还原 ==
1. `strings` 提取不可行（Dart AOT 字符串池是全局哈希序，邻居全是噪音）；
2. **正确做法是以业务类名为锚点定位符号**，例如：
   `grep -a 'aocai_love_v3/chatroom\|model/chatmessage'` 命中 `.dart` 路径与 `_$XxxToJson@<hash>` 符号；
3. 由符号还原出实体类清单（`ChatSendEntity`/`ChatReqEntity`/`ChatMsgEntity`）与 API 路径；
4. **从 so 里抽全量 API 路径**（正则 `/?[a-zA-Z][A-Za-z0-9_]*(/[A-Za-z][A-Za-z0-9_]*){0,3}/?`），APP 侧常有 Web 侧不存在的接口（本例挖出 `/message/getMessages`、`/message/getMsgIds`、`/attachment/uploadChat`）。

== D. WebSocket 上行可达性判定法（关键判据）==
不要只看"我的消息有没有被广播"，要**同时验证控制帧**：
  - 发 WS PING (opcode 0x9) → 若收到 PONG (opcode 0xA)，则**帧格式与协议层正确**，
    业务消息无回显只能说明"服务端不从该连接收业务消息"，而不是"格式错"；
  - 连接后前 6 秒统计服务端主动帧：若直接是业务广播且无 welcome/init/join-required 帧，
    则**排除缺 join 前置**的可能性；
  - 若两条都排除，即可判定该 WS 为 **Server→Client only 纯下行通道**，
    发送动作在 HTTP 侧（本例 `POST /aocai-api/ct/message` 返回 **405 Method Not Allowed**，
    是"路由存在但方法不匹配"的铁证，比 404 有价值得多）。
"""

```
