---
name: js-deobfuscator
description: 'JS/Python 混淆还原（smallfawn/decode_action）：自动识别并还原 sojson(v6)/jsjiami、sojsonv7、obfuscator.io、jsconfuser、阿里云 awsc、jjencode、通用 common 混淆——还原字符串数组加密、控制流平坦化、不透明谓词、十六进制标识符、无用变量与死代码；支持 zlib/bz2/lzma 压缩载荷。用于把看不懂的 JS（加密参数、风控/签名算法、WebShell 管理端、钓鱼页、恶意脚本）还原成可读源码并提取接口与硬编码密钥。'
---

# JS 混淆还原（decode_action）

## 一、在哪、能不能用（本机实测 2026-10-23）

| 项 | 值 |
|---|---|
| 素材根目录 | `C:\Users\Administrator\.dsh\skills-src\smallfawn__decode_action\decode_action-main` |
| 入口 | `src/main.js`（ESM，`package.json` 里 `"type": "module"`） |
| 运行时 | Node **v26.8.1**（本机） |
| 已装依赖 | 157 个包（`@babel/parser|traverse|generator|types`、`base64url`、`crypto-js`、`vm2` 等） |
| **关键垫片** | `node_modules/isolated-vm/`（**自制**，node:vm 实现 `Isolate` / `createContextSync` / `evalSync`） |

**为什么需要垫片**：上游把 `isolated-vm` 写成硬依赖，它是**原生插件**，装它要 MSVC + node-gyp（本机 `npm i` 直接 `gyp ERR! Could not find any Visual Studio installation to use`），且 node 26 的 ABI 也没有预编译包。而插件只用到 3 个 API（`new ivm.Isolate()`、`createContextSync()`、`evalSync(str)`），所以用 `node:vm` 等价替换，**已实测可跑通**：

```
输入 213,746 B → 输出 55,418 B，插件识别为 sojsonv7
```

> 想用真 `isolated-vm`：换 Node 18/20 + 装 VS Build Tools，然后删掉那个手写目录重装。

## 二、跑起来

```powershell
cd "C:\Users\Administrator\.dsh\skills-src\smallfawn__decode_action\decode_action-main"
node src/main.js -i input.js -o output.js
```

- 只认 `-i` / `-o`（默认 `input.js` → `output.js`）。
- **`package.json` 里的 `npm run deso / desov7 / deob` 传的 `-t` 参数源码根本没解析**，别指望它强制指定插件 —— 实际永远是**自动探测**。
- 换目标文件：`node src/main.js -i "C:\path\to\target.js" -o "C:\path\to\clean.js"`。
- 输出首行会写时间戳与来源注释（decode-js / decode_action），留着便于溯源。

## 三、探测顺序与判定（`src/main.js` 实测）

```
obfuscator → sojsonv7 → sojson → jsconfuser → awsc → jjencode → common
```

- 依次调用，**第一个让代码发生变化（`code !== processedCode`）的插件胜出**，其余跳过，写入输出文件并在 stderr 打日志（`使用插件 sojsonv7 成功处理并写入文件 ...`）。
- 任一步抛异常会被 `try/catch` 吞掉继续下一个 —— 所以"没还原"先看 stderr，别以为脚本没跑。
- 特例：源码里出现 `smEcV` 会直接 `break`（针对某类"反还原"样本的短路）。

## 四、支持的混淆器

| 插件 | 对应上游 | 典型特征 |
|---|---|---|
| `sojson` | jsjiami v6 | `_0x...` 数组 + `while(!![])` 数组轮转 + `parseInt` 校验 |
| `sojsonv7` | jsjiami v7 | 同上 + 控制流平坦化 `_0x...['switch']`、`smEcV` 类短路 |
| `obfuscator` | obfuscator.io | `_0x` 十六进制标识符、string-array + rotation、不透明谓词 |
| `jsconfuser` | jsconfuser | 全局隐藏、重复字面量、字符串压缩、栈式控制流 |
| `awsc` | 阿里云混淆 | `awsc` 系（阿里云 WAF/JS 挑战常见） |
| `jjencode` | jjencode | `$=~[];$={___:++$...` |
| `common` | 通用兜底 | 简单 eval/十六进制/未分类 |

还原动作：`calculate-constant-exp`（常量折叠）、`split-sequence`/`split-assignment`（拆序列与赋值）、`delete-unused-var`、`delete-unreachable-code`、`delete-nested-blocks`、`prune-if-branch`、`parse-control-flow-storage`（平坦化还原）、`merge-object`、`calculate-rstring`。

## 五、也支持压缩载荷（Python 侧）

- `src/decode.py`：自适应 `zlib` / `bz2` / `lzma` 解压。GitHub Actions 模式下把脚本丢进 `input.py`，`output.py` 出结果；本机直接
  ```powershell
  python src/decode.py            # 看脚本里的入口参数，按需改输入文件名
  ```
- 典型场景：冰蝎/哥斯拉马、内存马加载器、CTF misc 里 `exec(zlib.decompress(base64.b64decode(...)))` 一层套一层。**先剥压缩再谈反混淆**。

## 六、失败排查（按顺序）

1. **`ERR_MODULE_NOT_FOUND: @babel/parser`** → 依赖没装：在该目录 `npm i --no-audit --no-fund --ignore-scripts`（`--ignore-scripts` 是关键，避免又去编 `isolated-vm`）。
2. **`Cannot find module 'isolated-vm'`** → 垫片被删了。重建 `node_modules/isolated-vm/{package.json,isolated-vm.js}`，内容见本技能同目录 `references/isolated-vm-shim.md`。
3. **跑完输出跟输入一样** → 该混淆器不在清单里，或字符串表被拆成多文件。换思路：`rea`（`analyze_web_bundle`）拉运行时 bundle，或用 `wakaru` 走真 source map 还原。
4. **输出仍是 `_0x`** → 只做了一次探测链路。把输出再喂一次（二次还原），或直接跑 `node src/main.js -i out.js -o out2.js`。
5. **中文乱** → 输出为 UTF-8；PowerShell 看文件加 `-Encoding utf8`。

## 七、边界（别把它当万灵药）

- 它是**语法/结构层**还原：能把字符串表、平坦化、死代码清掉，但**算法语义**（比如签名用什么 key）还得人读代码或动态跑。
- 有反调试/反格式化（`debugger;` 循环、`Function.prototype.toString` 检测）时，先静态改掉再跑，或直接在沙箱里跑。
- 网站线上 bundle（webpack/vite 分包）不是"混淆"，是**打包**：用 `reverse-engineer-anything` 技能的 `analyze_web_bundle` / `recover_javascript_sources`（Wakaru），别硬套本技能。
