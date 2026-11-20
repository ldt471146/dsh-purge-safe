# isolated-vm 垫片（decode_action 专用）

上游 `smallfawn/decode_action` 把 `isolated-vm` 写成硬依赖，而它是**原生插件**：

- 装它要 MSVC Build Tools + node-gyp：本机实测 `npm i` 直接
  `npm error gyp ERR! stack Error: Could not find any Visual Studio installation to use`
  （`node-gyp -v 12.4.0`、`node -v v26.8.1`），整个 `npm install` 会**整体回滚**，连 babel 都装不上；
- node 26 的 ABI 也没有现成预编译包。

而插件的实际用法只有 3 个 API（`grep ivm\\.` 实测）：

```
obfuscator.js / sojson.js / sojsonv7.js
  const isolate = new ivm.Isolate()
  const globalContext = isolate.createContextSync()
  function virtualGlobalEval(jsStr) { return globalContext.evalSync(String(jsStr)) }
visitor/jsconfuser/*.js
  const isolate = new ivm.Isolate()   // 同样只做字符串求值
```

所以用 `node:vm` 等价替换 —— 语义上不再是"隔离进程"，但**执行同样的字符串、返回同样的值**，对"跑混淆器的字符串解密函数"这一用途足够。

## 落盘位置与内容

`<decode_action-main>/node_modules/isolated-vm/package.json`

```json
{
  "name": "isolated-vm",
  "version": "4.7.2-shim",
  "description": "Minimal node:vm based drop-in shim for the isolated-vm API subset used by decode_action.",
  "main": "isolated-vm.js",
  "type": "commonjs"
}
```

`<decode_action-main>/node_modules/isolated-vm/isolated-vm.js`

```js
'use strict';
const vm = require('node:vm');

class Context {
  constructor() {
    this._ctx = vm.createContext(Object.create(null));
    this.global = {};
  }
  evalSync(code) {
    return vm.runInContext(String(code), this._ctx, {
      timeout: 5000, displayErrors: true, breakOnSigint: false,
    });
  }
  eval(code) { return this.evalSync(code); }
}

class Isolate {
  constructor(options = {}) { this.options = options; this._contexts = []; }
  createContextSync() { const c = new Context(); this._contexts.push(c); return c; }
  dispose() { this._contexts = []; }
}

module.exports = { Isolate, Context };
module.exports.default = module.exports;
```

`"type": "commonjs"` 是必需的：decode_action 是 ESM（`"type": "module"`），`import ivm from 'isolated-vm'` 走 CJS 互操作，`default` 指向 `module.exports`，所以 `ivm.Isolate` 可用。

## 安装依赖的正确姿势

```powershell
cd <decode_action-main>
npm i --no-audit --no-fund --ignore-scripts      # --ignore-scripts 防止又去编 isolated-vm
# 若 node_modules/isolated-vm 被 npm 覆盖成空壳/坏壳，按上面两个文件重建
node src/main.js -i input.js -o output.js
```

## 实测结果（2026-10-23）

```
输入 input.js          213,746 B
输出 output.js          55,418 B
stderr 末行            使用插件 sojsonv7 成功处理并写入文件 output.js
还原动作                扁平化还原 ×13、提高代码可读性、Unused variable、解除环境限制、净化完成
```

## 什么时候该换回真包

- 需要**真正隔离**（跑不受信任的混淆代码、担心原型污染/进程逃逸）时；
- 混淆器用到 `Isolate` 的其它 API（`compileScript`、`new Context`、`ExternalCopy`）时 —— 当前垫片没实现，会 `undefined is not a function`。

换法：装 VS Build Tools（含 C++ 生成工具）→ 用 Node 18/20 → 删掉手写目录重装。
