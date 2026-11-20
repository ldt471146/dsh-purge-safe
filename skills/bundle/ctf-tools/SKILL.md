---
name: ctf-tools
description: 'CTF 编码/解码/加解密瑞士军刀（qianxiao996/CTF-Tools）：URL/Unicode/Escape/HTML/ASCII/Shellcode/qwerty、图片转 Base64/Hex、Base16/32/36/58/62/64/自定义64/85(ASCII85,RFC1924)/91/92、JSFuck/JJEncode/AAEncode/jother/百家姓/核心价值观、Rot13/Rot47/凯撒/栅栏(含W型)/培根/摩斯/云影/当铺/四方/仿射/a1z26/维吉尼亚/埃特巴什/与佛论禅、2~36 任意进制转换。用于 CTF misc/crypto 题、把一坨怪字符串按特征试解、口令/配置项的编码还原、flag 变形识别。'
---

# CTF 编解码工具箱（CTF-Tools）

## 一、在哪、能不能用（本机实测 2026-10-23）

| 项 | 值 |
|---|---|
| 素材根目录 | `C:\Users\Administrator\.dsh\skills-src\qianxiao996__CTF-Tools\CTF-Tools-master` |
| 压缩包 | `C:\Users\Administrator\.dsh\skills-src\_zip-archive-removed\qianxiao996__CTF-Tools.zip` |
| 入口（GUI） | `CTF-Tools.py`（PyQt5，**本机未装 PyQt5，别急着起 GUI**） |
| 给 agent 用的入口 | `module/func_decode.py` `Class_Decode`、`module/func_encode.py` `Class_Encode`、`module/func_decrypt.py` `Class_Decrypt`、`module/func_encrypt.py` `Class_Encrypt` |
| 依赖状态 | 已装：base36 / base58 / base62(来自 `base_62`) / base91 / PyExecJS / py7zr / pycryptodome；**缺**：`py3base92`（本机 pip 索引没有）、PyQt5、js2py（3.12 不兼容，见下） |

**为跑通做过的两处兼容（已落盘，别删）**：
1. `CTF-Tools-master/py3base92.py` —— 占位模块。缺它 `import py3base92` 会让 `Class_Decode` **整体导入失败**（90+ 个编解码全废）。装到真包后删掉它即可。
2. `CTF-Tools-master/js2py.py` —— js2py 0.74 在 Python 3.12 上 `import` 就抛 `KeyError: 3`。垫片把 `EvalJs().execute(js)` / `js_dr.func(...)` 翻译成「写临时 .js + 调 node」，**只依赖 node**（本机 v26.8.1）。实测 `func_jjencode` 编码→解码可闭环。

## 二、直接调（不用 GUI）

```powershell
cd "C:\Users\Administrator\.dsh\skills-src\qianxiao996__CTF-Tools\CTF-Tools-master"
$env:PYTHONIOENCODING='utf-8'      # 不加这句中文结果会是乱码/报 UnicodeEncodeError
python -W ignore -c "import sys;sys.path.insert(0,'.');from module.func_decode import Class_Decode;print(Class_Decode().func_base64('utf-8','5L2g5aW9'))"
```

脚本模板（一次问多个，省进程启动）：

```python
import sys; sys.path.insert(0, r"C:\Users\Administrator\.dsh\skills-src\qianxiao996__CTF-Tools\CTF-Tools-master")
from module.func_decode  import Class_Decode
from module.func_encode  import Class_Encode
from module.func_decrypt import Class_Decrypt
from module.func_encrypt import Class_Encrypt
d, e, de, en = Class_Decode(), Class_Encode(), Class_Decrypt(), Class_Encrypt()
print(d.func_base64('utf-8', '5L2g5aW9'))    # [1, '你好', 'Base64']
```

**返回约定统一是 `[状态, 结果, 方法名]`**：`状态=1` 成功、`0` 失败（失败也带原因，可直接当"这不是该编码"的判据，批量试解时很好用）。

**参数约定（重要）**：除个别带密钥的方法外，签名都是 `(encode_type, source_text)`：
- `encode_type` 是**输入文本的字符编码**，中文/UTF-8 内容传 `'utf-8'`。
- 带密钥的：`func_base64_zidingyi(encode_type, source_text, n)`、`func_vigenere(encode_type, source_text, key)`、`func_sifang(encode_type, source_text, key1, key2)`、`func_yufolunchan_v2(encode_type, source_text, key)`。
- 别猜：`python -c "import inspect;print(inspect.signature(类().func_xxx))"`。

## 三、能力清单（`dir()` 实测：解码 28 / 编码 28 / 解密 20 / 加密 15）

| 类别 | 方法（`Class_*` 上的 `func_*`） |
|---|---|
| 通用解码 | `func_url` `func_unicode` `func_escape_u` `func_html` `func_Hex_Str` `func_ASCII_2/8/10/16` `func_shellcode` `func_qwerty` `func_jsfuck` `func_jjencode` `func_aaencode` `func_jother` `func_baijiaxing`(百家姓) `func_Socialism`(核心价值观) |
| Base 家族 | `func_base16/32/36/58/62/64/64_zidingyi/91/92`、`func_bae85_ASCII85`、`func_bae85_RFC1924` |
| 古典密码（解密） | `func_rot13/rot5/rot18/rot47`、`func_kaisa`(固定 -3 移位，**只能字母数字**)、`func_zhalan` `func_zhalan_w`(栅栏/W型，会枚举所有因数)、`func_peigen` `func_mosi` `func_yunying`(云影) `func_dangpu`(当铺) `func_sifang`(四方) `func_fangshe`(仿射) `func_a1z26` `func_vigenere` `func_atbash` `func_Polybius`(棋盘) `func_yiwei`(移位) `func_yufolunchan_v1/v2`(与佛论禅) |
| 进制转换 | `func_ASCII_*` 系列 + GUI 里的 2/8/10/16 互转（任意进制走 GUI 或自写 `int(s,base)`） |

## 四、拿到一坨怪字符串：按特征路由（先看长相，再动手）

| 长相 | 先试 |
|---|---|
| `%E4%BD%A0` | `func_url` |
| `\u4f60` / `%u4f60` | `func_unicode` / `func_escape_u` |
| `&#20320;` `&lt;` | `func_html` |
| `5L2g5aW9` 结尾带 `=` 或纯 `A-Za-z0-9+/` | `func_base64`（先试，再试 base32/58/62/91/92） |
| 全是 `0x`/纯 hex | `func_Hex_Str` |
| `\x90\x90` / `\x41\x42` | `func_shellcode` |
| 只有 `[]()!+` | `func_jsfuck` |
| `$=~[];$={___` | `func_jjencode` |
| `(ﾟДﾟ) ['_'] (` | `func_aaencode` |
| `()[][+[]]` 一堆括号 | `func_jother` |
| `佛曰：` / `如是我闻：` | `func_yufolunchan_v1` / `v2`（v2 需 key） |
| `.... . .-..` | `func_mosi` |
| `0123456789` 分组 | `func_yunying`（云影） |
| 汉字/数字混排像"田""由""甲" | `func_dangpu`（当铺） |
| `abcdefg` 类字母串 | `func_kaisa` → `func_atbash` → `func_zhalan` → `func_vigenere` |
| 不确定 | 直接全量跑一遍（见下） |

批量试解模板：

```python
import sys; sys.path.insert(0, ROOT)
from module.func_decode import Class_Decode
d = Class_Decode(); s = "<密文>"
for name in [n for n in dir(d) if n.startswith('func_') and n not in ('func_base92',)]:
    try:
        r = getattr(d, name)('utf-8', s)
        if r and r[0] == 1 and r[1] and r[1] != s:
            print(f'{name:22} -> {r[1][:80]}')
    except Exception:
        pass
```

## 五、坑

- **PowerShell 显示中文乱码**：`Get-Content` 默认按 ANSI(GBK) 解码 UTF-8 文件 → 加 `-Encoding utf8`。别被"源码是 GBK"骗了，文件其实是 UTF-8。
- **`SyntaxWarning: invalid escape sequence '\s'`**：源码里塞了 JS 正则字符串，无害，`-W ignore` 掉即可。
- **不要 `pip install js2py`**（已验证 3.12 崩）；也不要删 `js2py.py` 垫片，否则 JSFuck/JJEncode/AAEncode 全挂。
- **Base92 目前不可用**（`py3base92` 装不上）：`func_base92` 会抛 `NotImplementedError`。需要时用在线工具或自己实现。
- **GUI 起不来是正常的**：`python CTF-Tools.py` 需要 PyQt5 + 桌面。本机是命令行场景，直接调 `Class_*`。
- 插件机制：`Plugins/Plugins.json` 里登记 `run(source_text, UI_1, UI_2)`，只有 GUI 用得上，命令行忽略。

## 六、跟别的技能怎么串

- 密文是**混淆过的 JS**（不是编码） → 用 `js-deobfuscator`（AST 级还原）。
- 密文是**某产品的数据库/配置口令** → 用 `decrypt-tools`（22 类国产 OA/中间件）。
- 需要跑大量变体、要落库/造字典 → 配 `pwsh` 批量循环，结果写文件再判。
