# Mystic BBS 1.12 A48 注册关闭判据：newuser 屏仍显示、答 Yes 即 16B(ESC[?1000l+8BS)+断开；guest 有口令墙 → 无法自建账号

- **code**: mystic-bbs-1.12-a48-注册关闭判据-newuser-屏仍显示-答-yes-即-16b-esc-100
- **kind**: poc
- **category**: protocol
- **component**: Mystic BBS 1.12 A48
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-12T01:31–01:35Z，bbs.retro32.com:1337（213.254.180.5）7 次连接复测：随机 alias 提交后仍显示 newuser 屏 "Create an account with this BBS? Yes No"（当时文本为 "This BBS is currently under bot attack, so automated new user sign up has temporarily been disabled..."）；发 'y' 单字节 0.2s 内仅收 16 字节 1b5b3f313030306c0808080808080808 后 EOF（真实 telnet 显示 Connection closed by foreign host）；发 'n'/CR 均 4.3KB 重绘并回到 alias 提示；guest 返回 "Enter your password:"。与 Mystic 源码 bbs_user.pas CreateNewUser 的 If Not bbsCfg.AllowNewUsers Then OutFile('nonewusr')+Halt(0) 完全吻合。原始日志 /opt/artex/data/tasks/12/i3450/probe3450.log + probe3450_raw_P*.log + pty3450.log。
- **path**: pocs/mystic-bbs-1.12-a48-注册关闭判据-newuser-屏仍显示-答-yes-即-16b-esc-100/poc.txt
- **tags**: mystic,bbs,telnet,registration,allownewusers,zip-slip,negative
- **created_at**: 2026-11-12T01:36:53.060Z
- **engine**: bbs.retro32.com:1337 / 213.254.180.5

## 用法

```
遇到 Mystic BBS 登录面要建账号时：① 随机 alias 看 newuser 屏；② 发 'y'（单字节，勿带 CR）——若 0.2s 内只回 16B `1b5b3f313030306c`+8×BS 后断开，即 bbsCfg.AllowNewUsers=False，自建账号不可行，无客户端绕过（GetYN 任何 Yes 分支都进 CreateNewUser→Halt）；③ 'n'/CR 回 alias 提示属正常控制组；④ guest 若返回 "Enter your password:" 说明有口令墙；⑤ 此类目标刷新 user 显示文件即可改文案（本次 4 小时内从标准文本改为 bot-attack 提示），出现 "bot attack" 字样应立即停止高频连接。
```

## 正文

```
判据与阴性结论（实测）：
- 注册关闭时 newuser 屏仍会显示（Mystic 先打印 newuser 文案再问 Yes/No，AllowNewUsers 检查在 Yes 之后）。
- Yes 路径（'y' 热键、或方向键选中后 CR）→ CreateNewUser 首行 If Not bbsCfg.AllowNewUsers → OutFile('nonewusr') + Halt(0)。线上观测=仅 16 字节 ESC[?1000l + 0x08×8 后 TCP EOF（nonewusr 文件缺失时为零文本）。
- 控制组：'n'=4398B、CR=4365B，均重绘 banner 回到 "[þ] Enter your alias/handle:"（说明会话与提示本身正常）。
- guest 账号存在但必须有口令（121B 含 "Enter your password:"）。
- 因此依赖"登录账号→文件区上传/View"的链路（Zmodem zip-slip、[V] virtual archive disk 解包）在注册关闭期间不可执行，属环境阻断而非阴性；不要反复连接试探（本次目标已改文案声明 under bot attack）。
```
