# Mystic BBS 1.12 A48 telnet 交互协议：多字符热键必须逐字节发送（整串 sendall 丢尾字节），单前缀键无限期 pending，CR 是唯一干净取消键

- **code**: mystic-bbs-1.12-a48-telnet-交互协议-多字符热键必须逐字节发送-整串-sendall-丢尾字节
- **kind**: poc
- **category**: protocol
- **component**: Mystic BBS 1.12 A48
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 在 bbs.retro32.com:1337 Mystic BBS 1.12 A48 上实测（2026-11-11）：HD 逐字节 0x48,0x44→1535B 进入 Help Desk；WHO 逐字节→1469B 进入 Who's Online；WHO 整串一次 sendall→仅回显 0x57 0x48（2B）并停在 pending（尾字节 O 丢失）；单发 H→回显1B 停 "Command -> H" 超 8s 无超时；随后 ESC/q/z 全 0B 无效；单发 CR→3516B 主菜单整屏重绘取消 pending。日志 /opt/artex/data/tasks/12/i1933/phaseA2|B1|K1|L1.log。
- **tags**: mystic-bbs, telnet, hotkey, protocol, interaction, bbs
- **created_at**: 2026-11-11T18:19:06.164Z
- **engine**: bbs.retro32.com:1337 (213.254.180.5)

## 描述

Mystic BBS 主菜单是热键式输入（非行输入）：命令可多字符（HD/WHO/XX/NW//N//S//P），服务器按前缀树匹配，对同一 TCP 段里多余/尾随字节会丢弃，导致整串 sendall 的后几个字符丢失、命令不触发。前缀匹配成功前会无限期等待（无超时），且 ESC/q/未知键都不能取消。正确用法：逐字节发送、每键间隔 150–300ms、不主动附加回车；若误发单前缀键导致 pending，发一个 CR 即可取消并重绘主菜单。

## 用法

```
Python: s.sendall(bytes([0x48])); time.sleep(0.25); s.sendall(bytes([0x44]))  # HD=Help Desk，不用发回车。收尾/取消 pending: s.sendall(b'\r')。telnet 协商可一律拒绝（DO→WONT, WILL→DONT）。主菜单命令：M 消息菜单、F 文件区、D 门径、S 新闻、L 最近呼叫、NW/I interBBS wall、U 用户列表、9 last99、A 账户设置、B BBS列表、E/T/R/Y 排行、HD 帮助、XX 广告、/N 聊天、WHO 在线、/S 发消息给节点、/P 与节点聊天、/G 快速下线。Mystic 对无权限/未知命令是零字节静默拒绝（无 Access denied 文案），判据要用"屏幕实际变化+原始字节"。
```
