# SSH 通用 top-N 弱口令有界验证全阴 + fail2ban 阈值量化（OpenSSH 9.6p1 Ubuntu）

- **code**: ssh-通用-top-n-弱口令有界验证全阴-fail2ban-阈值量化-openssh-9.6p1-ubuntu
- **kind**: poc
- **category**: weak-password
- **component**: OpenSSH 9.6p1 Ubuntu-3ubuntu13.20
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 对 88.208.224.249:22（OpenSSH 9.6p1 Ubuntu-3ubuntu13.20）实测：root 基线 5 次 + goffsgames×40/root×30/admin×20/visionhost×7 通用 top-N（rockyou 风格 97 条）= 103 次有效失败口令，全部回显 "Permission denied (publickey,password)."，p50 6.02s、max 8.62s，无 reset/timeout/延时爬升；随后 18:33:40 banner 仍正常且再试仍 Permission denied。18 分钟窗口内 103 次失败零封禁。
- **tags**: ssh,weak-password,fail2ban,negative,closed
- **created_at**: 2026-11-11T18:34:33.428Z
- **engine**: 88.208.224.249:22

## 描述

对暴露 SSH 做通用弱口令验证时的实测判据：单线程 sshpass + ssh（PreferredAuthentications=password、PubkeyAuthentication=no、NumberOfPasswordPrompts=1、StrictHostKeyChecking=no），每次间隔 3s。基线先测 5 次明显错误口令记录耗时/文案，再按最可能的系统用户名分级投通用 top-N。本目标 103 次有效失败、约 18 分钟窗口内无任何 fail2ban/限速痕迹（无 Connection reset、无 timeout、单次 4.3–8.6s 稳定），可判定其 22 端口 fail2ban 阈值 >103 次/18min 或未部署。注意与同主机 Plesk 面板的 IP 级聚合锁定（约 20 次/5min）相互独立。

## 用法

```
sshpass -p "$P" ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR "$U"@<IP> 'id'；逐次记录耗时并分类 AUTH_FAIL/CONN_ANOMALY/TIMEOUT，异常即停。
```
