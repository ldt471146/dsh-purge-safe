# 网段存活探测纪律：nmap -Pn 会把全部 IP 判为 up，必须用 -sn 复核

- **code**: 网段存活探测纪律-nmap-pn-会把全部-ip-判为-up-必须用-sn-复核
- **kind**: script
- **category**: recon
- **component**: nmap
- **severity**: info
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 实测复核：同一网段 203.0.113.30/24，`-Pn -sT` 报 256 hosts up，`-sn -T4` 报 40 hosts up，28 台有开放端口（runs/nmap-154-23-180.txt）。差异原因明确为 -Pn 跳过存活探测。
- **path**: pocs/网段存活探测纪律-nmap-pn-会把全部-ip-判为-up-必须用-sn-复核/poc.sh
- **tags**: nmap,存活探测,假阳性,纪律,-Pn
- **created_at**: 2026-09-28T20:42:33.847Z
- **found_by**: vuln-scan

## 描述

nmap 的 -Pn 会跳过存活探测并把网段内每个 IP 都判为 up，导致"256 台全存活"这类假阳性；必须用 nmap -sn 复核真实存活数。

## 用法

```
每次扫网段后，把 -Pn 的结果里的 hosts up 数字丢掉，改用 `nmap -sn -T4 --max-rate 200 <CIDR>` 复核；或用"有开放端口的主机数"近似。实例：203.0.113.30/24 的 -Pn 显示 256 up，-sn 复核为 40 up（28 台有开放端口）。
```

## 正文

```
## 现象
`nmap -Pn -sT -p ... 203.0.113.30/24` 的结果里写 `Nmap done: 256 IP addresses (256 hosts up)` —— **看起来全段都活着**。

## 根因
`-Pn` 的作用是**跳过主机存活探测、假定每个目标都 up**。因此 nmap 对该网段里每一个不存在的 IP 也会打印 `Host is up`。这个数字**不能当作存活数**。

## 正确做法（复核命令）
```bash
nmap -sn -T4 --max-rate 200 203.0.113.30/24
# 真实输出：Nmap done: 256 IP addresses (40 hosts up) scanned in 10.82 seconds
```
- `-sn` = ping 扫描（不发端口包），得到**真实存活数**；
- 或者用有开放端口的资产集合近似存活集（本次：256 台里只有 **28 台**有开放端口）；
- 两者差异（40 vs 28）= 12 台"ping 通但没扫到开放端口"的机器，属于正常。

## 纪律
**报告里绝不出现未复核的存活数字。** `-Pn` 扫出来的 "hosts up" 一律视为假阳性，必须用 `-sn` 复核后再写进报告/落库。
```
