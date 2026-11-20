# 单请求型隧道下的内网渗透方法论（op=chk 主机发现 + 目标侧 PHP 绕过多轮协议限制）

- **code**: 单请求型隧道下的内网渗透方法论-op-chk-主机发现-目标侧-php-绕过多轮协议限制
- **kind**: script
- **category**: tunnel
- **component**: PHP WebShell 自建 SOCKS5 隧道（op=req 单请求模式）
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 example 演练内网（经 example.com 冰蝎马 + PHP socket 隧道）全程实测：op=chk 扫完 203.0.113.52/24 全 254 IP（133s）得 7 台存活；LOAD_FILE 读出 ifcfg-eth0/eth1、hosts.allow、target103.example.com 等网段铁证；目标侧 PHP 完成 fsockopen banner 抓取、PMAP_DUMP、mysql_connect 认证、NFSv4 COMPOUND。
- **path**: pocs/单请求型隧道下的内网渗透方法论-op-chk-主机发现-目标侧-php-绕过多轮协议限制/poc.py
- **tags**: 内网渗透,隧道,WebShell,op=chk,NFS,RPC,open_basedir绕过,主机发现,静默失败,eval马,冰蝎
- **created_at**: 2026-09-30T15:27:53.125Z
- **found_by**: internal

## 描述

在单请求型 WebShell 隧道（不支持持久连接）下做内网渗透的四条落地技巧：op=chk 主机发现、目标侧 PHP 驱动多轮协议、LOAD_FILE 绕过 open_basedir 读网段配置、RPC/NFS 枚举。★★ 附一条最易误判的『静默失败』坑：冰蝎这类 eval 型马用 -f 传带 <?php ... ?> 标签的文件时，eval 触发 parse error，而马开头的 @error_reporting(0) 会把错误静默吞掉 —— 表现为 HTTP 200 但 len=0，极易被误判成『马挂了/目标不通』。实测同一 payload 写成纯语句（不带标签）即正常回显。排查顺序：① 先发 echo 'A1X'; 这类最短 payload 验证协议与 key（本环境 key=md5(密码)[:16]，XOR 为 key[(i+1)&15]）；② 再逐步加长度与函数；③ 确认 GET 探活（存在=200/0B、不存在=404/1143B）区分『马是否还在』。另：POST body 长度与 file_get_contents/scandir/php_uname 等关键字均实测不触发拦截，排除这两种假设后再怀疑 WAF。

## 用法

```
1) 主机发现：python runs/rt_net.py -i 203.0.113.52/24 -p 80 -w 6 -o runs/scan.txt
2) 读网段铁证：python runs/pq3.py "(SELECT LOAD_FILE('/etc/sysconfig/network-scripts/ifcfg-eth1'))"
3) 目标侧多轮协议：把 PHP 代码交给 WebShell 执行（如 python runs/rt_php.py -f runs/p5.php）
   ★ 用 -f 传文件时必须剥掉 <?php / ?> 标签，否则 eval 触发 parse error 且被 @error_reporting(0) 静默吞掉（表现为 HTTP 200 但 len=0）
4) 能力枚举先行：先 function_exists('mysql_connect'|'ftp_connect'|'curl_init'|'socket_create') 再决定用哪条协议
```

## 正文

```
# 场景
只有一条「一次 HTTP 请求 = 一次内网请求-响应」的自建隧道（无持久连接、单 Session 串行，
典型于 PHP/ASP 类 WebShell 隧道；suo5 只支持 Java/.NET 服务端时只能自建）。
此时 gogo/fscan 直接 -t 高并发会大面积超时并伪造"端口关闭"假象（实测 gogo 每端口约 9s）。

# 技巧一：用隧道端点的 op=chk 做低成本主机发现（0.4s/次）
隧道端点若支持"端口连通性判定"模式，直接 HTTP GET 它，用**错误类型**区分状态：
  OK                       -> 端口开放
  E:Connection refused     -> 主机存活、端口关闭   ★ 存活判据
  E:No route to host       -> 同段该 IP 无主机
  E:Connection timed out   -> 跨段被过滤（注意：默认路由同样 timeout，**不可据此判定新网段存在**）
批量脚本见 runs/rt_net.py（多线程 6 即可，每个请求在目标侧独立建连）。

# 技巧二：★ 把探测逻辑搬到目标侧 PHP 执行（绕开 op=req 限制的核心）
WebShell 所在主机的 PHP 往往具备完整网络扩展。先枚举能力：
  mysql_connect / mysqli_connect / ftp_connect / curl_init / socket_create / fsockopen / pfsockopen
PHP 进程在内网直连，**由 PHP 自己维持同一条 TCP 完成多轮往返**，结果一次性回显
=> FTP/MySQL/RPC/NFS/任意多轮协议全部可用，且内网 RTT≈0，远快于经隧道。
命令执行若被 safe_mode 禁掉不影响这条路（网络函数不属命令执行）。

# 技巧三：马受 open_basedir 限制时，改用 MySQL 的 LOAD_FILE 读系统文件
PHP open_basedir（如 docroot:/tmp:/some/ad/）会挡掉 /etc、/proc；
但 mysqld 的 LOAD_FILE 不受其限制，且 5.0 无 secure_file_priv：
  SELECT LOAD_FILE('/etc/hosts');        -- 主机名/别名
  SELECT LOAD_FILE('/etc/sysconfig/network-scripts/ifcfg-eth1');  -- ★ 网段铁证
  SELECT LOAD_FILE('/etc/hosts.allow');  -- 运维白名单
  SELECT GROUP_CONCAT(DISTINCT host) FROM mysql.user;             -- ★ 内网客户端清单
注意：/proc/* 用 LOAD_FILE 读回空（procfs size=0），不要依赖它。

# 技巧四：RPC/NFS 枚举（无 mountd 时）
PMAP_DUMP(prog=100000 vers=2 proc=4) 一次列出全部注册服务及端口；
RPC over TCP 需 4 字节 record marking（0x80000000|len）；XDR 头 28 字节后接链表。
若列表中无 mountd(100005)，则 showmount/MOUNT EXPORT 不通，只剩 NFSv4 伪根(PUTROOTFH=24)；
AUTH_NULL 可能 MSG_DENIED，可再试 AUTH_UNIX(flavor=1, stamp+ns(machine)+uid+gid+gids_len)。

```
