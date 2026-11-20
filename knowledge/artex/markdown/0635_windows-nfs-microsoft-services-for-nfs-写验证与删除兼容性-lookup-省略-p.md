# Windows NFS（Microsoft Services for NFS）写验证与删除兼容性：LOOKUP 省略 post_op_fh3 布尔头、NFSv3 REMOVE 返 EIO 时用 NFSv2 REMOVE/RMDIR

- **code**: windows-nfs-microsoft-services-for-nfs-写验证与删除兼容性-lookup-省略-p
- **kind**: poc
- **category**: protocol
- **component**: NFS / mountd / Microsoft Windows NFS Server
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 17:50 UTC 实测：90.152.8.56:2049 /ENTERPRISE（AUTH_UNIX uid=0，经 CONNECT 代理 102.164.252.150:8080）MKDIR/CREATE status=0，WRITE 189B status=0 count=189 committed=1，READ 回读 bytes_equal=True；NFSv3 REMOVE 返 5(EIO)/RMDIR 66(NOTEMPTY)/SETATTR 13/RENAME 10007，改用 NFSv2(vers=2, REMOVE=proc10, RMDIR=proc15) 全部 status=0，最终无残留。同一服务器 LOOKUP3 回包在 status 后直接是 fhandle3 的 uint32 长度(0x20)+32 字节 fh，省略了标准 post_op_fh3 的 bool 头。
- **path**: pocs/windows-nfs-microsoft-services-for-nfs-写验证与删除兼容性-lookup-省略-p/poc.py
- **created_at**: 2026-11-11T18:02:48.282Z
- **engine**: 90.152.8.56 (dynamics-nav.shopto.net):2049 /ENTERPRISE

## 用法

```
自写 NFSv3 客户端流程：MOUNT MNT(/ENTERPRISE, prog 100005 vers 3 proc 1) → GETATTR → ACCESS(0x3f) → MKDIR → LOOKUP 取 dir fh（兼容无 bool 的 fh 编码）→ CREATE(how=UNCHECKED) → LOOKUP 取 file fh → WRITE(stable=FILE_SYNC) → READ 校验字节 → NFSv2 REMOVE/RMDIR 清理。参考实现落盘于 /opt/artex/data/tasks/4/i1826/nfs_lib.py（Tunnel 类支持经 HTTP CONNECT 代理的持久连接、nfs3 create/write/read/remove + nfs2 直接用 t.rpc(100003,2,10/15,...)）。
```

## 正文

```
在 Windows Server 的 Microsoft NFS 服务上做 NFSv3 写验证时踩到的两个坑与对策：

1) LOOKUP/CREATE/MKDIR 的 post_op_fh3 解析：标准 XDR 是 bool present + (opaque fhandle)；该实现回包里 status 之后直接是 uint32 长度 + fh（如 00000020 + 32B fh），没有 00000001 布尔头。按标准解析会得到 fh=None。写一个兼容分支：若下一 uint32 在 8..128 且 4+len 不越界，就当作 fh 长度直接读。

2) 删除：NFSv3 REMOVE 对 uid 映射为 nobody 的新建文件返回 status=5(NFS3ERR_IO)，RMDIR 返回 66(NFS3ERR_NOTEMPTY)，SETATTR mode 返回 13(EACCES)，RENAME 返回 10007(BADTYPE)。同一服务器上改用 NFSv2（prog 100003, vers=2, REMOVE=proc 10, RMDIR=proc 15；fh 用 32 字节定长不带 opaque 长度）全部返回 0，可正常删除测试产物。若必须清理且 v3 删不掉，先试 v2。

3) ACCESS(bits=0x3f) 返回 0x1f 并不可全信：该服务器对匿名映射仍报 MODIFY/EXTEND/DELETE，实际 DELETE 被后端 Windows ACL 拒绝（表现为 EIO 而非 EACCES），写验证要把"CREATE+WRITE+READ 回读一致"作为写权限判据，不要只信 ACCESS。

4) 大量 READ 可能触发目标对源 IP 的整机封禁；把写验证放在读之前或用可轮换的 CONNECT 代理出口。
```
