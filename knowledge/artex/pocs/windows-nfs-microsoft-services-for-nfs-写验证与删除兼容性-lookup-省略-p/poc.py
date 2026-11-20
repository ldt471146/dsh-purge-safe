在 Windows Server 的 Microsoft NFS 服务上做 NFSv3 写验证时踩到的两个坑与对策：

1) LOOKUP/CREATE/MKDIR 的 post_op_fh3 解析：标准 XDR 是 bool present + (opaque fhandle)；该实现回包里 status 之后直接是 uint32 长度 + fh（如 00000020 + 32B fh），没有 00000001 布尔头。按标准解析会得到 fh=None。写一个兼容分支：若下一 uint32 在 8..128 且 4+len 不越界，就当作 fh 长度直接读。

2) 删除：NFSv3 REMOVE 对 uid 映射为 nobody 的新建文件返回 status=5(NFS3ERR_IO)，RMDIR 返回 66(NFS3ERR_NOTEMPTY)，SETATTR mode 返回 13(EACCES)，RENAME 返回 10007(BADTYPE)。同一服务器上改用 NFSv2（prog 100003, vers=2, REMOVE=proc 10, RMDIR=proc 15；fh 用 32 字节定长不带 opaque 长度）全部返回 0，可正常删除测试产物。若必须清理且 v3 删不掉，先试 v2。

3) ACCESS(bits=0x3f) 返回 0x1f 并不可全信：该服务器对匿名映射仍报 MODIFY/EXTEND/DELETE，实际 DELETE 被后端 Windows ACL 拒绝（表现为 EIO 而非 EACCES），写验证要把"CREATE+WRITE+READ 回读一致"作为写权限判据，不要只信 ACCESS。

4) 大量 READ 可能触发目标对源 IP 的整机封禁；把写验证放在读之前或用可轮换的 CONNECT 代理出口。