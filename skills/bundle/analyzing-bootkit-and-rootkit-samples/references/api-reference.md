# API 参考：Bootkit 和 Rootkit 分析工具

## dd - 引导扇区提取

### 语法
```bash
dd if=/dev/sda of=mbr.bin bs=512 count=1          # MBR
dd if=/dev/sda of=first_track.bin bs=512 count=63  # 第一磁道
dd if=/dev/sda1 of=vbr.bin bs=512 count=1          # VBR
```

## ndisasm - 16 位反汇编

### 语法
```bash
ndisasm -b16 mbr.bin > mbr_disasm.txt
ndisasm -b16 -o 0x7C00 mbr.bin   # 设置原点为 MBR 加载地址
```

### 主要标志
| 标志 | 说明 |
|------|-------------|
| `-b16` | 16 位实模式反汇编 |
| `-b32` | 32 位保护模式 |
| `-o` | 原点地址偏移 |

## UEFITool - 固件分析

### CLI 语法
```bash
UEFIExtract firmware.rom all             # 提取所有模块
UEFIExtract firmware.rom <GUID> body     # 提取特定模块主体
```

### 输出
将固件卷提取到目录树中，每个 DXE 驱动、PEI 模块和选项 ROM 作为独立文件，通过 GUID 标识。

## chipsec - 硬件安全评估

### 语法
```bash
python chipsec_main.py -m common.secureboot.variables  # 检查 Secure Boot
python chipsec_main.py -m common.bios_wp               # SPI 写保护
python chipsec_main.py -m common.spi_lock               # SPI 锁定状态
python chipsec_util.py spi dump firmware.rom            # 转储 SPI 闪存
```

### 主要模块
| 模块 | 用途 |
|--------|---------|
| `common.secureboot.variables` | 验证 Secure Boot 配置 |
| `common.bios_wp` | 检查 BIOS 写保护 |
| `common.spi_lock` | 验证 SPI 闪存锁定位 |
| `common.smm` | SMM 保护验证 |

## Volatility 3 - Rootkit 检测插件

### 语法
```bash
vol3 -f memory.dmp <plugin>
```

### Rootkit 检测插件
| 插件 | 用途 |
|--------|---------|
| `windows.ssdt` | 系统服务描述符表挂钩 |
| `windows.callbacks` | 内核回调注册 |
| `windows.driverscan` | 扫描驱动对象 |
| `windows.modules` | 列出已加载的内核模块 |
| `windows.psscan` | 池标签扫描进程（发现隐藏进程） |
| `windows.pslist` | 活动进程列表（受 DKOM 影响） |
| `windows.idt` | 中断描述符表挂钩 |

### 输出格式
```
Offset  Order  Module         Section  Owner
------- -----  ------         -------  -----
0x...   0      ntoskrnl.exe   .text    ntoskrnl.exe
0x...   73     UNKNOWN        -        rootkit.sys   ← 可疑
```

## flashrom - SPI 闪存转储

### 语法
```bash
flashrom -p internal -r firmware.rom     # 读取/转储
flashrom -p internal -w clean.rom        # 写入/重刷
flashrom -p internal --verify clean.rom  # 验证闪存内容
```

## YARA - 固件模式扫描

### 语法
```bash
yara -r uefi_malware.yar firmware.rom
yara -s -r rules.yar firmware.rom   # 显示匹配字符串
```
