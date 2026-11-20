---
name: cszh-hunting-for-defense-evasion-via-timestomping
description: 通过比较 MFT 中的 $STANDARD_INFORMATION 与 $FILE_NAME 时间戳， 检测 NTFS 时间戳篡改（MITRE T1070.006）。
---

> 本技能源自中文网络安全技能库 killvxk/cybersecurity-skills-zh（上游目录 hunting-for-defense-evasion-via-timestomping），正文按中文原文照录。

**这个技能干什么**：通过比较 MFT 中的 $STANDARD_INFORMATION 与 $FILE_NAME 时间戳， 检测 NTFS 时间戳篡改（MITRE T1070.006）。

**什么时候用**：需要按上游中文方法论执行「hunting-for-defense-evasion-via-timestomping」对应任务时加载本技能。

**关键工具**：见正文各章节列出的命令与工具清单。

# 狩猎通过时间戳篡改进行的防御规避

通过分析 NTFS MFT 条目中 $STANDARD_INFORMATION 和 $FILE_NAME 属性之间的差异来检测时间戳篡改。
