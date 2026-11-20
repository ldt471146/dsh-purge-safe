---
name: analyzing-browser-forensics-with-hindsight
description: 使用 Hindsight 分析基于 Chromium 的浏览器痕迹，从 Chrome、Edge、Brave 和 Opera 中提取浏览历史、下载记录、Cookie、缓存内容、自动填充数据、已保存密码和浏览器扩展，用于取证调查。
domain: cybersecurity
subdomain: digital-forensics
tags: [browser-forensics, hindsight, chrome-forensics, chromium, edge, browsing-history, cookies, downloads, cache, web-artifacts]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# 使用 Hindsight 分析浏览器取证

## 概述

Hindsight 是一款开源浏览器取证（Browser Forensics）工具，专为解析 Google Chrome 和其他基于 Chromium 的浏览器（Microsoft Edge、Brave、Opera、Vivaldi）的痕迹而设计。它从多个浏览器数据库文件中提取和关联数据，创建统一的网络活动时间线。Hindsight 可以解析 URL、下载历史、缓存记录、书签、自动填充记录、已保存密码、浏览器偏好设置、浏览器扩展、HTTP Cookie、本地存储（HTML5 Cookie）、登录数据以及会话/标签信息。该工具以多种输出格式（XLSX、JSON、SQLite）生成按时间顺序排列的时间线，使调查人员能够重建用户网络活动，适用于事件响应（Incident Response）、内部威胁调查和刑事案件。

## 前置条件

- Python 3.8+ 并安装 Hindsight（`pip install pyhindsight`）
- 可访问取证镜像中的浏览器配置文件目录
- 浏览器配置文件数据（未使用操作系统级加密）
- 用于分析的 Timeline Explorer 或电子表格应用程序

## 浏览器配置文件位置

| 浏览器 | Windows 配置文件路径 |
|--------|---------------------|
| Chrome | %LOCALAPPDATA%\Google\Chrome\User Data\Default\ |
| Edge | %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\ |
| Brave | %LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\ |
| Opera | %APPDATA%\Opera Software\Opera Stable\ |
| Vivaldi | %LOCALAPPDATA%\Vivaldi\User Data\Default\ |
| Chrome (macOS) | ~/Library/Application Support/Google/Chrome/Default/ |
| Chrome (Linux) | ~/.config/google-chrome/Default/ |

## 关键痕迹文件

| 文件 | 内容 |
|------|------|
| History | URL 访问记录、下载记录、关键词搜索 |
| Cookies | 带域名、过期时间和值的 HTTP Cookie |
| Web Data | 自动填充条目、已保存的信用卡 |
| Login Data | 已保存的用户名/密码（已加密） |
| Bookmarks | JSON 格式的书签树 |
| Preferences | 浏览器配置和扩展 |
| Local Storage/ | 每个域名的 HTML5 本地存储 |
| Session Storage/ | 每个域名的会话专属存储 |
| Network Action Predictor | 之前输入过的 URL |
| Shortcuts | 地址栏快捷方式和预测 |
| Top Sites | 常访问的网站 |

## 运行 Hindsight

### 命令行

```bash
# 基本的 Chrome 配置文件分析
hindsight.exe -i "C:\Evidence\Users\suspect\AppData\Local\Google\Chrome\User Data\Default" -o C:\Output\chrome_analysis

# 指定浏览器类型
hindsight.exe -i "/path/to/profile" -o /output/analysis -b Chrome

# JSON 输出格式
hindsight.exe -i "C:\Evidence\Chrome\Default" -o C:\Output\chrome --format jsonl

# 带缓存解析（较慢但更完整）
hindsight.exe -i "C:\Evidence\Chrome\Default" -o C:\Output\chrome --cache
```

### Web 界面

```bash
# 启动 Hindsight Web 界面
hindsight_gui.exe
# 访问 http://localhost:8080
# 上传或指向浏览器配置文件目录
# 配置输出格式和分析选项
# 生成并下载报告
```

## 痕迹分析详情

### URL 历史与访问记录

```sql
-- Chrome History 数据库结构（关键表）
-- urls 表: id, url, title, visit_count, typed_count, last_visit_time
-- visits 表: id, url, visit_time, from_visit, transition, segment_id

-- 时间戳为 Chrome/WebKit 格式：自 1601-01-01 起的微秒数
-- 转换: datetime((visit_time/1000000)-11644473600, 'unixepoch')
```

### 下载历史

```sql
-- downloads 表: id, current_path, target_path, start_time, end_time,
--   received_bytes, total_bytes, state, danger_type, interrupt_reason,
--   url, referrer, tab_url, mime_type, original_mime_type
```

### Cookie 分析

```sql
-- cookies 表: creation_utc, host_key, name, value, encrypted_value,
--   path, expires_utc, is_secure, is_httponly, last_access_utc,
--   has_expires, is_persistent, priority, samesite
```

## Python 分析脚本

```python
import sqlite3
import os
import json
import sys
from datetime import datetime, timedelta


CHROME_EPOCH = datetime(1601, 1, 1)


def chrome_time_to_datetime(chrome_ts: int):
    """Convert Chrome timestamp to datetime."""
    if chrome_ts == 0:
        return None
    try:
        return CHROME_EPOCH + timedelta(microseconds=chrome_ts)
    except (OverflowError, OSError):
        return None


def analyze_chrome_history(profile_path: str, output_dir: str) -> dict:
    """Analyze Chrome History database for forensic evidence."""
    history_db = os.path.join(profile_path, "History")
    if not os.path.exists(history_db):
        return {"error": "History database not found"}

    os.makedirs(output_dir, exist_ok=True)
    conn = sqlite3.connect(f"file:{history_db}?mode=ro", uri=True)

    # URL visits with timestamps
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.url, u.title, v.visit_time, u.visit_count,
               v.transition & 0xFF as transition_type
        FROM visits v JOIN urls u ON v.url = u.id
        ORDER BY v.visit_time DESC LIMIT 5000
    """)
    visits = [{
        "url": r[0], "title": r[1],
        "visit_time": str(chrome_time_to_datetime(r[2])),
        "total_visits": r[3], "transition": r[4]
    } for r in cursor.fetchall()]

    # Downloads
    cursor.execute("""
        SELECT target_path, tab_url, start_time, end_time,
               received_bytes, total_bytes, mime_type, state
        FROM downloads ORDER BY start_time DESC LIMIT 1000
    """)
    downloads = [{
        "path": r[0], "source_url": r[1],
        "start_time": str(chrome_time_to_datetime(r[2])),
        "end_time": str(chrome_time_to_datetime(r[3])),
        "received_bytes": r[4], "total_bytes": r[5],
        "mime_type": r[6], "state": r[7]
    } for r in cursor.fetchall()]

    # Keyword searches
    cursor.execute("""
        SELECT k.term, u.url, k.url_id
        FROM keyword_search_terms k JOIN urls u ON k.url_id = u.id
        ORDER BY u.last_visit_time DESC LIMIT 1000
    """)
    searches = [{"term": r[0], "url": r[1]} for r in cursor.fetchall()]

    conn.close()

    report = {
        "analysis_timestamp": datetime.now().isoformat(),
        "profile_path": profile_path,
        "total_visits": len(visits),
        "total_downloads": len(downloads),
        "total_searches": len(searches),
        "visits": visits,
        "downloads": downloads,
        "searches": searches
    }

    report_path = os.path.join(output_dir, "browser_forensics.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    return report


def main():
    if len(sys.argv) < 3:
        print("Usage: python process.py <chrome_profile_path> <output_dir>")
        sys.exit(1)
    analyze_chrome_history(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    main()
```

## 参考资料

- Hindsight GitHub: https://github.com/obsidianforensics/hindsight
- Chrome 取证指南: https://allenace.medium.com/hindsight-chrome-forensics-made-simple-425db99fa5ed
- 浏览器取证工具: https://www.cyberforensicacademy.com/blog/browser-forensics-tools-how-to-extract-user-activity
- Chromium 源码 (History): https://source.chromium.org/chromium/chromium/src/+/main:components/history/
