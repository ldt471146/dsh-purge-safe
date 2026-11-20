# API 参考：使用 Hindsight 进行浏览器取证

## Hindsight CLI

### 语法
```bash
hindsight.py -i <profile_path>                  # 分析 Chrome 配置文件
hindsight.py -i <path> -o <output_dir>          # 保存结果
hindsight.py -i <path> -f xlsx                  # 导出为 Excel
hindsight.py -i <path> -f sqlite                # 导出为 SQLite
hindsight.py -i <path> -b <browser_type>        # 指定浏览器类型
```

### 浏览器类型
| 参数 | 浏览器 |
|------|--------|
| `Chrome` | Google Chrome |
| `Edge` | Microsoft Edge (Chromium) |
| `Brave` | Brave Browser |
| `Opera` | Opera (Chromium) |

### 输出痕迹
| 表名 | 描述 |
|------|------|
| `urls` | 带访问次数的浏览历史 |
| `downloads` | 带来源 URL 的文件下载记录 |
| `cookies` | Cookie 值、域名、过期时间 |
| `autofill` | 表单自动填充条目 |
| `bookmarks` | 已保存的书签 |
| `preferences` | 浏览器配置 |
| `local_storage` | 网站本地存储数据 |
| `login_data` | 已保存凭据的元数据 |
| `extensions` | 已安装的扩展及其权限 |

## Chrome SQLite 数据库

### History 数据库
```sql
-- 浏览历史
SELECT u.url, u.title, v.visit_time, v.transition
FROM visits v JOIN urls u ON v.url = u.id
ORDER BY v.visit_time DESC;

-- 下载记录
SELECT target_path, tab_url, total_bytes, start_time, danger_type, mime_type
FROM downloads ORDER BY start_time DESC;
```

### Cookies 数据库
```sql
SELECT host_key, name, value, creation_utc, expires_utc, is_secure, is_httponly
FROM cookies ORDER BY creation_utc DESC;
```

### Web Data 数据库（自动填充）
```sql
SELECT name, value, count, date_created, date_last_used
FROM autofill ORDER BY date_last_used DESC;
```

## Chrome 时间戳转换

### 格式
自 1601 年 1 月 1 日起的微秒数（Windows FILETIME 基准）

### Python 转换
```python
import datetime
def chrome_to_datetime(chrome_time):
    epoch = datetime.datetime(1601, 1, 1)
    return epoch + datetime.timedelta(microseconds=chrome_time)
```

## 浏览器配置文件路径

| 操作系统 | 浏览器 | 默认路径 |
|----------|--------|---------|
| Windows | Chrome | `%LOCALAPPDATA%\Google\Chrome\User Data\Default` |
| Windows | Edge | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` |
| Linux | Chrome | `~/.config/google-chrome/Default` |
| macOS | Chrome | `~/Library/Application Support/Google/Chrome/Default` |

## 跳转类型（visit_transition & 0xFF）
| 值 | 类型 | 描述 |
|----|------|------|
| 0 | LINK | 点击链接 |
| 1 | TYPED | 在地址栏输入 URL |
| 2 | AUTO_BOOKMARK | 通过书签 |
| 3 | AUTO_SUBFRAME | 子框架导航 |
| 5 | GENERATED | 自动生成（如搜索） |
| 7 | FORM_SUBMIT | 表单提交 |
| 8 | RELOAD | 页面重载 |
