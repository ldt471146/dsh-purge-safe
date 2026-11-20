# 标准 - 使用 Hindsight 进行浏览器取证
## 工具
- Hindsight: https://github.com/obsidianforensics/hindsight
- DB Browser for SQLite: Chrome 数据库检查
- ChromeCacheView (NirSoft): 缓存分析
## 浏览器数据库
- History: URL 访问、下载、关键词搜索
- Cookies: 按域名的 HTTP Cookie
- Web Data: 自动填充、信用卡
- Login Data: 已保存凭据（加密）
- Bookmarks: JSON 格式书签树
## 时间戳格式
- Chrome/WebKit: 自 1601-01-01 UTC 起的微秒数
- Firefox/Mozilla: 自 Unix 纪元起的微秒数
- Safari/Mac: 自 2001-01-01 UTC 起的秒数
