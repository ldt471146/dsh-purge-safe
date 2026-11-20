"""Minimal Mach-O (arm64, 64-bit) reader: segments, sections, strings, disasm helpers."""
import struct, sys

FAT_MAGIC = 0xcafebabe
MH_MAGIC_64 = 0xfeedfacf

def u32(b, o): return struct.unpack_from('<I', b, o)[0]
def u64(b, o): return struct.unpack_from('<Q', b, o)[0]

class Section:
    __slots__ = ('segname','sectname','addr','size','offset','align','reloff','nreloc','flags')
    def __repr__(self):
        return f"{self.segname},{self.sectname} addr=0x{self.addr:x} size=0x{self.size:x} off=0x{self.offset:x}"

class MachO:
    def __init__(self, path):
        self.path = path
        with open(path, 'rb') as f:
            self.data = f.read()
        self._parse()

    def _parse(self):
        d = self.data
        magic = u32(d, 0)
        if magic == MH_MAGIC_64:
            self.base = 0
        elif magic == FAT_MAGIC:
            # fat binary: take first slice
            n = u32(d, 4)
            self.base = u32(d, 12)  # offset of first arch
            magic = u32(d, self.base)
            assert magic == MH_MAGIC_64, hex(magic)
        else:
            raise SystemExit(f"not a 64-bit Mach-O: {magic:#x}")
        b = self.base
        self.cputype = u32(d, b + 4)
        self.ncmds = u32(d, b + 16)
        self.sizeofcmds = u32(d, b + 20)
        self.flags = u32(d, b + 24)
        off = b + 32
        self.sections = []
        self.segments = []
        self.symtab = None
        self.uuid = None
        self.cryptid = None
        for _ in range(self.ncmds):
            cmd = u32(d, off); cmdsize = u32(d, off + 4)
            if cmd == 0x19:  # LC_SEGMENT_64
                segname = d[off+8:off+8+16].rstrip(b'\x00').decode('latin1')
                vmaddr = u64(d, off+24); vmsize = u64(d, off+32)
                fileoff = u64(d, off+40); filesize = u64(d, off+48)
                nsects = u32(d, off+64)
                self.segments.append(dict(segname=segname, vmaddr=vmaddr, vmsize=vmsize,
                                          fileoff=fileoff, filesize=filesize, nsects=nsects))
                so = off + 72
                for _i in range(nsects):
                    s = Section()
                    s.sectname = d[so:so+16].rstrip(b'\x00').decode('latin1')
                    s.segname = d[so+16:so+32].rstrip(b'\x00').decode('latin1')
                    s.addr = u64(d, so+32); s.size = u64(d, so+40)
                    s.offset = u32(d, so+48); s.align = u32(d, so+52)
                    s.reloff = u32(d, so+56); s.nreloc = u32(d, so+60)
                    s.flags = u32(d, so+64)
                    self.sections.append(s)
                    so += 80
            elif cmd == 0x2:  # LC_SYMTAB
                self.symtab = dict(symoff=u32(d, off+8), nsyms=u32(d, off+12),
                                   stroff=u32(d, off+16), strsize=u32(d, off+20))
            elif cmd == 0x1b:  # LC_UUID
                self.uuid = d[off+8:off+24].hex()
            elif cmd == 0x2c or cmd == 0x2d:  # LC_ENCRYPTION_INFO(_64)
                self.cryptid = u32(d, off+16)
            off += cmdsize

    # ---- address helpers ----
    def sec_by_name(self, seg, sect):
        for s in self.sections:
            if s.segname == seg and s.sectname == sect:
                return s
        return None

    def addr_to_off(self, addr):
        for s in self.sections:
            if s.addr <= addr < s.addr + s.size and s.offset:
                return s.offset + (addr - s.addr)
        for sg in self.segments:
            if sg['vmaddr'] <= addr < sg['vmaddr'] + sg['vmsize'] and sg['fileoff']:
                return sg['fileoff'] + (addr - sg['vmaddr'])
        return None

    def off_to_addr(self, off):
        for s in self.sections:
            if s.offset <= off < s.offset + s.size and s.offset:
                return s.addr + (off - s.offset)
        return None

    def read(self, addr, n):
        o = self.addr_to_off(addr)
        return self.data[o:o+n] if o is not None else b''

    def cstring_at(self, addr):
        o = self.addr_to_off(addr)
        if o is None: return None
        end = self.data.find(b'\x00', o)
        return self.data[o:end].decode('utf-8', 'replace')

    def sections_of_seg(self, seg):
        return [s for s in self.sections if s.segname == seg]

    def symbols(self):
        if not self.symtab: return []
        d = self.data; st = self.symtab; out = []
        for i in range(st['nsyms']):
            o = st['symoff'] + i * 16
            strx = u32(d, o); ntype = d[o+4]; sect = d[o+5]; desc = struct.unpack_from('<H', d, o+6)[0]
            value = u64(d, o+8)
            so = st['stroff'] + strx
            name = d[so:d.find(b'\x00', so)].decode('utf-8', 'replace')
            out.append((name, value, ntype, sect))
        return out


def find_strings(m, minlen=6):
    """Yield (addr, text) for NUL-terminated printable runs in __TEXT,cstring and swift5 literals."""
    out = []
    for s in m.sections:
        if s.sectname in ('cstring', '__cstring'):
            o = s.offset; end = o + s.size
            cur = bytearray(); start = o
            while o < end:
                c = m.data[o]
                if 32 <= c < 127 or c in (9,):
                    if not cur: start = o
                    cur.append(c)
                else:
                    if len(cur) >= minlen:
                        out.append((m.off_to_addr(start), cur.decode('latin1')))
                    cur = bytearray()
                o += 1
    return out


if __name__ == '__main__':
    m = MachO(sys.argv[1])
    print(f"file={m.path}")
    print(f"cputype={m.cputype:#x} ncmds={m.ncmds} sizeofcmds={m.sizeofcmds} uuid={m.uuid} cryptid={m.cryptid}")
    print("== segments ==")
    for sg in m.segments:
        print(f"  {sg['segname']:12s} vmaddr=0x{sg['vmaddr']:x} vmsize=0x{sg['vmsize']:x} fileoff=0x{sg['fileoff']:x} filesize=0x{sg['filesize']:x}")
    print("== sections ==")
    for s in m.sections:
        print("  ", s)
    if m.symtab:
        print(f"== symtab: {m.symtab['nsyms']} symbols ==")
    else:
        print("== no symtab ==")
