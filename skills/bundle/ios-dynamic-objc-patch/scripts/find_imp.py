"""Given block-invoke function addresses, find containing functions (method IMPs) that reference them."""
import sys, pickle, bisect
sys.path.insert(0, r'C:\Users\Administrator\Downloads\tipa-kurwa\tools')
from macho import MachO
import struct
m = MachO(r'C:\Users\Administrator\Downloads\tipa-kurwa\Payload\LitvinTap.app\LitvinTap')
SITES = pickle.load(open(r'C:\Users\Administrator\Downloads\tipa-kurwa\out_xrefs.pkl', 'rb'))
BASE = 0x100000000

def function_starts():
    d = m.data; off = m.base + 32; starts = []
    for _ in range(m.ncmds):
        cmd = struct.unpack_from('<I', d, off)[0]
        cmdsize = struct.unpack_from('<I', d, off+4)[0]
        if cmd == 0x26:
            dataoff, datasize = struct.unpack_from('<II', d, off+8)
            p, end, addr = dataoff, dataoff+datasize, BASE
            while p < end:
                val = 0; shift = 0
                while True:
                    b = d[p]; p += 1; val |= (b & 0x7F) << shift
                    if not (b & 0x80): break
                    shift += 7
                if val == 0: break
                addr += val; starts.append(addr)
            return sorted(set(starts))
        off += cmdsize
    return []

FS = function_starts()
SYMS = sorted([(v, n) for (n, v, t, s) in m.symbols() if v])
SYMV = [v for v, n in SYMS]

def func_at(a):
    i = bisect.bisect_right(FS, a) - 1
    return FS[i] if i >= 0 else None

def sym_at(a):
    i = bisect.bisect_right(SYMV, a) - 1
    if i >= 0:
        v, n = SYMS[i]
        return n if a == v else f"{n}+0x{a-v:x}"
    return None

for arg in sys.argv[1:]:
    t = int(arg, 16)
    print(f"\n=== refs to block invoke 0x{t:x} ({sym_at(t)}) ===")
    for site, kind in SITES.get(t, []):
        f = func_at(site)
        print(f"   site 0x{site:x} ({kind}) -> func 0x{f:x} {sym_at(f) if f else ''}")
