"""List ObjC message sends (selref loads) inside a function range, with selector names."""
import sys, struct, bisect, pickle, json
sys.path.insert(0, r'C:\Users\Administrator\Downloads\tipa-kurwa\tools')
from macho import MachO

m = MachO(r'C:\Users\Administrator\Downloads\tipa-kurwa\Payload\LitvinTap.app\LitvinTap')
BASE = 0x100000000
SITES = pickle.load(open(r'C:\Users\Administrator\Downloads\tipa-kurwa\out_xrefs.pkl', 'rb'))
selsec = m.sec_by_name('__DATA', '__objc_selrefs')
clssec = m.sec_by_name('__DATA', '__objc_classrefs')

def norm(raw):
    if raw == 0: return 0
    c = BASE + (raw & 0xFFFFFFFFF)
    if m.addr_to_off(c) is not None: return c
    if raw >= BASE and m.addr_to_off(raw) is not None: return raw
    return 0

def slotval(a):
    o = m.addr_to_off(a)
    return norm(struct.unpack_from('<Q', m.data, o)[0]) if o is not None else 0

# build reverse map: slot -> name
selmap = {}
i = 0
while i < selsec.size // 8:
    slot = selsec.addr + i * 8
    s = m.cstring_at(slotval(slot))
    if s: selmap[slot] = s
    i += 1
clsm = {}
i = 0
while i < clssec.size // 8:
    slot = clssec.addr + i * 8
    p = slotval(slot)
    if p:
        clsm[slot] = f"class@0x{p:x}"
    i += 1

# xrefs (target=slot) -> sites. invert SITES
inv = {}
for t, sites in SITES.items():
    for s, k in sites:
        inv.setdefault(s, []).append((t, k))

lo, hi = int(sys.argv[1], 16), int(sys.argv[2], 16)
rows = []
for site, lst in inv.items():
    if not (lo <= site < hi): continue
    for t, k in lst:
        if selsec.addr <= t < selsec.addr + selsec.size:
            rows.append((site, 'SEL', selmap.get(t, f'0x{t:x}')))
        elif clssec.addr <= t < clssec.addr + clssec.size:
            rows.append((site, 'CLS', clsm.get(t, f'0x{t:x}')))
for site, kind, name in sorted(rows):
    print(f"0x{site:x}  {kind}  {name}")
print(f"total: {len(rows)}")
