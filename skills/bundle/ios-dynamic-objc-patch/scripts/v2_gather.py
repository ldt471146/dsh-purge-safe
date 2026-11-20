"""为 v2 补丁收集素材: keyField/text/acceptKey: 的 selref 槽、objc_msgSend stub、可用代码洞、loginTapped/acceptKey IMP。"""
import sys, struct, pickle, bisect
sys.path.insert(0, r'C:\Users\Administrator\Downloads\tipa-kurwa\tools')
from macho import MachO

BIN = r'C:\Users\Administrator\Downloads\tipa-kurwa\Payload\LitvinTap.app\LitvinTap'
m = MachO(BIN)
BASE = 0x100000000
SITES = pickle.load(open(r'C:\Users\Administrator\Downloads\tipa-kurwa\out_xrefs.pkl', 'rb'))

selsec = m.sec_by_name('__DATA', '__objc_selrefs')

def norm(raw):
    if raw == 0: return 0
    c = BASE + (raw & 0xFFFFFFFFF)
    if m.addr_to_off(c) is not None: return c
    if raw >= BASE and m.addr_to_off(raw) is not None: return raw
    return 0

def slotval(a):
    o = m.addr_to_off(a)
    return norm(struct.unpack_from('<Q', m.data, o)[0]) if o is not None else 0

# slot -> selector
selmap = {}
for i in range(selsec.size // 8):
    slot = selsec.addr + i * 8
    s = m.cstring_at(slotval(slot))
    if s:
        selmap.setdefault(s, []).append(slot)

for name in ('keyField', 'text', 'acceptKey:', 'resumeWithKey:', 'busy'):
    print(f"{name:16s} slots: " + ', '.join(f'0x{x:x}' for x in selmap.get(name, [])))

# 这些槽被哪些指令加载（定位 loginTapped 里的取用点）
for name in ('keyField', 'text', 'acceptKey:'):
    for slot in selmap.get(name, []):
        refs = SITES.get(slot, [])
        print(f"  [{name}] slot 0x{slot:x} loaded at: " + ', '.join(f'0x{a:x}' for a, k in refs[:6]))

# 代码洞：__TEXT 段内连续 0x120 字节 0
print('\n=== zero caves in __TEXT ===')
text_seg = [s for s in m.segments if s['segname'] == '__TEXT'][0]
start, end = text_seg['vmaddr'], text_seg['vmaddr'] + text_seg['filesize']
run = 0
best = []
i = m.addr_to_off(start)
endoff = m.addr_to_off(start) + (end - start)
while i < endoff:
    if m.data[i] == 0:
        run += 1
        if run == 0x120:
            va = m.off_to_addr(i - 0x11f)
            best.append(va)
    else:
        run = 0
    i += 1
print(f'found {len(best)} runs of 0x120 zeros; first 10: ' + ', '.join(f'0x{x:x}' for x in best[:10]))
