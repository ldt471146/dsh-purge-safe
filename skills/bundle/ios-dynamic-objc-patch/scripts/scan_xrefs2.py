"""Fast raw-word (no full disasm) ADRP/ADD/ADR/LDR-reference scanner over __text."""
import sys, struct, pickle, array
sys.path.insert(0, r'C:\Users\Administrator\Downloads\tipa-kurwa\tools')
from macho import MachO

PATH = r'C:\Users\Administrator\Downloads\tipa-kurwa\Payload\LitvinTap.app\LitvinTap'
OUT = r'C:\Users\Administrator\Downloads\tipa-kurwa\out_xrefs.pkl'

m = MachO(PATH)
text = m.sec_by_name('__TEXT', '__text')
raw = m.data[text.offset:text.offset + text.size]
words = array.array('I')
words.frombytes(raw[:len(raw) - (len(raw) % 4)])

base = text.addr
sites = {}
pend = {}  # reg -> (page_addr)

def reg(n): return n & 31

for i, w in enumerate(words):
    a = base + i * 4
    if (w & 0x9F000000) == 0x90000000:  # ADRP
        rd = reg(w)
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20): imm -= (1 << 21)
        page = (a & ~0xFFF) + (imm << 12)
        pend[rd] = page
        continue
    if (w & 0x9F000000) == 0x10000000:  # ADR
        rd = reg(w)
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20): imm -= (1 << 21)
        sites.setdefault(a + imm, []).append((a, 'adr'))
        continue
    if (w & 0x7F000000) == 0x11000000:  # ADD (immediate), 64/32-bit
        sf = (w >> 31) & 1
        sh = (w >> 22) & 1
        imm12 = (w >> 10) & 0xFFF
        rn = reg(w >> 5)
        if rn in pend and (rn != 31):
            imm = imm12 << (12 if sh else 0)
            sites.setdefault(pend[rn] + imm, []).append((a, 'add'))
        continue
    if (w & 0x3B000000) == 0x39000000:  # LDR/STR unsigned imm
        size = (w >> 30) & 3
        opc = (w >> 22) & 3
        imm12 = (w >> 10) & 0xFFF
        rn = reg(w >> 5)
        if rn in pend:
            sites.setdefault(pend[rn] + (imm12 << size), []).append((a, 'ldst'))
        continue
    if (w & 0xFFC00000) == 0xF9400000:  # LDR (immediate, 64-bit unsigned offset)
        imm12 = (w >> 10) & 0xFFF
        rn = reg(w >> 5)
        if rn in pend:
            sites.setdefault(pend[rn] + imm12 * 8, []).append((a, 'ldr'))
        continue

print("words:", len(words), "targets:", len(sites))
with open(OUT, 'wb') as f:
    pickle.dump(sites, f)
# quick sanity: how many distinct data targets in cstring range
cs_ = m.sec_by_name('__TEXT', '__cstring')
cnt = sum(1 for t in sites if cs_.addr <= t < cs_.addr + cs_.size)
print("targets pointing into __cstring:", cnt)
