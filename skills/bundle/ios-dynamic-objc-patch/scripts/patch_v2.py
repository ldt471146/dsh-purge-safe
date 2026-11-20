"""v2 补丁: 恢复门禁 UI（不再劫持 installGate / premium），改为「登录按钮 -> 直接调 acceptKey:」。
让 App 自己的成功流程（rememberKey / startHeartbeat / successPulse / tearDownAnimated）照常执行。
"""
import os, shutil, struct, sys, zipfile
sys.path.insert(0, r'C:\Users\Administrator\Downloads\tipa-kurwa\tools')
from macho import MachO
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

SRC_APP = r'C:\Users\Administrator\Downloads\tipa-kurwa\Payload\LitvinTap.app'
WORK = r'C:\Users\Administrator\Downloads\tipa-kurwa\v2'
APP = os.path.join(WORK, 'Payload', 'LitvinTap.app')
BIN = os.path.join(APP, 'LitvinTap')
OUT_IPA = r'C:\Users\Administrator\Desktop\kurwa-patched-v2.ipa'

CAVE = 0x101A006BC          # __TEXT 尾部零填充（可执行）
SEL_KF = 0x101A471F0        # @selector(keyField)
SEL_TX = 0x101A450C8        # @selector(text)
SEL_AK = 0x101A47388        # @selector(acceptKey:)
MSGSEND = 0x101516B78       # _objc_msgSend stub
LOGIN = 0x1005D3328         # -[LTGateViewController loginTapped:]
RESUME = 0x100332414        # -[LTAccessGateContainer resumeWithKey:]
SWITCH = 0x100340434        # -[LTAccessGateContainer switchToLaunchpad]
LOCKOUT = 0x10033E680       # -[LTAccessGateContainer lockOut]
JAIL = 0x100345518          # -[LTAccessGateContainer showJailbreakAlert]


def off_of(m, va):
    o = m.addr_to_off(va)
    if o is not None:
        return o
    for sg in m.segments:
        if sg['vmaddr'] <= va < sg['vmaddr'] + sg['filesize']:
            return sg['fileoff'] + (va - sg['vmaddr'])
    raise SystemExit(f'unmapped 0x{va:x}')


def adrp(rd, target, pc):
    imm = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd


def ldr_x(rt, rn, off):
    return 0xF9400000 | (((off >> 3) & 0xFFF) << 10) | (rn << 5) | rt


def bl(target, pc):
    d = target - pc
    assert d % 4 == 0 and -(1 << 27) <= d < (1 << 27)
    return 0x94000000 | ((d >> 2) & 0x3FFFFFF)


def b(target, pc):
    d = target - pc
    assert d % 4 == 0 and -(1 << 27) <= d < (1 << 27)
    return 0x14000000 | ((d >> 2) & 0x3FFFFFF)


def mov(d, m):
    return 0xAA0003E0 | (m << 16) | d


def cbz(rt, target, pc):
    d = target - pc
    assert d % 4 == 0
    return 0xB4000000 | (((d >> 2) & 0x7FFFF) << 5) | rt


def stp_pre(a, b_, off):
    return 0xA9800000 | ((((-off) // 8) & 0x7F) << 15) | (b_ << 10) | (31 << 5) | a


def stp_off(a, b_, off):
    return 0xA9000000 | (((off // 8) & 0x7F) << 15) | (b_ << 10) | (31 << 5) | a


def ldp_off(a, b_, off):
    return 0xA9400000 | (((off // 8) & 0x7F) << 15) | (b_ << 10) | (31 << 5) | a


def ldp_post(a, b_, off):
    return 0xA8C00000 | (((off // 8) & 0x7F) << 15) | (b_ << 10) | (31 << 5) | a


MOV_X29_SP = 0x910003FD
RET = 0xD65F03C0
NOP = 0xD503201F
BAIL_OFF = 0x50


def build_stub():
    code, pc = [], CAVE

    def emit(w):
        nonlocal pc
        code.append(w)
        pc += 4

    emit(stp_pre(29, 30, 0x20))
    emit(MOV_X29_SP)
    emit(stp_off(19, 20, 0x10))
    emit(mov(19, 0))                                            # x19 = self
    emit(adrp(1, SEL_KF, pc)); emit(ldr_x(1, 1, SEL_KF & 0xFFF))
    emit(bl(MSGSEND, pc))
    emit(cbz(0, CAVE + BAIL_OFF, pc))                            # keyField==nil -> bail
    emit(mov(20, 0))                                            # x20 = keyField
    emit(adrp(1, SEL_TX, pc)); emit(ldr_x(1, 1, SEL_TX & 0xFFF))
    emit(mov(0, 20))
    emit(bl(MSGSEND, pc))
    emit(cbz(0, CAVE + BAIL_OFF, pc))                            # text==nil -> bail
    emit(mov(2, 0))                                             # x2 = key
    emit(adrp(1, SEL_AK, pc)); emit(ldr_x(1, 1, SEL_AK & 0xFFF))
    emit(mov(0, 19))                                            # x0 = self
    emit(bl(MSGSEND, pc))
    while pc < CAVE + BAIL_OFF:
        emit(NOP)
    emit(ldp_off(19, 20, 0x10))
    emit(ldp_post(29, 30, 0x20))
    emit(RET)
    return code


def main():
    if os.path.isdir(WORK):
        shutil.rmtree(WORK)
    os.makedirs(WORK)
    shutil.copytree(SRC_APP, APP)

    m = MachO(BIN)
    stub = build_stub()
    patches = [
        ('loginTapped: -> stub(keyField.text -> acceptKey:)', LOGIN, [b(CAVE, LOGIN)], 'fc6fbba9'),
        ('stub', CAVE, stub, None),
        ('resumeWithKey: -> switchToLaunchpad', RESUME, [b(SWITCH, RESUME)], 'e923bb6d'),
        ('lockOut -> ret', LOCKOUT, [RET], 'f44fbea9'),
        ('showJailbreakAlert -> switchToLaunchpad', JAIL, [b(SWITCH, JAIL)], 'fa67bba9'),
    ]
    with open(BIN, 'r+b') as f:
        for name, va, words, expect in patches:
            off = off_of(m, va)
            if expect:
                f.seek(off)
                orig = f.read(4)
                assert orig.hex() == expect, f'{name}: 原字节 {orig.hex()} != {expect}'
            f.seek(off)
            f.write(b''.join(struct.pack('<I', w) for w in words))
            print(f'[patch] {name:46s} @0x{va:x} off=0x{off:x}')

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    m2 = MachO(BIN)
    print('\n=== 校验 ===')
    for name, va, words, _ in patches:
        if name == 'stub':
            continue
        off = off_of(m2, va)
        raw = m2.data[off:off + 4]
        print(f'  0x{va:x} {raw.hex()}  ' + '; '.join(f'{i.mnemonic} {i.op_str}' for i in md.disasm(raw, va)))
    off = off_of(m2, CAVE)
    print(f'\n=== stub @0x{CAVE:x} ===')
    for i in md.disasm(m2.data[off:off + 0x5C], CAVE):
        print(f'  0x{i.address:x}  {i.mnemonic:8s} {i.op_str}')

    if os.path.exists(OUT_IPA):
        os.remove(OUT_IPA)
    with zipfile.ZipFile(OUT_IPA, 'w', zipfile.ZIP_DEFLATED) as z:
        for root, _, files in os.walk(WORK):
            for fn in files:
                p = os.path.join(root, fn)
                z.write(p, os.path.relpath(p, WORK).replace('\\', '/'))
    print(f'\n[wrote] {OUT_IPA} ({os.path.getsize(OUT_IPA)} bytes)')


if __name__ == '__main__':
    main()
