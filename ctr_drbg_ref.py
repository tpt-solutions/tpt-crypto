"""SP 800-90A 10.2.1 no-DF CTR_DRBG reference (independent python impl)."""
import sys
SBOX = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]
def xtime(a):
    a <<= 1
    if a & 0x100: a ^= 0x1b
    return a & 0xFF
def expand256(key):
    RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40]
    w = [list(key[4*i:4*i+4]) for i in range(8)]
    for i in range(8, 60):
        t = list(w[i-1])
        if i % 8 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= RCON[i//8 - 1]
        elif i % 8 == 4:
            t = [SBOX[b] for b in t]
        w.append([w[i-8][j] ^ t[j] for j in range(4)])
    rounds = []
    for r in range(15):
        rk = []
        for c in range(4):
            rk.extend(w[r*4+c])
        rounds.append(rk)
    return rounds
def aes256_encrypt(key, block):
    wk = expand256(key)
    s = list(block)
    def addrk(r):
        for i in range(16): s[i] ^= wk[r][i]
    def sub():
        for i in range(16): s[i] = SBOX[s[i]]
    def shift():
        t = list(s)
        for col in range(4):
            for row in range(4):
                s[4*col+row] = t[4*((col+row)%4)+row]
    def mix():
        for col in range(4):
            a = s[4*col:4*col+4]
            s[4*col+0] = xtime(a[0])^xtime(a[1])^a[1]^a[2]^a[3]
            s[4*col+1] = a[0]^xtime(a[1])^xtime(a[2])^a[2]^a[3]
            s[4*col+2] = a[0]^a[1]^xtime(a[2])^xtime(a[3])^a[3]
            s[4*col+3] = xtime(a[0])^a[0]^a[1]^a[2]^xtime(a[3])
    addrk(0)
    for r in range(1, 14):
        sub(); shift(); mix(); addrk(r)
    sub(); shift(); addrk(14)
    return bytes(s)
# sanity vs openssl
assert aes256_encrypt(bytes.fromhex('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'),
                      bytes.fromhex('6bc1bee22ee409f67e2213b237b0b3d2')) == bytes.fromhex('a6552cbbba08754cd273bf93c6107241')

def run(entropy, pers, ops, ret_len, ctr_len=32, use_ai=True, rs_mode='xor'):
    st = {'K': b'\x00'*32, 'V': b'\x00'*16}
    def inc(v):
        if ctr_len >= 128:
            n = int.from_bytes(v, 'big') + 1
            return (n % (1 << 128)).to_bytes(16, 'big')
        mask = (1 << ctr_len) - 1
        right = int.from_bytes(v[16 - ctr_len//8:], 'big') if ctr_len % 8 == 0 else None
        if right is None:
            bits = int.from_bytes(v, 'big')
            shift = 128 - ctr_len
            right = bits & ((1 << shift) - 1)
            right = (right + 1) % (1 << shift)
            bits = (bits >> shift << shift) | right
            return bits.to_bytes(16, 'big')
        right = (right + 1) % (1 << ctr_len)
        return v[:16 - ctr_len//8] + right.to_bytes(ctr_len//8, 'big')
    def update(pd48):
        pd48 = pd48[:48] + bytes(48 - len(pd48[:48]))
        temp = b''
        while len(temp) < 48:
            st['V'] = inc(st['V'])
            temp += aes256_encrypt(st['K'], st['V'])
        temp = temp[:48]
        temp = bytes(a ^ b for a, b in zip(temp, pd48))
        st['K'] = temp[:32]
        st['V'] = temp[32:]
    def gen(ai, n):
        if ai:
            update(ai)
        temp = b''
        while len(temp) < n:
            st['V'] = inc(st['V'])
            temp += aes256_encrypt(st['K'], st['V'])
        out = temp[:n]
        update(ai if ai else b'\x00'*48)
        return out
    update(bytes(a ^ b for a, b in zip(entropy.ljust(48, b'\x00'), pers.ljust(48, b'\x00'))))
    outs = []
    for (e, a) in ops:
        if e is not None:
            update(bytes(x ^ y for x, y in zip(e.ljust(48, b'\x00'), a.ljust(48, b'\x00'))))
        outs.append(gen(a, ret_len))
    return outs

if __name__ == '__main__':
    text = open('crates/tpt-crypto-aead/tests/kat/ctr_drbg_awslc.txt').read()
    for rec in text.split('[kat]')[1:]:
        f = dict(l.split(' = ', 1) for l in rec.strip().splitlines() if ' = ' in l)
        ent = bytes.fromhex(f['entropy']); pers = bytes.fromhex(f['pers'])
        hx = lambda s: bytes.fromhex(s) if s and s != '-' else b''
        e0 = hx(f['op0_entropy']); a0 = hx(f['op0_reseed_ai'])
        a1 = hx(f['op1_generate_ai']); a2 = hx(f['op2_generate_ai'])
        want = f['returned']
        ret_len = len(want) // 2
        found = []
        for cw in range(8, 129, 8):
            for use_ai in (True, False):
                for rs_mode in ('xor', 'concat-e', 'xor-init-mask'):
                    outs = run(ent, pers, [(e0, a0), (None, a1), (None, a2)], ret_len, cw, use_ai, rs_mode)
                    if outs[-1].hex() == want:
                        found.append(('last', cw, use_ai, rs_mode))
                    if outs[0].hex() == want:
                        found.append(('first', cw, use_ai, rs_mode))
        print(f"count {f['count']}: found={found}")
