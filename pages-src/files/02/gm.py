"""教学用 SM3 / SM2 纯 Python 实现（仅标准库）。只用于课堂演示与验签练习，不可用于生产。"""
import hashlib, secrets

# ---------- SM3 (GB/T 32905-2016) ----------
_IV = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]
def _rotl(x, n): n %= 32; return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
def _p0(x): return x ^ _rotl(x, 9) ^ _rotl(x, 17)
def _p1(x): return x ^ _rotl(x, 15) ^ _rotl(x, 23)
def sm3(data: bytes) -> bytes:
    l = len(data) * 8
    m = data + b"\x80" + b"\x00" * ((56 - (len(data) + 1) % 64) % 64) + l.to_bytes(8, "big")
    v = _IV[:]
    for i in range(0, len(m), 64):
        w = [int.from_bytes(m[i + 4 * j:i + 4 * j + 4], "big") for j in range(16)]
        for j in range(16, 68):
            w.append(_p1(w[j-16] ^ w[j-9] ^ _rotl(w[j-3], 15)) ^ _rotl(w[j-13], 7) ^ w[j-6])
        w1 = [w[j] ^ w[j+4] for j in range(64)]
        a, b, c, d, e, f, g, h = v
        for j in range(64):
            t = 0x79CC4519 if j < 16 else 0x7A879D8A
            ss1 = _rotl((_rotl(a, 12) + e + _rotl(t, j)) & 0xFFFFFFFF, 7)
            ss2 = ss1 ^ _rotl(a, 12)
            ff = (a ^ b ^ c) if j < 16 else ((a & b) | (a & c) | (b & c))
            gg = (e ^ f ^ g) if j < 16 else ((e & f) | (~e & g))
            tt1 = (ff + d + ss2 + w1[j]) & 0xFFFFFFFF
            tt2 = (gg + h + ss1 + w[j]) & 0xFFFFFFFF
            d, c, b, a = c, _rotl(b, 9), a, tt1
            h, g, f, e = g, _rotl(f, 19), e, _p0(tt2)
        v = [x ^ y for x, y in zip(v, [a, b, c, d, e, f, g, h])]
    return b"".join(x.to_bytes(4, "big") for x in v)

# ---------- SM2 曲线参数 (sm2p256v1) ----------
P  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B  = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
G = (GX, GY)

def _add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % P == 0: return None
    if p1 == p2: l = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else: l = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (l * l - x1 - x2) % P
    return (x3, (l * (x1 - x3) - y1) % P)

def mul(k, pt):
    r = None
    while k:
        if k & 1: r = _add(r, pt)
        pt = _add(pt, pt); k >>= 1
    return r

def on_curve(pt):
    x, y = pt
    return (y * y - (x * x * x + A * x + B)) % P == 0

def keygen():
    d = secrets.randbelow(N - 2) + 1
    return d, mul(d, G)

def za(pub, uid=b"1234567812345678"):
    entl = (len(uid) * 8).to_bytes(2, "big")
    f = lambda n: n.to_bytes(32, "big")
    return sm3(entl + uid + f(A) + f(B) + f(GX) + f(GY) + f(pub[0]) + f(pub[1]))

def sign_e(e, d, k=None):
    while True:
        kk = k or (secrets.randbelow(N - 1) + 1)
        x1, _ = mul(kk, G)
        r = (e + x1) % N
        if r == 0 or r + kk == N:
            if k: raise ValueError("bad k"); continue
            continue
        s = pow(1 + d, -1, N) * (kk - r * d) % N
        if s == 0:
            if k: raise ValueError("bad k")
            continue
        return r, s

def verify_e(e, r, s, pub):
    if not (1 <= r < N and 1 <= s < N) or not on_curve(pub): return False
    t = (r + s) % N
    if t == 0: return False
    pt = _add(mul(s, G), mul(t, pub))
    if pt is None: return False
    return (e + pt[0]) % N == r

def e_standard(msg: bytes, pub, uid=b"1234567812345678"):
    return int.from_bytes(sm3(za(pub, uid) + msg), "big")
