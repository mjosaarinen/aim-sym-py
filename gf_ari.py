#   gf_ari.py
#   2023-07-20  Markku-Juhani O. Saarinen < mjos@pqshield.com>. See LICENSE
#   --- Simple finite field operations.

#   irreducible polynomials
GF128   = 0x100000000000000000000000000000087
GF192   = 0x1000000000000000000000000000000000000000000000087
GF256   = 0x10000000000000000000000000000000000000000000000000000000000000425

def gf_from_bytes(f, x):
    """Convert bytes to field element."""
    y = 0
    for i in range(len(x)):
        y |= x[i] << (8 * i)
    return y

def gf_to_bytes(f, x):
    """Convert field f element to bytes."""
    d = int(f).bit_length() - 1
    y = b''
    while x > 0:
        y += bytes([x & 0xFF])
        x >>= 8
    y +=  b'\x00' * ( d//8 - len(y) )
    return y;

def gf_mul(f, x, y):
    """Multiplication x*y in field f."""
    d = int(f).bit_length() - 1
    if y & 1:
        r = x
    else:
        r = 0
    while y > 1:
        x <<= 1
        if (x >> d) & 1:
            x ^= f
        y >>= 1
        if y & 1:
            r ^= x
    return r

def gf_exp(f, x, e):
    """Exponentiation x**e in field f."""
    if e & 1:
        r = x
    else:
        r = 1
    while e > 1:
        e >>= 1
        x = gf_mul(f, x, x)
        if e & 1:
            r = gf_mul(f, r, x)
    return r

def gf_inv(f, x):
    """Multiplicative inverse."""
    d = int(f).bit_length() - 1
    return gf_exp(f, x, (1 << d) - 2)

def gf_vec_mat(va, mb):
    """Binary vector-matrix multiply."""
    vr = 0
    for i in range(len(mb)):
        if (va >> i) & 1:
            vr ^= mb[i]
    return vr

def gf_mat_mat(ma, mb):
    """Binary matrix-matrix multiply."""
    return [ gf_vec_mat(t, mb) for t in ma ]

