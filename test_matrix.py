#   test_matrix.py
#   2023-07-20  Markku-Juhani O. Saarinen < mjos@pqshield.com>. See LICENSE

#   this code just demonstrates the matrix manipulation

from aim import *
from gf_ari import *

#   print some internal variables using exponentiation

def aim128_r(pt, iv, ct):
    f   = GF128
    x   =   gf_from_bytes(f, pt)    # unknown
    c   =   gf_from_bytes(f, ct)    # known
    print(f"x=  {x:032x}")
    print(f"c=  {c:032x}")
    (a, b) = gen_lu(f, iv, 2)

    t0  =  gf_exp(f, x, 2**3-1)
    t1  =  gf_exp(f, x, 2**27-1)
    u   =  gf_vec_mat(t0, a[0]) ^ gf_vec_mat(t1, a[1])
    u   ^= b
    print(f"u=  {u:032x}")

    d   =  gf_exp(f, u, 2**5-1) ^ x
    print(f"d=  {d:032x}")

    r1  =   gf_exp(f, u, 2**5)
    r2  =   gf_mul(f, x ^ c, u)
    print(f"r1= {r1:032x}")
    print(f"r2= {r2:032x}")

    return gf_to_bytes(f, d)

def pow_to_mat(f, e):
    """Return matrix Ee for which x*Ee == x**(2**e)."""
    d = int(f).bit_length() - 1
    m = []
    for i in range(d):
        x = 1 << i
        for j in range(e):
            x = gf_mul(f, x, x)
        m += [ x ]
    return m

#   check the matrix version

def aim128_e(pt, iv, ct):
    """AIM-I one-way function (key search manipulation)."""
    f = GF128
    x = gf_from_bytes(f, pt)    # unknown
    c = gf_from_bytes(f, ct)    # known
    print(f"x=  {x:032x}")
    print(f"c=  {c:032x}")

    #   linear layer
    (a, b) = gen_lu(f, iv, 2)

    #   inverse
    z   = gf_inv(f, x)

    #   get the matrices
    e3  = pow_to_mat(f, 3)
    e27 = pow_to_mat(f, 27)
    e5  = pow_to_mat(f, 5)

    #   u = x*E3*z*A1 + x*E27*z*A2 + b
    t0  = gf_vec_mat(x, e3)
    t0  = gf_mul(f, t0, z)
    t0  = gf_vec_mat(t0, a[0])

    t1  = gf_vec_mat(x, e27)
    t1  = gf_mul(f, t1, z)
    t1  = gf_vec_mat(t1, a[1])
    u   = t0 ^ t1 ^ b

    #   u*E5 == (c + x)*u
    p1  = gf_vec_mat(u, e5)     #   left
    p2  = gf_mul(f, c ^ x, u)   #   right

    print(f'pl= {p1:032x}')
    print(f'p2= {p2:032x}')


if __name__ == '__main__':
    print("Reference")
    pt = bytes.fromhex("91282214654CB55E7C2CACD53919604D")
    print("PT=", pt.hex())
    iv = bytes.fromhex("7C9935A0B07694AA0C6D10E4DB6B1ADD")
    kt = bytes.fromhex("CFCB2D8FA8739AA839CFC249DFBC9E07")
    print("IV=", iv.hex())
    print("KT=", kt.hex())
    ct = aim128(pt, iv)
    print("CT=", ct.hex())
    print()

    print("Display variables")
    rt = aim128_r(pt, iv, ct)
    print("RT=", ct.hex())
    print()

    print("No-exponentiation version")
    aim128_e(pt, iv, ct)

