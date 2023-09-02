#   aim.py
#   2023-07-20  Markku-Juhani O. Saarinen < mjos@pqshield.com>. See LICENSE

#   Implementation of AIM-I, AIM-III, and AIM-V from AIMer v1.0

from Crypto.Hash import SHAKE128,SHAKE256
from gf_ari import *

#   main functions
def aim128(pt, iv):
    """AIM-I one-way function."""
    f = GF128
    x = gf_from_bytes(f, pt)
    t = [   gf_exp(f, x, 2**3-1),
            gf_exp(f, x, 2**27-1) ]
    (a, b) = gen_lu(f, iv, 2)
    for i in range(2):
        b ^= gf_vec_mat(t[i], a[i])
    u = gf_exp(f, b, 2**5-1) ^ x
    return gf_to_bytes(f, u)

def aim192(pt, iv):
    """AIM-III one-way function."""
    f = GF192
    x = gf_from_bytes(f, pt)
    t = [   gf_exp(f, x, 2**5-1),
            gf_exp(f, x, 2**29-1) ]
    (a, b) = gen_lu(f, iv, 2)
    for i in range(2):
        b ^= gf_vec_mat(t[i], a[i])
    u = gf_exp(f, b, 2**7-1) ^ x
    return gf_to_bytes(f, u)

def aim256(pt, iv):
    """AIM-V one-way function."""
    f = GF256
    x = gf_from_bytes(f, pt)
    t = [   gf_exp(f, x, 2**3-1),
            gf_exp(f, x, 2**53-1),
            gf_exp(f, x, 2**7-1) ]
    (a, b) = gen_lu(f, iv, 3)
    for i in range(3):
        b ^= gf_vec_mat(t[i], a[i])
    u = gf_exp(f, b, 2**5-1) ^ x
    return gf_to_bytes(f, u)

def gen_lu(f, iv, s):
    """Generate matrix A (L and U) and constant b from iv using SHAKE."""
    d = 8 * len(iv)
    if d == 128:
        xof = SHAKE128.new(iv)
    else:
        xof = SHAKE256.new(iv)

    a = []
    for j in range(s):
        #   Lower L
        al = []
        for i in range(d):
            l = (d - i + 6) // 8
            z = xof.read(l)
            x = gf_from_bytes(f, z) << (8 * ((d//8)-l))
            x = (x & ~((1 << i)-1)) | (1 << i)
            al += [x]

        #   Upper U
        au = []
        for i in range(d):
            l = (i + 7) // 8
            z = xof.read(l)
            x = gf_from_bytes(f, z)
            x = (x & ((1 << i)-1)) | (1 << i)
            au += [x]

        #   product A
        a += [ gf_mat_mat(au, al) ]

    #   constant b
    b = gf_from_bytes(f, xof.read(d // 8))
    return (a, b)

#   self-test

if __name__ == '__main__':

    def test_aim(pk, sk):
        """Check if a keypair is valid."""
        fail = 0
        #   handle possible extra "variant id" byte in the beginning
        if len(pk) % 8 == 1:
            pk = pk[1:]
        if len(sk) % 8 == 1:
            sk = sk[1:]
        bs = len(pk) // 2
        iv = pk[0:bs]   #   pk = (iv, ct)
        ct = pk[bs:]
        pt = sk[0:bs]   #   pt may be followed by a copy of pk

        if bs == 16:
            rt = aim128(pt, iv)
        elif bs == 24:
            rt = aim192(pt, iv)
        elif bs == 32:
            rt = aim256(pt, iv)
        else:
            rt = b''

        if rt != ct:
            print("pt =", pt.hex())
            print("iv =", iv.hex())
            print("ct =", ct.hex())
            print("rt =", rt.hex())
            fail += 1

        return fail

    #   these (pk,sk) test vectors are lifted from "count=0" kat entries
    tv = [
    [   "7C9935A0B07694AA0C6D10E4DB6B1ADD" +
        "CFCB2D8FA8739AA839CFC249DFBC9E07",
        "91282214654CB55E7C2CACD53919604D" ],
    [   "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB14803" +
        "78B4FA6C29E81B3828090ABCB4BE64365D4782C0333AE2CF",
        "8626ED79D451140800E03B59B956F8210E556067407D13DC" ],
    [   "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D" +
        "8C15C43B615082DB6D7DC6F8639420321B27976067A21A515B182F976D7E728F",
        "8626ED79D451140800E03B59B956F8210E556067407D13DC90FA9E8B872BFB8F" ] ]
    fail = 0
    for t in tv:
        fail += test_aim(bytes.fromhex(t[0]), bytes.fromhex(t[1]))
    print("self-test fails =", fail)
