import gmpy2
import math
import os
import re
import subprocess
from functools import reduce
from sage.all import *
from OpenSSL import crypto
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse


def pqe2rsa(p, q, e):
    """Generate an RSA private key from p, q and e"""
    n = p * q
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    key_params = (long(n), long(e), long(d), long(p), long(q))
    priv_key = RSA.construct(key_params)
    return priv_key.exportKey()


def read_rsa_key(path):
    with open(path) as f:
        key = f.read()
    return RSA.importKey(key)


def rsa_cert_to_key(path):
    with open(path) as f:
        cert = f.read()
    crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    pubKeyObject = crtObj.get_pubkey()
    pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM, pubKeyObject)
    return pubKeyString


def rsa_recover_primes(n, e, d):
    """Recover p and q when d is known
    https://crypto.stackexchange.com/a/62487
    """
    k = e * d - 1
    s = 0
    t = k

    while t % 2 == 0:
        t = t // 2
        s += 1

    i = s
    a = 2

    assert 2**s * t == k

    p, q = None, None

    while True:
        b = pow(a, t, n)

        if b == 1:
            a = gmpy2.next_prime(a)
            continue

        while i != 1:
            c = pow(b, 2, n)
            if c == 1:
                break
            else:
                b = c
                i -= 1

        if b == n - 1:
            a = gmpy2.next_prime(a)
            continue

        p = math.gcd(b-1, n)
        q = n // p
        return p, q


def is_prime(n):
    return gmpy2.is_prime(n)


def factorise(n):
    return ecm.factor(n)


def is_coprime(a, b):
    return gcd(a, b) == 1


def isqrt(n):
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


def mul_inv(a, b):
    b0 = b
    x0, x1 = 0, 1
    if b == 1:
        return 1
    while a > 1:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += b0
    return x1


def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a*b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * mul_inv(p, n_i) * p
    return sum % prod


def totient(p, k):
    """Euler's totient for prime powers
    https://en.wikipedia.org/wiki/Euler%27s_totient_function#Value_for_a_prime_power_argument"""
    if not is_prime(p):
        raise Exception("p must be prime")
    return pow(p, k-1)*(p-1)
