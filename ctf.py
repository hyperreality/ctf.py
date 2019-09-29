from collections import Counter
import math
import random
import re
import string
import subprocess
from OpenSSL import crypto
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long


def chunks(l, n):
    """break up into groups of n
    >>> chunks("hello", 2)
    ['he', 'll', 'o']"""
    n = max(1, n)
    return [l[i:i+n] for i in range(0, len(l), n)]


def partition(l, n):
    """break up into x columns, i.e.
    >>> partition("hello", 2)
    ['hlo', 'el']"""
    cols = [""] * n
    for i, c in enumerate(l):
        cols[i % n] += c
    return cols


def egcd(a, b):
    """Extended Euclidean algorithm"""
    """https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm"""
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = b // a, b % a
        m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    return b, x, y


def modinv(e, m):
    """Modular multiplicative inverse"""
    """https://en.wikipedia.org/wiki/Modular_multiplicative_inverse"""
    g, x, y = egcd(e, m)
    if g != 1:
        return None
    else:
        return x % m


def pqe2rsa(p, q, e):
    """Generate an RSA private key from p, q and e"""
    from Crypto.PublicKey import RSA
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    key_params = (long(n), long(e), long(d), long(p), long(q))
    priv_key = RSA.construct(key_params)
    return priv_key.exportKey()


def read_rsa_key(path):
    return RSA.importKey(open(path).read())


def rsa_cert_to_key(path):
    crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, open(path).read())
    pubKeyObject = crtObj.get_pubkey()
    pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM, pubKeyObject)
    return pubKeyString


def is_prime(n):
    """
    Miller-Rabin primality test.

    A return value of False means n is certainly not prime. A return value of
    True means n is very likely a prime.
    """
    if n != int(n):
        return False
    n = int(n)
    if n == 0 or n == 1 or n == 4 or n == 6 or n == 8 or n == 9:
        return False

    if n == 2 or n == 3 or n == 5 or n == 7:
        return True
    s = 0
    d = n-1
    while d % 2 == 0:
        d >>= 1
        s += 1
    assert(2**s * d == n-1)

    def trial_composite(a):
        if pow(a, d, n) == 1:
            return False
        for i in range(s):
            if pow(a, 2**i * d, n) == n-1:
                return False
        return True

    for i in range(8):  # number of trials
        a = random.randrange(2, n)
        if trial_composite(a):
            return False

    return True


def factorise(n):
    """Extremely janky way to use yafu binary to find prime factors

    Need yafu binary in PATH"""
    res = subprocess.run(["yafu", f"factor({n})"], stdout=subprocess.PIPE)
    output = res.stdout.decode('ascii').split("\n")

    factors = []

    for line in output:
        z = re.match("[P|C]\d+ = (.*)", line)
        if z:
            factor = int(z.group(1))
            if is_prime(factor):
                factors.append(factor)
            else:
                for f in factorise(factor):
                    factors.append(f)

    return [int(f) for f in factors]


def ic(ctext):
    """index of coincidence
    0.067 is close to English"""
    num = 0.0
    den = 0.0
    for val in Counter(ctext).values():
        i = val
        num += i * (i - 1)
        den += i
    if den == 0.0:
        return 0.0
    else:
        return num / (den * (den - 1))


def find_keylen_ics(ctext, low=3, high=20, rows=5):
    if high > len(ctext) / 2:
        high = math.floor(len(ctext) / 2)

    results = {}
    for length in range(low, high + 1):
        ics = [ic(col) for col in partition(ctext, length)]
        results[length] = sum(ics) / len(ics)

    best = sorted(results.items(), key=lambda kv: -kv[1])

    print("%8s %8s" % ("keylen", "ic"))
    for k, v in best[:rows]:
        print("%8d %8.3f" % (k, v))
