import gmpy2
import math
import os
import random
import re
import string
import subprocess
from collections import Counter
from fractions import gcd
from functools import reduce
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
        b = pow(a,t,n)

        if b == 1:
            a = gmpy2.next_prime(a)
            continue

        while i != 1:
            c = pow(b,2,n)
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
    """Extremely janky way to use yafu binary to find prime factors

    Need yafu binary in PATH"""
    try:
        res = subprocess.run(["yafu", "factor(%s)" % n], stdout=subprocess.PIPE)
        output = res.stdout.decode('ascii').split("\n")
    finally:
        os.system("rm -f siqs.dat factor.log session.log") # cleanup yafu crap

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


def xor_strings(s1, s2, extend=False):
    if extend:
        if len(s1) < len(s2):
            s1 = s1 * (len(s2)//len(s1) + 1)
        else:
            s2 = s2 * (len(s1)//len(s2) + 1)

    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))


def english_words():
    dirname = os.path.dirname(__file__)
    dictionaryFile = os.path.join(dirname, 'words.txt')
    englishWords = {}
    with open(dictionaryFile) as f:
        for word in f.read().split('\n'):
            englishWords[word] = None
    return englishWords


def printable(message, printablePercentage=80):
    return (100 * [c in string.printable for c in message].count(True) / len(message)) > printablePercentage


def looks_like_english(message, wordPercentage=20, letterPercentage=90, splitChar=" "):
    """Credit: https://inventwithpython.com/hacking/chapter12.html

    Will come up with a better function for CTFs when I'm feeling less lazy"""

    ENGLISH_WORDS = english_words()

    def getEnglishCount(message, splitChar):
        message = message.upper()
        message = removeNonLetters(message, splitChar)
        possibleWords = [word.lower() for word in message.split(splitChar)]


        if possibleWords == []:
            return 0.0  # no words at all, so return 0.0

        matches = 0
        for word in possibleWords:
            if word in ENGLISH_WORDS:
                matches += 1
        return float(matches) / len(possibleWords)

    def removeNonLetters(message, splitChar):
        lettersOnly = []
        for symbol in message:
            if symbol in string.ascii_lowercase + string.ascii_uppercase + splitChar:
                lettersOnly.append(symbol)
        return ''.join(lettersOnly)

    wordsMatch = getEnglishCount(message, splitChar) * 100 >= wordPercentage
    numLetters = len(removeNonLetters(message, splitChar))
    messageLettersPercentage = float(numLetters) / len(message) * 100
    lettersMatch = messageLettersPercentage >= letterPercentage

    return wordsMatch and lettersMatch
