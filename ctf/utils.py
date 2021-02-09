import os
import string


ALPHANUMERIC = string.ascii_letters + string.digits


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


def english_words():
    dirname = os.path.dirname(__file__)
    dictionaryFile = os.path.join(dirname, 'files/words.txt')
    englishWords = {}
    with open(dictionaryFile) as f:
        for word in f.read().split('\n'):
            englishWords[word] = None
    return englishWords


def bip39():
    with open('files/bip39.txt') as f:
        words = [a.strip() for a in f.readlines()]
    return words
