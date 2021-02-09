import re
import string
from collections import Counter
from utils import *


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
