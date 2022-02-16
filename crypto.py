import os
import ostools
import binascii
from random import randint


dcsymbhol = '🔓'  # Don't encrypted
ecsymbhol = '🔒'  # Encrypted
ErrorKeyNotFound = "<c=red>Error: Not found open rsa key</c>"
# chunksize = 1024 // 16
chunksize = 6
n = 9173503
d = 6111579
e = 3
# Error: Key Not Found


def pow(a, p, n):
    res = 1
    while (p):
        if (p & 1):
            res *= a
            res %= n
        a *= a
        a %= n
        p >>= 1
    return res


def factorN(n):
    s = 0
    while (n % 2 == 0):
        s += 1
        n //= 2
    return (s, n)


def iterTest(a, s, m, n):
    q = pow(a, m, n)
    if (abs(q) == 1):
        return True
    for i in range(s - 1):
        q = (q * q) % n
        if (q == n - 1):
            return True
    return False


def isPrime(n, k):
    if (n % 2 == 0):
        return False
    s, m = factorN(n - 1)
    for i in range(k):
        if (not iterTest(randint(2, n - 1), s, m, n)):
            return False
    return True


def m_r_gen(k, size):
    pr = randint((1 << (size - 1)) + 1, (1 << (size)) - 1)
    while (not isPrime(pr, k)):
        pr = randint((1 << (size - 1)) + 1, (1 << (size)) - 1)
    return pr


def gcd(a, b):
    if (a == 0):
        x = 0
        y = 1
        return (x, y, b)
    x1, y1, d = gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return (x, y, d)


def inv(k, m):
    return gcd(k, -m)[0] % m


def rsa_keygen():
    p = m_r_gen(30, 128)
    q = m_r_gen(30, 128)
    while (q == p):
        q = m_r_gen(30, 128)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = randint(1, phi - 1)
    while (gcd(e, phi)[2] != 1):
        e = randint(1, phi - 1)
    d = inv(e, phi)
    return (n, p, q, e, d)


def strToHex(string):
    return binascii.hexlify(string.encode("utf-8")).decode("ascii")


def hexToStr(hexstr):
    return binascii.unhexlify(hexstr.encode("ascii")).decode("utf-8")


def encodeChunk(chunk):
    chunk = int(chunk, base=16)
    return hex(pow(chunk, e, n))[2:]


def decodeChunk(chunk):
    chunk = int(chunk, base=16)
    return hex(pow(chunk, d, n))[2:]


def encodeMessage(message, user):
    return message
    cryptosymbhol = message[0]
    if (cryptosymbhol == dcsymbhol):
        return message[1:]
    elif (cryptosymbhol != ecsymbhol):
        return message
    else:
        emessage = message[1:]
        _rsadir = ostools.getDataDir() + "rsa/"
        if (not os.path.exists(_rsadir)):
            os.mkdir(_rsadir)
        if (not os.path.exists(_rsadir + user + ".dat")):
            return ErrorKeyNotFound
        return emessage


def decodeMessage(message, user):
    return message


if (__name__ == "__main__"):
    message = "Test"
    user = "ShchMax"
    print(encodeMessage(message, user))
    print(encodeChunk("123F"))
    print(decodeChunk(encodeChunk("123F")))
