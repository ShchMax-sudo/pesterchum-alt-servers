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


def int15(num):
    preans = []
    nums = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B",
            "C", "D", "E"]
    while (num != 0):
        preans.append(nums[num % 15])
        num //= 15
    return "".join(list(reversed(preans)))


def int15to16(str):
    d = {
        "0": "1",
        "1": "2",
        "2": "3",
        "3": "4",
        "4": "5",
        "5": "6",
        "6": "7",
        "7": "8",
        "8": "9",
        "9": "A",
        "A": "B",
        "B": "C",
        "C": "D",
        "D": "E",
        "E": "F",
    }
    return "".join([d[ch.upper()] for ch in str])


def int16to15(str):
    d = {
        "1": "0",
        "2": "1",
        "3": "2",
        "4": "3",
        "5": "4",
        "6": "5",
        "7": "6",
        "8": "7",
        "9": "8",
        "A": "9",
        "B": "A",
        "C": "B",
        "D": "C",
        "E": "D",
        "F": "E",
    }
    return "".join([d[ch.upper()] for ch in str])


def strToHex(string):
    return int15to16(
        int15(
            int(
                binascii.hexlify(
                    string.encode("utf-8")
                ).decode("ascii"), base=16
            )
        )
    )


def hexToStr(hexstr):
    return binascii.unhexlify(
        hex(int(int16to15(hexstr), base=15))[2:].encode("ascii")
    ).decode("utf-8")


def encodeChunk(chunk):
    chunk = int(chunk, base=16)
    return (("0" * chunksize) + hex(pow(chunk, e, n))[2:])[-chunksize:]


def decodeChunk(chunk):
    chunk = int(chunk, base=16)
    return hex(pow(chunk, d, n))[2:]


def getKey(user=None):
    if (user is None):
        return (d, n)
    else:
        return (e, n)
    _rsadir = ostools.getDataDir() + "rsa/"
    if (not os.path.exists(_rsadir)):
        os.mkdir(_rsadir)
    if (not os.path.exists(_rsadir + user + ".dat")):
        return (None, None)
    return tuple(map(int, open(_rsadir + user + ".dat", "w").readlines()))


def decodeMessage(message):
    cryptosymbhol = message[0]
    if (cryptosymbhol == dcsymbhol):
        return message[1:]
    elif (cryptosymbhol != ecsymbhol):
        return message
    else:
        cryptedmessage = message[1:]
        (d, n) = getKey()
        if (d is None):
            return ErrorKeyNotFound
        decryptedmessage = ""
        for i in range(0, len(cryptedmessage), chunksize):
            decryptedmessage += decodeChunk(
                cryptedmessage[i:i + chunksize])
        return hexToStr(decryptedmessage)


def encodeMessage(message, user):
    (e, n) = getKey(user)
    if (e is None):
        return dcsymbhol + message
    hexed = strToHex(message)
    cryptedmessage = ""
    i = 0
    while (i < len(hexed)):
        currentChunk = ""
        while (i < len(hexed) and int(currentChunk + hexed[i], base=16) < n):
            currentChunk += hexed[i]
            i += 1
        cryptedmessage += encodeChunk(currentChunk)
    return ecsymbhol + cryptedmessage


if (__name__ == "__main__"):
    message = "TestTestTestWith🔒"
    user = "ShchMax"
    cr = encodeMessage(message, user)
    print(cr)
    print(decodeMessage(cr))
    print(encodeChunk("123F"))
    print(decodeChunk(encodeChunk("123F")))
