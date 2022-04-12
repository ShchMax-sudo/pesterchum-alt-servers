import binascii
from random import randint, shuffle, choice
from math import log2


def int15(num):
    # This function transforms int to 15 numeric base string
    preans = []
    nums = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B",
            "C", "D", "E"]
    while (num != 0):
        preans.append(nums[num % 15])
        num //= 15
    return "".join(list(reversed(preans)))


def int15to16(str):
    # This function increases every digit  by 1
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
    # This function degreases every digit by 1
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
    # This function converts char string to hex string
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
    # This function converts hex string to char string
    return binascii.unhexlify(
        hex(int(int16to15(hexstr), base=15))[2:].encode("ascii")
    ).decode("utf-8")


class RSAEncoder():
    # This class is used to encrypt private chats
    # Rivest-Shamir-Adleman
    chunksize = 64    # Size of chunk
    n = None          # Module for RSA system
    d = None          # Private key
    e = None          # Public key

    def binPow(self, a, p, n):
        # Binary power for numbers
        res = 1
        while (p):
            if (p & 1):
                res *= a
                res %= n
            a *= a
            a %= n
            p >>= 1
        return res

    def factorN(self, n):
        # This function removes as mush as possible 2-s from
        # number factorization
        s = 0
        while (n % 2 == 0):
            s += 1
            n //= 2
        return (s, n)

    def iterTest(self, a, s, m, n):
        # One iteration of Miller-Rabbin test
        q = self.binPow(a, m, n)
        if (abs(q) == 1):
            return True
        for i in range(s - 1):
            q = (q * q) % n
            if (q == n - 1):
                return True
        return False

    def isPrime(self, n, k):
        # Miller-Rabbin prime test
        if (n % 2 == 0):
            return False
        s, m = self.factorN(n - 1)
        for i in range(k):
            if (not self.iterTest(randint(2, n - 1), s, m, n)):
                return False
        return True

    def primeGen(self, k, size):
        # This function generates prime size-bit number
        pr = randint((1 << (size - 1)) + 1, (1 << (size)) - 1)
        while (not self.isPrime(pr, k)):
            pr = randint((1 << (size - 1)) + 1, (1 << (size)) - 1)
        return pr

    def gcd(self, a, b):
        # Fast gcd
        if (a == 0):
            x = 0
            y = 1
            return (x, y, b)
        x1, y1, d = self.gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return (x, y, d)

    def inv(self, k, m):
        # Returns number reciprocal modulo n
        return self.gcd(k, -m)[0] % m

    def rsaKeygen(self):
        # This function generates working rsa keys and modulo
        p = self.primeGen(30, 128)
        q = self.primeGen(30, 128)
        while (q == p):
            q = self.primeGen(30, 128)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = randint(1, phi - 1)
        while (self.gcd(e, phi)[2] != 1):
            e = randint(1, phi - 1)
        d = self.inv(e, phi)
        self.n = n
        self.e = e
        self.d = d

    def encodeJUNK(self, chunk):
        # This function encodes one chunk by rsa keys
        chunk = int(chunk, base=16)
        return (("0" * self.chunksize)
                + hex(self.binPow(chunk,
                                  self.e, self.n))[2:])[-self.chunksize:]

    def decodeJUNK(self, chunk):
        # This function decodes one chunk by rsa keys
        chunk = int(chunk, base=16)
        return hex(self.binPow(chunk, self.d, self.n))[2:]

    def decodeMessage(self, message):
        # This function decodes message by rsa keys
        try:
            cryptedmessage = message
            decryptedmessage = ""
            for i in range(0, len(cryptedmessage), self.chunksize):
                decryptedmessage += self.decodeJUNK(
                    cryptedmessage[i:i + self.chunksize])
            return hexToStr(decryptedmessage)
        except (ValueError):
            return message

    def canEncode(self):
        # This function checks open key existence
        return self.e is not None

    def encodeMessage(self, message):
        # This function encodes message by rsa keys
        if (not self.canEncode()):
            print("Failed to encode message")
            return message
        hexed = strToHex(message)
        cryptedmessage = ""
        i = 0
        while (i < len(hexed)):
            currentChunk = ""
            while (i < len(hexed)
                   and int(currentChunk + hexed[i], base=16) < self.n):
                currentChunk += hexed[i]
                i += 1
            cryptedmessage += self.encodeJUNK(currentChunk)
        return cryptedmessage

    def encodeKeys(self, myname):
        # This function encodes public keys
        es = hex(self.e)[2:]
        ns = hex(self.n)[2:]
        checksumm = ""
        for i in range(5):
            checksumm += es[int(es[i], base=16)]
        for i in range(5):
            checksumm += ns[int(ns[i], base=16)]
        return strToHex(myname) \
            + " " \
            + checksumm \
            + " " \
            + es \
            + " " \
            + ns

    def decodeKeys(self, message, myname, isPush=True):
        # This function decodes and applyes public keys
        e_ = None
        n_ = None
        try:
            _, _, e_, n_ = map(lambda x: int(x, base=16),
                               message.split())
        except ValueError:
            return False
        if (e_ is None or n_ is None):
            return False
        name, ch, es, ns = message.split()
        if (len(ch) != 10):
            return False
        for i in range(5):
            if (es[int(es[i], base=16)] != ch[i]
               or ns[int(ns[i], base=16)] != ch[i + 5]):
                return False
        try:
            name = hexToStr(name)
        except UnicodeDecodeError:
            return False
        if (name != myname and isPush):
            return False
        if (isPush):
            self.e = e_
            self.n = n_
        return True


class DHEncoder():
    # This class is used to encrypt group chats
    # Diffie-Hellman
    cnt = None         # Count of users who have ever visited chat
    p = None           # Prime module
    g = None           # Primitive root
    key = None         # Secret code
    myKey = None       # User specified key
    commonKey = None   # Encripting key

    def binPow(self, a, p, n):
        # Binary power for numbers
        res = 1
        while (p):
            if (p & 1):
                res *= a
                res %= n
            a *= a
            a %= n
            p >>= 1
        return res % n

    def sieveInit(self):
        # This method returns sieve of Eratosthenes
        # from 2 to 256
        primeMax = 256
        primes = []
        sieve = [1 for i in range(primeMax + 1)]
        for i in range(2, primeMax + 1):
            if (sieve[i] == 1):
                for j in range(i * i, primeMax + 1, i):
                    sieve[j] = 0

        for i in range(2, primeMax + 1):
            if (sieve[i] == 1):
                primes.append(i)
        return primes

    def generateBase(self, primes):
        # This function generates some composite number
        k = randint(5, 20)
        primesq = primes[1:]
        shuffle(primesq)
        primesq = primesq[:k - 1]
        ans = 2
        for el in primesq:
            ans *= el
        primesq.append(2)
        primeset = list(sorted(primesq))
        return (ans, primeset)

    def maxCnt(self, n, primeset):
        # This function returns max prime number with which you can multiple n
        L = 0
        R = len(primeset)
        while (R - L > 1):
            m = (R + L) // 2
            if (n * primeset[m] < (1 << 128)):
                L = m
            else:
                R = m
        return R

    def generate(self, primes):
        # This function generates prime minus 1 number
        ker, primeset = self.generateBase(primes)
        while (ker < (1 << 127)):
            n = choice(primeset[:self.maxCnt(ker, primeset)])
            ker *= n
        return (ker, primeset)

    def check(self, a, n, primeset):
        # This is one iteration of Lucas test
        if (self.binPow(a, n, n + 1) != 1):
            return False
        for exp in primeset:
            if (self.binPow(a, n // exp, n + 1) == 1):
                return False
        return True

    def lucasGen(self):
        # This function generates prime number and its primitive root
        primes = self.sieveInit()
        while (True):
            n, primeset = self.generate(primes)
            for a in range(2, int(log2(n)) + 10):
                if (self.check(a, n, primeset)):
                    return [n + 1, a]

    def __init__(self, *args):
        # This function inits encoder
        if (len(args) == 0):
            self.cnt = 0
            self.p, self.g = self.lucasGen()
            self.myKey = self.g
            self.key = randint(1, self.p - 1)
            self.commonKey = self.binPow(self.g, self.key, self.p)
        else:
            self.p, self.g, self.cnt = args
            self.key = randint(1, self.p - 1)

    def encodeMessage(self, message):
        # This function encodes message by common key
        hexedMessage = strToHex(message)
        binKey = bin(self.commonKey)[2:]
        length = len(binKey)
        binMessage = bin(int(hexedMessage, base=16))[2:]
        remainder = (length - len(binMessage) % length) % length
        binMessage = "0" * remainder + binMessage
        cryptedMessage = ""
        for i in range(0, len(binMessage), length):
            cryptedMessage += (bin(int(binMessage[i:i + length], base=2)
                                   ^ self.commonKey)[2:][::-1]
                               + "0" * length)[0:length][::-1]
        return hex(int(cryptedMessage, base=2))[2:]

    def decodeMessage(self, message):
        # This function decodes message by common key
        binKey = bin(self.commonKey)[2:]
        length = len(binKey)
        cryptedMessage = bin(int(message, base=16))[2:]
        remainder = (length - len(cryptedMessage) % length) % length
        cryptedMessage = "0" * remainder + cryptedMessage
        binMessage = ""
        for i in range(0, len(cryptedMessage), length):
            binMessage += (bin(int(cryptedMessage[i:i + length], base=2)
                               ^ self.commonKey)[2:][::-1]
                           + "0" * length)[0:length][::-1]
        return hexToStr(hex(int(binMessage, base=2))[2:])


# It's just test polygon. Don't look on it. There are some suspicious code.
# I don't responsible for your eyes integrity after reading this part of code.
if __name__ == "__main__":
    # en = DHEncoder()
    while (True):
        print("Hell'o word!")
