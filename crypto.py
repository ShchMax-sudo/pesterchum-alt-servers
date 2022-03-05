import binascii
from random import randint


class Encoder():
    dcsymbol = '🔓'   # Don't encrypted
    ecsymbol = '🔒'   # Encrypted
    keysymbol = '🔑'  # Keys
    chunksize = 64
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
        # This function generates working rsa keys and module
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

    def int15(self, num):
        # This function transforms int to 15 numeric base string
        preans = []
        nums = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B",
                "C", "D", "E"]
        while (num != 0):
            preans.append(nums[num % 15])
            num //= 15
        return "".join(list(reversed(preans)))

    def int15to16(self, str):
        # This function increases by 1 every digit
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

    def int16to15(self, str):
        # This function degreases by 1 every digit
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

    def strToHex(self, string):
        # This function converts char string to hex string
        return self.int15to16(
            self.int15(
                int(
                    binascii.hexlify(
                        string.encode("utf-8")
                    ).decode("ascii"), base=16
                )
            )
        )

    def hexToStr(self, hexstr):
        # This function converts hex string to char string
        return binascii.unhexlify(
            hex(int(self.int16to15(hexstr), base=15))[2:].encode("ascii")
        ).decode("utf-8")

    def encodeChunk(self, chunk):
        # This function encodes one chunk by rsa keys
        chunk = int(chunk, base=16)
        return (("0" * self.chunksize)
                + hex(self.binPow(chunk,
                                  self.e, self.n))[2:])[-self.chunksize:]

    def decodeChunk(self, chunk):
        # This function decodes one chunk by rsa keys
        chunk = int(chunk, base=16)
        return hex(self.binPow(chunk, self.d, self.n))[2:]

    def decodeMessage(self, message):
        # This function decodes message by rsa keys
        cryptosymbhol = message[0]
        if (cryptosymbhol == self.dcsymbol):
            return message[1:]
        elif (cryptosymbhol != self.ecsymbol):
            return message
        else:
            cryptedmessage = message[1:]
            decryptedmessage = ""
            for i in range(0, len(cryptedmessage), self.chunksize):
                decryptedmessage += self.decodeChunk(
                    cryptedmessage[i:i + self.chunksize])
            return self.hexToStr(decryptedmessage)

    def canEncode(self):
        # This function checks open key existence
        return self.e is not None

    def encodeMessage(self, message, user):
        # This function encodes message by rsa keys
        if (not self.canEncode()):
            return self.dcsymbol + message
        hexed = self.strToHex(message)
        cryptedmessage = ""
        i = 0
        while (i < len(hexed)):
            currentChunk = ""
            while (i < len(hexed)
                   and int(currentChunk + hexed[i], base=16) < self.n):
                currentChunk += hexed[i]
                i += 1
            cryptedmessage += self.encodeChunk(currentChunk)
        return self.ecsymbol + cryptedmessage

    def encodeKeys(self, myname):
        # This function encodes public keys
        es = hex(self.e)[2:]
        ns = hex(self.n)[2:]
        checksumm = ""
        for i in range(5):
            checksumm += es[int(es[i], base=16)]
        for i in range(5):
            checksumm += ns[int(ns[i], base=16)]
        return self.keysymbol \
            + self.strToHex(myname) \
            + " " \
            + checksumm \
            + " " \
            + es \
            + " " \
            + ns \
            + self.keysymbol

    def decodeKeys(self, message, myname, isPush=True):
        # This function decodes and applyes public keys
        if (message[0] != message[-1] or message[0] != self.keysymbol):
            return False
        e_ = None
        n_ = None
        try:
            _, _, e_, n_ = map(lambda x: int(x, base=16),
                               message[1:-1].split())
        except ValueError:
            return False
        if (e_ is None or n_ is None):
            return False
        name, ch, es, ns = message[1:-1].split()
        if (len(ch) != 10):
            return False
        for i in range(5):
            if (es[int(es[i], base=16)] != ch[i]
               or ns[int(ns[i], base=16)] != ch[i + 5]):
                return False
        name = self.hexToStr(name)
        if (name == myname):
            return False
        if (isPush):
            self.e = e_
            self.n = n_
        return True
