import random
import re

def upperrep(text):
    return text.upper()
upperrep.command = "upper"

def lowerrep(text):
    return text.lower()
lowerrep.command = "lower"

def scramblerep(text):
    return "".join(random.sample(text, len(text)))
scramblerep.command = "scramble"

def reverserep(text):
    return text[::-1]
reverserep.command = "reverse"

# Removes color from text so it becomes readable after affect of some questionable quirks.
def removecolors(texts):
    return "".join([k[1] for k in re.findall("<c=(.+?)>(.+?)</c>", texts)])
removecolors.command = "decolor"