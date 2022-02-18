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
    matches = re.finditer("<c=(.+?)>(.+?)</c>", texts)
    answer = [(ch, None) for ch in texts]
    for match in matches:
        ms = texts[match.start():match.end()]
        colour = re.search("=(.+?)>", ms).group(0)[1:-1]
        text = re.search(">(.+?)<", ms).group(0)[1:-1]
        answer[match.start()] = (text, colour)
        for i in range(match.start() + 1, match.end()):
            answer[i] = (None, None)
    text = ""
    for (ch, col) in answer:
        text += ch
    return text
removecolors.command = "decolor"