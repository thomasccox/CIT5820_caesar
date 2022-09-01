from typing import List, Any


def encrypt(key, plaintext):
    ciphertext = ""
    length = len(plaintext)
    cap = []
    low = []
    for x in range(ord('A'), ord('Z') + 1):
        cap.append(x)

    for y in range(ord('a'), ord('z') + 1):
        low.append(y)

    for x in range(length):
        orig = ord(plaintext[x])
        crypt = orig + key

        if key >= 0:
            if (orig in cap) and crypt > ord('Z'):
                crypt = ord('A') + (crypt - (ord('Z') + 1))

            elif (orig in low) and crypt > ord('z'):
                crypt = ord('a') + (crypt - (ord('z') + 1))

        else:
            if (orig in cap) and crypt < ord('A'):
                crypt = ord('Z') - (ord('A') - (crypt + 1))
                print(chr(crypt))

            elif (orig in low) and crypt > ord('z'):
                crypt = ord('z') - (ord('z') - (crypt + 1))

        ciphertext = ciphertext + chr(crypt)

    return ciphertext


def decrypt(key, ciphertext):
    plaintext = ""
    length = len(ciphertext)
    cap = []
    low = []
    for x in range(ord('A'), ord('Z') + 1):
        cap.append(x)

    for y in range(ord('a'), ord('z') + 1):
        low.append(y)

    for x in range(length):
        crypt = ord(ciphertext[x])
        orig = crypt - key

        if key >= 0:
            if (crypt in cap) and orig < ord('A'):
                orig = ord('Z') - (ord('A') - (orig + 1))

            elif (crypt in low) and orig < ord('a'):
                orig = ord('z') - (ord('a') - (orig + 1))
        else:
            if (crypt in cap) and orig > ord('Z'):
                orig = ord('A') + (orig - (ord('Z') + 1))

            elif (crypt in low) and orig < ord('a'):
                orig = ord('a') + (orig - (ord('z') + 1))

        plaintext = plaintext + chr(orig)

    return plaintext
