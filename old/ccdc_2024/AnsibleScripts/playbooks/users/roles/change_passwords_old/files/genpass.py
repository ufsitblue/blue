"""
Script to generate a password on Linux machines

Copyright (c) 2024 Yuliang Huang
"""
import os
import secrets
import sys
from typing import List

def printhelp(programname: str):
    print(programname + " <NUMBER_OF_WORDS>")
    print("NUMBER_OF_WORDS - The number of words in the password to generate")

def genpass(num_words: int = 4) -> List[str]:
    """
    Gets a password of a certain length, as a list of strings
    :param num_words: Number of words in the password. Default is 4
    :return: A list of num_words strings.
    """
    basepath = os.path.abspath(".")
    try:
        basepath = sys._MEIPASS
    except Exception:
        pass

    wordlist: list = []
    with open(basepath + os.sep + "WORDLIST.TXT", "r") as wordlistfile:
        while True:
            currentword = wordlistfile.readline()
            if not currentword:
                break
            else:
                wordlist.append(wordlistfile.readline())
    
    output_words = []
    for _ in range(num_words):
        output_words.append(secrets.choice(wordlist).strip())

    return output_words

def main(argv: List[str]) -> int:
    
    words = 4
    if len(argv) >= 2:
        try:
            words = int(argv[1])
        except ValueError:
            printhelp(argv[0])
            return 0
    
    output_words = genpass(words)

    print(' '.join(output_words))

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
