import os
import secrets
import sys

def printhelp(programname: str):
    print(programname + " <NUMBER_OF_WORDS>")
    print("NUMBER_OF_WORDS - The number of words in the password to generate")

def main(argv: list[str]) -> int:
    basepath = os.path.abspath(".")
    try:
        basepath = sys._MEIPASS
    except Exception:
        pass

    words = 4
    if len(argv) >= 2:
        try:
            words = int(argv[1])
        except ValueError:
            printhelp(argv[0])
            return 0
    
    wordlist: list = []
    with open(basepath + os.sep + "WORDLIST.TXT", "r") as wordlistfile:
        while True:
            currentword = wordlistfile.readline()
            if not currentword:
                break
            else:
                wordlist.append(wordlistfile.readline())
    
    for _ in range(words):
        print(end=secrets.choice(wordlist).strip() + ' ')
    print()

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
