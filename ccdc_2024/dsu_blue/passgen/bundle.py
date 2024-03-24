from subprocess import check_output
from bs4 import BeautifulSoup
import htmlmin
import base64

def bundle(path):
    with open(path) as inFile:
        soup = BeautifulSoup(inFile.read(), features="html.parser")

    for script in soup.select('script[src]'):
        script.string = check_output(["google-closure-compiler.cmd", "--js", script["src"]], encoding="utf-8")
        del script["src"]
    
    for img in soup.select('img[src]'):
        with open(img["src"], "rb") as imgFile:
            imgData = imgFile.read()
        
        ext = img['src'].split('.')[-1]
        img.src = f"data:image/{ext};base64,{base64.b64encode(imgData)}"
    
    return htmlmin.minify(str(soup))

with open("passgen.min.html", "w") as outFile:
    outFile.write(bundle("passgen.html"))