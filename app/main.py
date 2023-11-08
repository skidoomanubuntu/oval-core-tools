from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import os, subprocess, time, json

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def isOlderThanADay(file):
    fileTime = os.path.getmtime(file)
    return ((time.time() - fileTime) / 3600 > 24)

@app.get("/")
def index():
    os.chdir(os.getenv('SNAP_DATA'))
    dict = {}
    needToRefresh = False
    # Case 1: The PHP files were never generated, so there is nothing to show for
    file_prefixes = ['cve', 'usn']
    for prefix in file_prefixes:
        if not os.path.isfile('%s_stats.php' % prefix):
            dict[prefix] = ''
            needToRefresh = True
        else:
            if isOlderThanADay('%s_stats.php' % prefix):
                needToRefresh = True
            with open('%s_stats.php' % prefix, 'r') as myFile:
                dict[prefix] = myFile.read()
    print ('now executing in %s' % os.getcwd())
    if needToRefresh:
        subprocess.Popen(['python3', '%s/bin/security_scan.py' % os.getenv('SNAP')])
        return "REFRESHING"
    return "OK"

@app.get("/usn")
def usn():
    if not os.path.isfile("usn_stats.php"):
        return "BEING GENERATED"
    with open("usn_stats.php", "r") as myFile:
        contents = myFile.read()
        print ('CONTENTS: %s' % contents)
        return Response(content=contents)

@app.get("/cve")
def cve():
    if not os.path.isfile("cve_stats.php"):
        return "BEING GENERATED"
    with open("cve_stats.php", "r") as myFile:
        contents = myFile.read()
        return Response(content=contents, status_code=200)
