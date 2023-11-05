from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
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
    return json.dumps(dict)
