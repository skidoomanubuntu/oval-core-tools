from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os, subprocess

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def index():
    msg = "Operating in pwd %s" % os.getcwd()
    os.chdir(os.getenv('SNAP_DATA'))
    print ('now executing in %s' % os.getcwd())
    subprocess.Popen(['python3', '%s/bin/security_scan.py' % os.getenv('SNAP')])
    return msg
