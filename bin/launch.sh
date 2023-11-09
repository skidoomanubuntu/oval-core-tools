#!/bin/bash
cd $SNAP
echo Executing in $SNAP
$SNAP/bin/uvicorn app.main:app --port 4042 --host 0.0.0.0
