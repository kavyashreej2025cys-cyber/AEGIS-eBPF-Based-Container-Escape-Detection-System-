#!/usr/bin/env python3
"""Replay recorded telemetry into the matching server mode with fresh timestamps.
Use only for evaluation; replay is not live kernel telemetry.
"""
import argparse,json,os,time,urllib.request
from pathlib import Path
p=argparse.ArgumentParser(); p.add_argument('file'); p.add_argument('--url',default='http://127.0.0.1:8080'); p.add_argument('--source',choices=['demo','ebpf'],default='demo'); args=p.parse_args()
token=os.environ.get('AEGIS_TOKEN','demo-local-token')
for line in Path(args.file).read_text().splitlines():
    e=json.loads(line); e['ts']=time.time(); e['source']=args.source
    req=urllib.request.Request(args.url+'/api/ingest',data=json.dumps({'events':[e]}).encode(),headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
    with urllib.request.urlopen(req) as r:
        j=json.load(r)
        if j['errors']: raise SystemExit(j['errors'])
    time.sleep(.02)
