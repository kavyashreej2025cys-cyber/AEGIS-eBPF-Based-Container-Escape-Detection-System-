import argparse,hmac,json,os,threading,time,signal
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from .model import Autoencoder
from .storage import Store
from .engine import Engine
from .synthetic import events,SCENARIOS
ROOT=Path(__file__).resolve().parent.parent
class Application:
    def __init__(self,mode='demo',data=None,models=None,token=None):
        self.mode=mode; self.token=token or os.environ.get('AEGIS_TOKEN','demo-local-token' if mode=='demo' else '')
        if not self.token: raise ValueError('Live mode requires AEGIS_TOKEN')
        self.model,self.meta=Autoencoder.load(models or ROOT/'models')
        d=Path(data or ROOT/'data'); d.mkdir(parents=True,exist_ok=True); self.store=Store(d/'aegis.sqlite3')
        self.engine=Engine(self.model,self.store,self.meta['window_seconds']); self.stop=threading.Event(); self.collector={}; self.tick=0
    def background(self):
        while not self.stop.wait(1):
            if self.mode=='demo':
                self.tick+=1
                if self.tick%5==1:
                    for cid in ('demo-web','demo-api','demo-worker'):
                        for e in events(container=cid): self.engine.ingest(e)
            self.engine.flush()
            if self.tick%60==0: self.store.prune()
            if self.mode!='demo': self.tick+=1
    def status(self):
        with self.engine.lock: containers=list(self.engine.last.values())
        return dict(mode=self.mode,received=self.engine.received,dropped=self.engine.dropped,containers=containers,model=self.meta,collector=self.collector,collector_stale=time.time()-self.collector.get('ts',0)>15)
    def close(self): self.stop.set()
class Handler(BaseHTTPRequestHandler):
    server_version='AEGIS/1.0'
    def log_message(self,*args): pass
    @property
    def app(self): return self.server.app
    def reply(self,code,value,ctype='application/json'):
        body=json.dumps(value).encode() if ctype=='application/json' else value
        self.send_response(code); self.send_header('Content-Type',ctype); self.send_header('Content-Length',str(len(body))); self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff'); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        path=urlsplit(self.path).path
        if path=='/': return self.reply(200,(ROOT/'dashboard/index.html').read_bytes(),'text/html; charset=utf-8')
        if path=='/api/health': return self.reply(200,{'status':'ok','mode':self.app.mode})
        if path=='/api/status': return self.reply(200,self.app.status())
        if path in ('/api/events','/api/windows','/api/alerts'): return self.reply(200,self.app.store.recent(path.rsplit('/',1)[-1]))
        if path=='/api/export':
            rows=self.app.store.recent('alerts',1000)
            return self.reply(200,('\n'.join(json.dumps(r) for r in reversed(rows))+'\n').encode(),'application/x-ndjson')
        self.reply(404,{'error':'Not found'})
    def do_POST(self):
        if not hmac.compare_digest(self.headers.get('Authorization',''), 'Bearer '+self.app.token): return self.reply(401,{'error':'Bearer token required'})
        # Reject browser cross-origin mutation attempts; API collectors do not send Origin.
        origin=self.headers.get('Origin')
        if origin and urlsplit(origin).netloc!=self.headers.get('Host'): return self.reply(403,{'error':'Origin mismatch'})
        try:
            n=int(self.headers.get('Content-Length','0'))
            if not 0<n<=1048576: return self.reply(413,{'error':'Body must be 1 byte to 1 MiB'})
            value=json.loads(self.rfile.read(n)); path=urlsplit(self.path).path
            if path=='/api/ingest':
                batch=value.get('events',[])
                if not isinstance(batch,list) or not 1<=len(batch)<=500: raise ValueError('Send 1–500 events')
                accepted=0; errors=[]
                for i,e in enumerate(batch):
                    try:
                        if not isinstance(e,dict): raise ValueError('Event must be an object')
                        if e.get('source')!=('demo' if self.app.mode=='demo' else 'ebpf'): raise ValueError('Event source does not match server mode')
                        accepted+=int(self.app.engine.ingest(e))
                    except (ValueError,TypeError) as ex: errors.append({'index':i,'error':str(ex)})
                return self.reply(200,{'accepted':accepted,'errors':errors,'dropped':len(batch)-accepted-len(errors)})
            if path=='/api/collector':
                self.app.collector=dict(ts=time.time(),lost=int(value.get('lost',0)),queue_dropped=int(value.get('queue_dropped',0)),delivery_errors=int(value.get('delivery_errors',0)),probes=value.get('probes',[]),skipped=int(value.get('skipped',0)))
                return self.reply(200,{'ok':True})
            if path=='/api/demo':
                if self.app.mode!='demo': return self.reply(409,{'error':'Demo injection disabled in live mode'})
                kind=value.get('scenario')
                if kind not in SCENARIOS: raise ValueError('Unknown scenario')
                for e in events(kind,container='demo-web'): self.app.engine.ingest(e)
                return self.reply(200,{'ok':True,'scenario':kind,'message':'Alert appears after the current window closes'})
            if path=='/api/ack':
                ok=self.app.store.ack(int(value['id'])); return self.reply(200 if ok else 404,{'ok':ok})
            self.reply(404,{'error':'Not found'})
        except (ValueError,TypeError,KeyError,json.JSONDecodeError,AttributeError) as ex: self.reply(400,{'error':str(ex)})
def main():
    p=argparse.ArgumentParser(); p.add_argument('--mode',choices=['demo','live'],default='demo'); p.add_argument('--port',type=int,default=8080); p.add_argument('--data'); p.add_argument('--models'); args=p.parse_args()
    app=Application(args.mode,args.data,args.models); server=ThreadingHTTPServer(('127.0.0.1',args.port),Handler); server.app=app; server.daemon_threads=True
    worker=threading.Thread(target=app.background); worker.start()
    print(f'AEGIS {args.mode}: http://127.0.0.1:{args.port} (Ctrl+C to stop)',flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: app.close(); worker.join(); server.server_close(); app.store.close()
if __name__=='__main__': main()
