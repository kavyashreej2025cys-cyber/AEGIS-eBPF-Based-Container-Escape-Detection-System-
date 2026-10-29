import threading,time
from collections import defaultdict
from .features import extract,rules,NAMES,OPS
class Engine:
    def __init__(self,model,store,window=5):
        self.model=model; self.store=store; self.window=window; self.lock=threading.RLock(); self.buckets=defaultdict(list); self.last={}; self.received=0; self.dropped=0
    def ingest(self,e):
        now=time.time()
        required=('ts','container_id','pid','syscall','source')
        if any(k not in e for k in required): raise ValueError('Missing required event fields')
        if e['syscall'] not in OPS or e['source'] not in ('demo','ebpf'): raise ValueError('Invalid syscall/source')
        if not isinstance(e['container_id'],str) or not 1<=len(e['container_id'])<=128: raise ValueError('Invalid container ID')
        for k in ('pid','uid','ret','cgroup_id'):
            if k in e and (not isinstance(e[k],int) or isinstance(e[k],bool)): raise ValueError('Invalid integer field '+k)
        if not isinstance(e['ts'],(int,float)) or not now-60<=e['ts']<=now+5: raise ValueError('Timestamp outside live ingestion tolerance')
        for k in ('path','comm'):
            if k in e and (not isinstance(e[k],str) or len(e[k])>1024): raise ValueError('Invalid string field '+k)
        # Receive-time windows keep bounded latency and avoid late event reopening.
        key=(e['source'],e['container_id'],int(now//self.window))
        with self.lock:
            if len(self.buckets)>=2000 and key not in self.buckets or len(self.buckets.get(key,[]))>=5000:
                self.dropped+=1; return False
            self.buckets[key].append(e); self.received+=1; self.store.add('events',e)
        return True
    def flush(self,force=False):
        now=time.time(); boundary=int(now//self.window)
        with self.lock:
            ready=[(k,self.buckets.pop(k)) for k in list(self.buckets) if force or k[2]<boundary]
        for (source,cid,bucket),events in ready:
            x=extract(events); scores,errors=self.model.score(x); score=float(scores[0]); evidence=rules(events)
            top=sorted(zip(NAMES,errors[0]),key=lambda p:p[1],reverse=True)[:5]
            record=dict(ts=now,container_id=cid,source=source,window_start=bucket*self.window,event_count=len(events),score=score,threshold=self.model.threshold,ratio=score/self.model.threshold,anomaly=score>self.model.threshold,rules=evidence,top_features=[{'feature':n,'error':float(v)} for n,v in top],features=x.tolist())
            self.store.add('windows',record)
            with self.lock: self.last[(source,cid)]=record
            if record['anomaly'] or evidence:
                self.store.add('alerts',dict(record,severity='high' if evidence else 'medium',detection='hybrid' if evidence and record['anomaly'] else 'rule' if evidence else 'autoencoder',summary='Suspicious behavior; analyst verification required'))
        with self.lock:
            self.last={k:v for k,v in self.last.items() if now-v['ts']<3600}
        return len(ready)
