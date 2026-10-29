#!/usr/bin/env python3
"""Host-side BCC collector. Requires Linux root and cgroup v2.
Collects syscall entry + exit, retaining entry cgroup and pathname.
Never executes an attack. JSONL output and a bounded retry queue.
"""
import argparse,json,os,queue,re,sys,threading,time,urllib.request
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1]))
from aegis.features import OPS
BASE=r"""
#include <uapi/linux/ptrace.h>
struct event_t { u64 cgroup; u64 started; u32 pid; u32 tid; u32 uid; u32 op; s64 ret; char comm[16]; char path[192]; };
BPF_HASH(pending, u64, struct event_t, 32768);
BPF_PERF_OUTPUT(events);
"""
def program(available):
    code=BASE
    for i,op in enumerate(OPS):
        if op not in available: continue
        patharg={'openat':'filename','execve':'filename','mount':'dir_name','chroot':'filename','chmod':'filename','fchmodat':'filename','umount2':'name'}.get(op)
        read=f'bpf_probe_read_user_str(e.path, sizeof(e.path), args->{patharg});' if patharg else ''
        code+=f"""
TRACEPOINT_PROBE(syscalls, sys_enter_{op}) {{
    u64 id=bpf_get_current_pid_tgid(); struct event_t e={{}};
    e.cgroup=bpf_get_current_cgroup_id(); e.started=bpf_ktime_get_ns(); e.pid=id>>32; e.tid=(u32)id;
    e.uid=(u32)bpf_get_current_uid_gid(); e.op={i}; bpf_get_current_comm(e.comm,sizeof(e.comm));
    {read}
    pending.update(&id,&e); return 0;
}}
TRACEPOINT_PROBE(syscalls, sys_exit_{op}) {{
    u64 id=bpf_get_current_pid_tgid(); struct event_t *e=pending.lookup(&id);
    if (e) {{ e->ret=args->ret; events.perf_submit(args,e,sizeof(*e)); pending.delete(&id); }}
    return 0;
}}
"""
    # Remove pending entries when a task exits during a non-returning syscall.
    code+="""
TRACEPOINT_PROBE(sched, sched_process_exit) {
    u64 id=bpf_get_current_pid_tgid(); pending.delete(&id); return 0;
}
"""
    return code

def container_from_pid(pid):
    try:
        text=Path(f'/proc/{pid}/cgroup').read_text()
        found=re.search(r'(?<![a-f0-9])([a-f0-9]{64})(?![a-f0-9])',text)
        return found.group(1) if found else None
    except OSError: return None

def main():
    p=argparse.ArgumentParser(); p.add_argument('--url',default='http://127.0.0.1:8080'); p.add_argument('--output',default='data/capture.jsonl'); p.add_argument('--cgroup-id',type=int,action='append',default=[],help='Explicit monitored cgroup v2 ID; can repeat'); args=p.parse_args()
    if os.geteuid()!=0: raise SystemExit('Run collector with sudo -E on the Linux container host.')
    if not Path('/sys/fs/cgroup/cgroup.controllers').exists(): raise SystemExit('cgroup v2 required')
    token=os.environ.get('AEGIS_TOKEN')
    if not token: raise SystemExit('Set AEGIS_TOKEN; use sudo -E to preserve it.')
    from bcc import BPF
    trace=next((x for x in [Path('/sys/kernel/tracing/events'),Path('/sys/kernel/debug/tracing/events')] if x.exists()),None)
    if trace is None: raise SystemExit('tracefs missing; see docs/LINUX_SETUP.md')
    available=[op for op in OPS if (trace/'syscalls'/f'sys_enter_{op}'/'format').exists() and (trace/'syscalls'/f'sys_exit_{op}'/'format').exists()]
    if not available: raise SystemExit('No syscall tracepoints available')
    b=BPF(text=program(available))
    q=queue.Queue(maxsize=10000); stop=threading.Event(); stats={'lost':0,'queue_dropped':0,'delivery_errors':0,'skipped':0}; identity={}; probes=available
    Path(args.output).parent.mkdir(parents=True,exist_ok=True)
    capture=open(args.output,'a',buffering=1)
    def send(endpoint,payload):
        req=urllib.request.Request(args.url.rstrip('/')+endpoint,data=json.dumps(payload).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+token})
        with urllib.request.urlopen(req,timeout=2) as response: return json.load(response)
    def relay():
        heartbeat=0; batch=[]
        while not stop.is_set():
            try:
                if len(batch)<200: batch.append(q.get(timeout=.2))
                while len(batch)<200: batch.append(q.get_nowait())
            except queue.Empty: pass
            if batch:
                try:
                    result=send('/api/ingest',{'events':batch})
                    if result.get('errors'): print('Backend rejected events: '+json.dumps(result['errors'][:3]),file=sys.stderr)
                    stats['queue_dropped']+=len(result.get('errors',[]))+result.get('dropped',0); batch=[]
                except Exception:
                    stats['delivery_errors']+=1
                    # Retain up to one batch for retry, but expire old events to avoid late window corruption.
                    expired=[e for e in batch if time.time()-e['ts']>50]; stats['queue_dropped']+=len(expired); batch=[e for e in batch if time.time()-e['ts']<=50]
                    stop.wait(1)
            if time.time()-heartbeat>=5:
                heartbeat=time.time()
                try: send('/api/collector',dict(stats,probes=probes))
                except Exception: stats['delivery_errors']+=1
        stats['queue_dropped']+=len(batch)+q.qsize()
    def callback(cpu,data,size):
        e=b['events'].event(data); cg=int(e.cgroup); now=time.time()
        # Cache stable runtime cgroup identities for short-lived processes.
        cid=identity.get(cg)
        if cg in args.cgroup_id: cid=f'cgroup-{cg}'
        elif not cid: cid=container_from_pid(e.pid)
        if not cid: stats['skipped']+=1; return
        if len(identity)>10000: identity.clear()
        identity[cg]=cid
        body=dict(ts=now,container_id=cid,cgroup_id=cg,pid=int(e.pid),tid=int(e.tid),uid=int(e.uid),comm=bytes(e.comm).split(b'\0')[0].decode(errors='replace'),syscall=OPS[e.op],ret=int(e.ret),path=bytes(e.path).split(b'\0')[0].decode(errors='replace'),duration_ns=max(0,time.monotonic_ns()-int(e.started)),source='ebpf')
        capture.write(json.dumps(body)+'\n')
        try: q.put_nowait(body)
        except queue.Full: stats['queue_dropped']+=1
    def lost(cpu,count): stats['lost']+=count
    b['events'].open_perf_buffer(callback,page_cnt=64,lost_cb=lost)
    worker=threading.Thread(target=relay); worker.start(); print('Attached probes: '+', '.join(probes),flush=True)
    print('Skipped unsupported probes: '+', '.join(set(OPS)-set(probes)),flush=True)
    try:
        while True: b.perf_buffer_poll(timeout=500)
    except KeyboardInterrupt: pass
    finally:
        stop.set(); worker.join(timeout=10); capture.close(); print(json.dumps(stats))
if __name__=='__main__': main()
