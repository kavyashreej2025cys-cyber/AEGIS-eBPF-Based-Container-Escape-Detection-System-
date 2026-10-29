"""Synthetic telemetry only. Does not execute escape operations."""
import random,time
from .features import extract
SCENARIOS=['normal','namespace','runtime-socket','mount-probe','unknown-burst']
def events(kind='normal',container='demo-web',seed=None,ts=None):
    rng=random.Random(seed); ts=time.time() if ts is None else ts
    ops=['openat']*8+['connect']*2+['clone','execve']
    n=rng.randint(12,40); out=[]
    for i in range(n):
        op=rng.choice(ops); path='/app/config.json' if op=='openat' else '/usr/bin/python3' if op=='execve' else ''
        out.append(dict(ts=ts,container_id=container,cgroup_id=1001,pid=200+rng.randint(0,3),uid=1000,comm='python3',syscall=op,path=path,ret=0,source='demo'))
    base=dict(ts=ts,container_id=container,cgroup_id=1001,pid=201,uid=0,comm='demo-probe',ret=-1,source='demo')
    additions={'namespace':[('openat','/proc/1/ns/mnt'),('setns',''),('unshare','')]*5,'runtime-socket':[('openat','/var/run/docker.sock')]*8,'mount-probe':[('mount','/host'),('chroot','/host')]*5,'unknown-burst':[('connect','')]*120+[('execve','/bin/sh')]*30}
    for op,path in additions.get(kind,[]): out.append(dict(base,syscall=op,path=path))
    return out
def normal_matrix(n,seed=42):
    return __import__('numpy').stack([extract(events(seed=seed+i)) for i in range(n)])
