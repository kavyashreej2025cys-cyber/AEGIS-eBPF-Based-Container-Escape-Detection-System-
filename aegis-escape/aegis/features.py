import numpy as np
OPS = ['execve','openat','connect','mount','umount2','setns','unshare','ptrace','bpf','clone','clone3','chmod','fchmodat','chroot']
NAMES = ['count_'+x for x in OPS] + ['failed','root','unique_pids','sensitive_path','runtime_socket','shell']
DIM = len(NAMES)
SENSITIVE = ('/proc/1/root','/proc/1/ns','/sys/fs/cgroup','/etc/shadow','/proc/sys','/dev/mem')
def extract(events):
    counts = [sum(e['syscall']==op for e in events) for op in OPS]
    counts += [sum(e.get('ret',0)<0 for e in events),sum(e.get('uid',1)==0 for e in events),len({e['pid'] for e in events}),sum(any(p in e.get('path','') for p in SENSITIVE) for e in events),sum(any(p in e.get('path','') for p in ('docker.sock','containerd.sock','crio.sock')) for e in events),sum(e['syscall']=='execve' and e.get('path','').rsplit('/',1)[-1] in ('sh','bash','dash','zsh') for e in events)]
    return np.log1p(np.asarray(counts,dtype=np.float64))
def rules(events):
    found=[]
    for e in events:
        op=e['syscall']; path=e.get('path',''); failed=e.get('ret',0)<0
        reason=None
        if op in ('setns','mount','chroot','ptrace','bpf'): reason='Sensitive syscall: '+op
        elif any(x in path for x in ('docker.sock','containerd.sock','crio.sock')): reason='Container runtime socket access'
        elif any(x in path for x in ('/proc/1/root','/proc/1/ns','/dev/mem')): reason='Host-like resource path access'
        if reason:
            item={'reason':reason,'outcome':'failed attempt' if failed else 'syscall returned successfully','pid':e['pid'],'syscall':op,'path':path}
            if item not in found: found.append(item)
    return found[:20]
