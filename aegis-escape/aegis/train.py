import argparse,json,time
from pathlib import Path
import numpy as np
from .model import Autoencoder
from .features import extract
from .synthetic import normal_matrix,events,SCENARIOS

def main():
    p=argparse.ArgumentParser(description='Train on trusted benign telemetry; never train on alerts automatically.')
    p.add_argument('--input',help='Trusted benign events JSONL exported by collector'); p.add_argument('--output',default='models'); p.add_argument('--epochs',type=int,default=100); p.add_argument('--window',type=float,default=5)
    args=p.parse_args()
    if args.epochs<1 or args.window<=0: p.error('epochs and window must be positive')
    if args.input:
        groups={}
        for line in Path(args.input).read_text().splitlines():
            e=json.loads(line); k=(e['container_id'],int(e['ts']//args.window)); groups.setdefault(k,[]).append(e)
        # Chronological window split, rather than splitting events from one window.
        keys=sorted(groups,key=lambda k:k[1]); x=np.stack([extract(groups[k]) for k in keys]); provenance='operator-supplied benign capture'
    else: x=normal_matrix(1800); provenance='synthetic demonstration baseline'
    if len(x)<100: raise SystemExit('Need at least 100 nonempty windows for train/calibration/test separation')
    a=int(len(x)*.7); b=int(len(x)*.85); model=Autoencoder(); history=model.fit(x[:a],x[a:b],epochs=args.epochs)
    benign=model.score(x[b:])[0]; metrics={'held_out_benign_windows':len(benign),'benign_false_positive_rate':float((benign>model.threshold).mean()),'initial_loss':history[0],'final_loss':history[-1]}
    if not args.input:
        metrics['synthetic_anomaly_detection_rate']={s:float(np.mean(model.score(np.stack([extract(events(s,seed=10000+i)) for i in range(100)]))[0]>model.threshold)) for s in SCENARIOS[1:]}
    model.save(args.output,dict(created_at=time.time(),provenance=provenance,window_seconds=args.window,train_windows=a,calibration_windows=b-a,metrics=metrics))
    Path(args.output,'training-history.json').write_text(json.dumps(history))
    print(json.dumps(metrics,indent=2))
if __name__=='__main__': main()
