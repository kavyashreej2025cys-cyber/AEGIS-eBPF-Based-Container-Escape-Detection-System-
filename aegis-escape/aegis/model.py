"""Deep dense autoencoder, NumPy backpropagation and Adam; no GPU required."""
import json
from pathlib import Path
import numpy as np
from .features import NAMES,DIM
class Autoencoder:
    def __init__(self,seed=42):
        rng=np.random.default_rng(seed); self.sizes=[DIM,32,16,4,16,32,DIM]
        self.w=[rng.normal(0,np.sqrt(2/(a+b)),(a,b)) for a,b in zip(self.sizes[:-1],self.sizes[1:])]
        self.b=[np.zeros(b) for b in self.sizes[1:]]
        self.mean=np.zeros(DIM); self.scale=np.ones(DIM); self.threshold=1.
    def forward(self,x):
        a=[x]
        for i,(w,b) in enumerate(zip(self.w,self.b)):
            z=a[-1]@w+b; a.append(z if i==len(self.w)-1 else np.tanh(z))
        return a
    def fit(self,train,validation,epochs=100,batch=64):
        self.mean=train.mean(0); self.scale=np.maximum(train.std(0),0.25)
        x=(train-self.mean)/self.scale; rng=np.random.default_rng(43)
        params=self.w+self.b; m=[np.zeros_like(p) for p in params]; v=[np.zeros_like(p) for p in params]; t=0; history=[]
        for epoch in range(epochs):
            for ids in np.array_split(rng.permutation(len(x)),max(1,int(np.ceil(len(x)/batch)))):
                xb=x[ids]; a=self.forward(xb); grad=2*(a[-1]-xb)/(len(xb)*DIM); gw=[None]*len(self.w); gb=[None]*len(self.b)
                for i in range(len(self.w)-1,-1,-1):
                    gw[i]=a[i].T@grad; gb[i]=grad.sum(0)
                    if i: grad=(grad@self.w[i].T)*(1-a[i]**2)
                t+=1
                for j,g in enumerate(gw+gb):
                    g=np.clip(g,-10,10); m[j]=.9*m[j]+.1*g; v[j]=.999*v[j]+.001*g*g
                    params[j]-=.002*(m[j]/(1-.9**t))/(np.sqrt(v[j]/(1-.999**t))+1e-8)
            history.append(float(np.mean((self.forward(x)[-1]-x)**2)))
        errors=self.score(validation)[0]; self.threshold=max(float(np.quantile(errors,.99)),1e-6)
        return history
    def score(self,x):
        x=np.atleast_2d(x); z=(x-self.mean)/self.scale; errors=(self.forward(z)[-1]-z)**2
        return errors.mean(1),errors
    def save(self,directory,meta):
        d=Path(directory); d.mkdir(parents=True,exist_ok=True)
        np.savez_compressed(d/'autoencoder.npz',mean=self.mean,scale=self.scale,threshold=np.array(self.threshold),**{f'w{i}':x for i,x in enumerate(self.w)},**{f'b{i}':x for i,x in enumerate(self.b)})
        (d/'metadata.json').write_text(json.dumps(dict(meta,features=NAMES,architecture=self.sizes,threshold=self.threshold),indent=2))
    @classmethod
    def load(cls,directory):
        d=Path(directory); meta=json.loads((d/'metadata.json').read_text())
        if meta['features']!=NAMES: raise ValueError('Feature schema mismatch; retrain model')
        model=cls()
        with np.load(d/'autoencoder.npz',allow_pickle=False) as f:
            model.w=[f[f'w{i}'] for i in range(6)]; model.b=[f[f'b{i}'] for i in range(6)]; model.mean=f['mean']; model.scale=f['scale']; model.threshold=float(f['threshold'])
        return model,meta
