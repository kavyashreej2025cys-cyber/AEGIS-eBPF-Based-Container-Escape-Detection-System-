#!/usr/bin/env python3
import json,sys
from pathlib import Path
import numpy as np
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from aegis.model import Autoencoder
from aegis.synthetic import normal_matrix,events,SCENARIOS
from aegis.features import extract,rules
model,meta=Autoencoder.load(ROOT/'models')
normal=model.score(normal_matrix(500,seed=50000))[0]
result={'scope':'Synthetic-only smoke evaluation; not real attack accuracy','benign_samples':500,'benign_false_positive_rate':float(np.mean(normal>model.threshold)),'scenarios':{}}
for kind in SCENARIOS[1:]:
    batch=[events(kind,seed=60000+i) for i in range(100)]
    detected=model.score(np.stack([extract(e) for e in batch]))[0]>model.threshold
    rule=np.array([bool(rules(e)) for e in batch])
    result['scenarios'][kind]={'autoencoder_rate':float(detected.mean()),'rule_rate':float(rule.mean()),'hybrid_union_rate':float((detected|rule).mean())}
print(json.dumps(result,indent=2))
