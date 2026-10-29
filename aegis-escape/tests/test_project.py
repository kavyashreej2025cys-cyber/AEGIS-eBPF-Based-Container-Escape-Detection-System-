import json,tempfile,threading,time,unittest,urllib.request,urllib.error
from pathlib import Path
import numpy as np
from aegis.features import extract,rules,NAMES
from aegis.model import Autoencoder
from aegis.synthetic import events,normal_matrix
from aegis.storage import Store
from aegis.engine import Engine
from aegis.server import Application,Handler,ThreadingHTTPServer
ROOT=Path(__file__).resolve().parents[1]
class ProjectTests(unittest.TestCase):
    def test_features_and_failed_attempt(self):
        e=events('namespace',seed=1); x=extract(e)
        self.assertEqual(len(x),len(NAMES)); self.assertTrue(np.isfinite(x).all()); self.assertTrue(any(r['outcome']=='failed attempt' for r in rules(e)))
    def test_training_roundtrip(self):
        x=normal_matrix(150); m=Autoencoder(); loss=m.fit(x[:100],x[100:125],epochs=12)
        self.assertLess(loss[-1],loss[0])
        with tempfile.TemporaryDirectory() as d:
            m.save(d,{'provenance':'test'}); loaded,_=Autoencoder.load(d); np.testing.assert_allclose(m.score(x)[0],loaded.score(x)[0])
    def test_pretrained_unknown_anomaly(self):
        m,_=Autoencoder.load(ROOT/'models'); score=m.score(extract(events('unknown-burst',seed=1)))[0][0]
        self.assertGreater(score,m.threshold)
    def test_window_isolation_ack_and_validation(self):
        with tempfile.TemporaryDirectory() as d:
            s=Store(Path(d)/'db'); m,_=Autoencoder.load(ROOT/'models'); e=Engine(m,s)
            for cid,scenario in [('one','normal'),('two','namespace')]:
                for event in events(scenario,container=cid,seed=1): e.ingest(event)
            self.assertEqual(e.flush(force=True),2); self.assertEqual({w['container_id'] for w in s.recent('windows')},{'one','two'})
            a=next(a for a in s.recent('alerts') if a['container_id']=='two'); self.assertTrue(s.ack(a['id'])); self.assertTrue(s.recent('alerts')[0]['acknowledged'])
            bad=events()[0]; bad['ts']=0
            with self.assertRaises(ValueError): e.ingest(bad)
            s.close()
    def test_http_auth_inject_and_export(self):
        with tempfile.TemporaryDirectory() as d:
            app=Application(data=d); server=ThreadingHTTPServer(('127.0.0.1',0),Handler); server.app=app
            worker=threading.Thread(target=server.serve_forever); worker.start(); url=f'http://127.0.0.1:{server.server_port}'
            try:
                req=urllib.request.Request(url+'/api/demo',data=b'{"scenario":"namespace"}',headers={'Content-Type':'application/json'})
                with self.assertRaises(urllib.error.HTTPError) as ex: urllib.request.urlopen(req)
                self.assertEqual(ex.exception.code,401)
                req.add_header('Authorization','Bearer demo-local-token')
                with urllib.request.urlopen(req) as response: self.assertTrue(json.load(response)['ok'])
                app.engine.flush(force=True)
                with urllib.request.urlopen(url+'/api/alerts') as r: self.assertGreater(len(json.load(r)),0)
                with urllib.request.urlopen(url+'/api/export') as r: self.assertIn(b'namespace',r.read().replace(b'setns',b'namespace'))
                with urllib.request.urlopen(url+'/') as r: self.assertIn(b'AEGIS',r.read())
            finally: server.shutdown(); worker.join(); server.server_close(); app.store.close()
    def test_live_rejects_demo_and_bad_events(self):
        with tempfile.TemporaryDirectory() as d:
            app=Application(mode='live',data=d,token='test')
            server=ThreadingHTTPServer(('127.0.0.1',0),Handler); server.app=app
            worker=threading.Thread(target=server.serve_forever); worker.start()
            url=f'http://127.0.0.1:{server.server_port}'
            def post(route,body,origin=None):
                headers={'Content-Type':'application/json','Authorization':'Bearer test'}
                if origin: headers['Origin']=origin
                return urllib.request.urlopen(urllib.request.Request(url+route,data=json.dumps(body).encode(),headers=headers))
            try:
                with self.assertRaises(urllib.error.HTTPError) as ex: post('/api/demo',{'scenario':'namespace'})
                self.assertEqual(ex.exception.code,409)
                with post('/api/ingest',{'events':events(seed=1)[:1]}) as r:
                    j=json.load(r); self.assertEqual(j['accepted'],0); self.assertEqual(len(j['errors']),1)
                valid=events(seed=1)[0]; valid['source']='ebpf'
                invalid=dict(valid,pid='wrong')
                with post('/api/ingest',{'events':[valid,invalid]}) as r:
                    j=json.load(r); self.assertEqual(j['accepted'],1); self.assertEqual(len(j['errors']),1)
                with self.assertRaises(urllib.error.HTTPError) as ex: post('/api/ack',{'id':1},'http://evil.invalid')
                self.assertEqual(ex.exception.code,403)
            finally: server.shutdown(); worker.join(); server.server_close(); app.store.close()
    def test_backpressure_and_source_isolation(self):
        with tempfile.TemporaryDirectory() as d:
            store=Store(Path(d)/'db'); model,_=Autoencoder.load(ROOT/'models'); engine=Engine(model,store)
            one=events(seed=1)[0]; key=(one['source'],one['container_id'],int(time.time()//engine.window))
            engine.buckets[key]=[one]*5000
            self.assertFalse(engine.ingest(one)); self.assertEqual(engine.dropped,1)
            engine.buckets.clear()
            engine.ingest(one); real=dict(one,source='ebpf'); engine.ingest(real)
            self.assertEqual(engine.flush(force=True),2); store.close()
    def test_collector_generation(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('collector',ROOT/'collector/collect.py'); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        code=module.program(['openat','setns']); self.assertIn('sys_enter_openat',code); self.assertIn('sys_exit_setns',code); self.assertNotIn('sys_enter_mount',code)
if __name__=='__main__': unittest.main()
