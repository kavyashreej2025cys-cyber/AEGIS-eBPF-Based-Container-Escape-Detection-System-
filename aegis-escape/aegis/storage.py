import sqlite3,json,threading,time
class Store:
    def __init__(self,path):
        self.lock=threading.RLock(); self.db=sqlite3.connect(path,check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.executescript('CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts REAL, body TEXT); CREATE TABLE IF NOT EXISTS windows(id INTEGER PRIMARY KEY, ts REAL, body TEXT); CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, ts REAL, body TEXT, acknowledged INTEGER DEFAULT 0);')
        self.db.commit()
    def add(self,table,body):
        if table not in ('events','windows','alerts'): raise ValueError('Unknown table')
        with self.lock:
            cur=self.db.execute(f'INSERT INTO {table}(ts,body) VALUES (?,?)',(body.get('ts',time.time()),json.dumps(body))); self.db.commit()
            return cur.lastrowid
    def recent(self,table,limit=100):
        if table not in ('events','windows','alerts'): raise ValueError('Unknown table')
        with self.lock:
            rows=self.db.execute(f'SELECT id,body'+(',acknowledged' if table=='alerts' else '')+f' FROM {table} ORDER BY id DESC LIMIT ?',(limit,)).fetchall()
        return [dict(json.loads(r[1]),id=r[0],**({'acknowledged':bool(r[2])} if len(r)>2 else {})) for r in rows]
    def ack(self,id):
        with self.lock:
            cur=self.db.execute('UPDATE alerts SET acknowledged=1 WHERE id=?',(id,)); self.db.commit(); return cur.rowcount>0
    def prune(self,seconds=604800):
        with self.lock:
            for table in ('events','windows','alerts'): self.db.execute(f'DELETE FROM {table} WHERE ts<?',(time.time()-seconds,))
            self.db.commit()
    def close(self): self.db.close()
