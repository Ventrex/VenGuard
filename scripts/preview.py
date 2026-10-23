"""Browser QA only: disposable demo data, no real AdGuard access, no login needed.

Never use this script to deploy VenGuard; use docker compose instead.
"""
import copy
import sys
import tempfile
from pathlib import Path
from http.server import ThreadingHTTPServer
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from server import Store,Handler,utc

class DemoHandler(Handler):
    def auth(self): return True

class DemoStore(Store):
    def agh(self,path,body=None,query=None,settings=None):
        if path=='status': return {'version':'DEMO — geen echte AdGuard','protection_enabled':True}
        if path=='filtering/status': return {'enabled':True,'filters':[],'user_rules':[]}
        if path=='clients': return {'clients':[]}
        if path=='querylog':
            return {'data':[{'time':utc(),'client':'192.0.2.83','client_info':{'name':'Demo iPhone'},'question':{'name':d,'type':'A'},'reason':r,'status':'NOERROR','rules':[]} for d,r in [('advertising-module.api.dpgmedia.cloud','NotFilteredNotFound'),('tracking-module.api.dpgmedia.cloud','FilteredBlackList'),('login.dpgmedia.net','NotFilteredNotFound'),('unknown.example.net','NotFilteredNotFound')]]}
        if path=='filtering/check_host': return {'reason':'NotFilteredNotFound','rules':[]}
        return {}

if __name__=='__main__':
    import os
    store=DemoStore(tempfile.mkdtemp(prefix='venguard-ui-demo-'))
    store.config['adguard']['url']='http://demo-adguard.invalid'
    store.config['public_url']='http://demo-venguard.invalid:8098'
    store.config['auto_sync']=False
    store.config['sources'][0]['name']='DEMO — HaGeZi Light (testselectie)'
    store.caches={'hagezi-light':{'rules':['||ads.example.net^','||advertising-module.api.dpgmedia.cloud^'],'counts':{},'fetched':utc()}}
    store.rebuild(False);store.poll()
    server=ThreadingHTTPServer(('0.0.0.0',4173),DemoHandler);server.store=store
    print('DISPOSABLE UI DEMO at http://localhost:4173 — no production data',flush=True)
    server.serve_forever()
