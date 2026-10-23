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
    protection=True;filtering=True
    def monitor(self):
        import time
        for h in self.health.values():h.update(checked_at=utc(),checked_epoch=time.time(),controls_checked_at=utc(),controls_epoch=time.time(),protection_enabled=self.protection,filtering_enabled=self.filtering)
    def agh(self,path,body=None,query=None,settings=None,method=None):
        if path=='protection':self.protection=body['enabled'];return {}
        if path=='filtering/config':self.filtering=body['enabled'];return {}
        if path=='status': return {'version':'DEMO — geen echte AdGuard','protection_enabled':self.protection}
        if path=='dns_info':return {'upstream_dns':['https://dns.example.org/dns-query'],'bootstrap_dns':['1.1.1.1']}
        if path=='rewrite/list':return [{'domain':'nas.home.arpa','answer':'192.0.2.20','enabled':True}]
        if path=='querylog/config':return {'enabled':True,'interval':86400000,'anonymize_client_ip':False}
        if path=='filtering/status': return {'enabled':self.filtering,'filters':[],'user_rules':[]}
        if path=='clients': return {'clients':[]}
        if path=='querylog':
            return {'data':[{'time':utc(),'client':'192.0.2.83','client_info':{'name':'Demo iPhone'},'question':{'name':d,'type':'A'},'reason':r,'status':'NOERROR','rules':[]} for d,r in [('advertising-module.api.dpgmedia.cloud','NotFilteredNotFound'),('tracking-module.api.dpgmedia.cloud','FilteredBlackList'),('login.dpgmedia.net','NotFilteredNotFound'),('unknown.example.net','NotFilteredNotFound')]]}
        if path=='filtering/check_host': return {'reason':'NotFilteredNotFound','rules':[]}
        return {}

if __name__=='__main__':
    import os
    store=DemoStore(tempfile.mkdtemp(prefix='venguard-ui-demo-'))
    store.config['servers']=[{'id':'one','name':'NUC — demo','url':'http://192.0.2.10:3000','username':'','password':'','enabled':True,'dns_host':'192.0.2.10','dns_port':53},{'id':'two','name':'ZimaBoard — demo','url':'http://192.0.2.11:3000','username':'','password':'','enabled':True,'dns_host':'192.0.2.11','dns_port':53}]
    store.config['primary_id']='one';store.align_primary()
    import time
    store.health={'one':{'checked_at':utc(),'checked_epoch':time.time(),'api_ok':True,'protection_enabled':True,'version':'DEMO','dns':{'ok':True,'ms':2.4,'error':''}},'two':{'checked_at':utc(),'checked_epoch':time.time(),'api_ok':False,'protection_enabled':None,'dns':{'ok':False,'ms':None,'error':'Demonstratie van een uitgevallen server.'}}}
    store.config['public_url']='http://demo-venguard.invalid:8098'
    store.config['auto_sync']=False
    store.config['sources'][0]['name']='DEMO — HaGeZi Light (testselectie)'
    store.caches={'hagezi-light':{'rules':['||ads.example.net^','||advertising-module.api.dpgmedia.cloud^'],'counts':{},'fetched':utc()}}
    store.monitor();store.rebuild(False);store.poll()
    server=ThreadingHTTPServer(('0.0.0.0',4173),DemoHandler);server.store=store
    print('DISPOSABLE UI DEMO at http://localhost:4173 — no production data',flush=True)
    server.serve_forever()
