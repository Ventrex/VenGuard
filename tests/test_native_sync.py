"""Exercise the bundled, unmodified Go engine against real local HTTP services.

Run in the Docker image with ADGUARD_SYNC_BINARY set, or point that variable
at the official release binary on a developer machine.
"""
import copy
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
sys.path.insert(0,'/app')
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from server import Store

class AGH(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):self.respond()
    def do_POST(self):self.respond()
    def do_PUT(self):self.respond()
    def respond(self):
        path=self.path.split('?')[0];raw=self.rfile.read(int(self.headers.get('Content-Length','0')));body=json.loads(raw or '{}')
        if self.headers.get('Authorization')!='Basic dGVzdDpzZWNyZXQ=':self.send_response(401);self.end_headers();return
        values={
          '/control/status':{'version':'v0.107.79','protection_enabled':True,'running':True,'dns_addresses':['127.0.0.1'],'dns_port':53},
          '/control/profile':{'name':'test','language':'en','theme':'dark'},
          '/control/parental/status':{'enabled':False},
          '/control/safebrowsing/status':{'enabled':False},
          '/control/safesearch/status':{'enabled':False},
          '/control/rewrite/settings':{'enabled':True},
          '/control/rewrite/list':[],
          '/control/blocked_services/get':{'ids':[],'schedule':{'time_zone':'Local'}},
          '/control/filtering/status':{'enabled':True,'interval':24,'filters':[],'whitelist_filters':[],'user_rules':self.server.rules},
          '/control/clients':{'clients':[],'auto_clients':[],'supported_tags':[]},
          '/control/querylog/config':{'enabled':True,'interval':86400000,'anonymize_client_ip':False,'ignored':[]},
          '/control/stats/config':{'enabled':True,'interval':86400000,'ignored':[]},
          '/control/access/list':{'allowed_clients':[],'disallowed_clients':[],'blocked_hosts':[]},
          '/control/dns_info':{'upstream_dns':['1.1.1.1'],'bootstrap_dns':['1.1.1.1'],'fallback_dns':[],'cache_size':4194304},
        }
        if path=='/control/filtering/set_rules':self.server.rules=body['rules'];value={}
        elif path in ['/control/filtering/refresh','/control/filtering/config']:value={}
        elif path in values:value=values[path]
        else:self.send_response(404);self.end_headers();return
        raw=json.dumps(value).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)

@unittest.skipUnless(os.getenv('ADGUARD_SYNC_BINARY') and shutil.which(os.getenv('ADGUARD_SYNC_BINARY','')), 'Official native binary is tested in the Docker job')
class NativeSyncTest(unittest.TestCase):
    def test_real_binary_copies_rules_and_reports_partial_outage(self):
        servers=[]
        for rules in [['||central.example.net^'],['||old-replica.example.net^']]:
            server=ThreadingHTTPServer(('127.0.0.1',0),AGH);server.rules=rules
            threading.Thread(target=server.serve_forever,daemon=True).start();servers.append(server)
        try:
            with tempfile.TemporaryDirectory() as folder:
                store=Store(folder);store.config['sources']=[]
                store.config['servers']=[{'id':str(i),'name':'Server '+str(i),'url':'http://127.0.0.1:'+str(s.server_port),'username':'test','password':'secret','enabled':True,'dns_host':'','dns_port':53} for i,s in enumerate(servers)]
                store.config['primary_id']='0';store.align_primary();store.config['cluster_sync']['enabled']=True
                store.config['cluster_sync']['features']={key:key=='filters' for key in store.config['cluster_sync']['features']}
                # A third, offline replica must not stop synchronization to the healthy one.
                store.config['servers'].append({'id':'offline','name':'Offline','url':'http://127.0.0.1:1','username':'test','password':'secret','enabled':True,'dns_host':'','dns_port':53})
                result=store.run_cluster()
                self.assertEqual(servers[1].rules,servers[0].rules,result)
                self.assertEqual(result['status']['results']['1']['state'],'success',result)
                self.assertEqual(result['status']['results']['offline']['state'],'error',result)
                self.assertEqual(result['status']['state'],'partial',result)
                self.assertFalse((Path(folder)/'adguard-sync-runtime.yaml').exists())
        finally:
            for s in servers:s.shutdown();s.server_close()
if __name__=='__main__':unittest.main(verbosity=2)
