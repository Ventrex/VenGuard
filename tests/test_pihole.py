"""Pi-hole v6 HTTP contracts, mixed servers and token-protected subscriptions."""
import copy
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from unittest.mock import patch
from server import Store,Handler
from hub import HUB_DEFAULT
from providers import PiHole
from test_controls import AdGuard

class FTL(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):self.api()
    def do_POST(self):self.api()
    def do_PUT(self):self.api()
    def do_DELETE(self):self.api()
    def api(self):
        p=urllib.parse.urlsplit(self.path);path=urllib.parse.unquote(p.path.removeprefix('/api/'));query=urllib.parse.parse_qs(p.query)
        body=json.loads(self.rfile.read(int(self.headers.get('Content-Length',0))) or b'{}');s=self.server;s.calls.append((self.command,path,body))
        status=200;ctype='application/json'
        if path=='auth':
            s.auth_count+=1
            if body.get('password')!='test-app-password':status=401;value={'error':{'key':'unauthorized'}}
            else:s.sid='session-'+str(s.auth_count);value={'session':{'valid':True,'sid':s.sid,'csrf':'csrf-secret','validity':300}}
        elif self.headers.get('X-FTL-SID')!=s.sid:status=401;value={'error':{'key':'unauthorized'}}
        elif path=='dns/blocking':
            if self.command=='POST':s.blocking=body['blocking']
            value={'blocking':'enabled' if s.blocking else 'disabled','timer':None}
        elif path=='info/version':value={'version':{'ftl':{'local':{'version':'v6.test'}}}}
        elif path=='queries':value={'queries':[{'id':1,'time':1792742400,'type':'A','domain':'checkout.example.net','status':'GRAVITY','reply':{'type':'IP'},'client':{'ip':'192.0.2.83','name':'Test tablet'},'list_id':2}]}
        elif path=='action/gravity':
            for item in s.lists:
                if item['enabled']:
                    with urllib.request.urlopen(item['address'],timeout=3) as r:s.downloaded[item['type']]=r.read().decode()
                    item.update(date_updated=int(time.time()),status=1)
            s.gravity+=1;value=b'[i] gravity completed\n';ctype='text/plain'
        elif path=='lists':
            if self.command=='POST':s.lists.append({**body,'id':len(s.lists)+1,'type':query.get('type',['block'])[0]})
            value={'lists':copy.deepcopy(s.lists)}
        elif path.startswith('lists/'):
            address=path[6:];listtype=query['type'][0];item=next(x for x in s.lists if x['address']==address and x['type']==listtype)
            if self.command=='PUT':item.update(body)
            elif self.command=='DELETE':s.lists.remove(item)
            value={'lists':copy.deepcopy(s.lists)}
        elif path=='domains':value={'domains':copy.deepcopy(s.domains)}
        elif path.startswith('domains/'):
            parts=path.split('/',3);t,k=parts[1:3];domain=parts[3] if len(parts)>3 else body['domain'];item=next((x for x in s.domains if (x['type'],x['kind'],x['domain'])==(t,k,domain)),None)
            if self.command=='POST':s.domains.append({**body,'type':t,'kind':k})
            elif self.command=='PUT':item.update(body)
            elif self.command=='DELETE':s.domains.remove(item)
            value={'domains':copy.deepcopy(s.domains),'processed':{'success':[],'errors':[]}}
        elif path.startswith('search/'):value={'search':{'domains':copy.deepcopy(s.domains),'gravity':[]}}
        else:status=404;value={'error':{'key':'not_found'}}
        raw=value if isinstance(value,bytes) else json.dumps(value).encode()
        self.send_response(status);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)

def ftl_server():
    s=ThreadingHTTPServer(('127.0.0.1',0),FTL);s.calls=[];s.auth_count=0;s.sid='';s.blocking=True;s.lists=[];s.domains=[];s.gravity=0;s.downloaded={};threading.Thread(target=s.serve_forever,daemon=True).start();return s

class PiHoleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(self.tmp.name);self.ftl=ftl_server()
        self.pi={'id':'pi','type':'pihole','name':'Test Pi-hole','url':'http://127.0.0.1:'+str(self.ftl.server_port)+'/admin','password':'test-app-password','username':'','enabled':True,'dns_host':'','dns_port':53}
        self.store.config['servers']=[self.pi];self.store.config['primary_id']='pi';self.store.align_primary();self.store.config['sources']=[];self.store.config['auto_sync']=False
        self.web=ThreadingHTTPServer(('127.0.0.1',0),Handler);self.web.store=self.store;threading.Thread(target=self.web.serve_forever,daemon=True).start()
        self.store.config['public_url']='http://127.0.0.1:'+str(self.web.server_port)
    def tearDown(self):
        for s in (self.web,self.ftl):s.shutdown();s.server_close()
        self.tmp.cleanup()
    def test_session_reuse_401_renewal_and_secret_redaction(self):
        self.assertTrue(self.store.agh('status')['protection_enabled']);self.store.agh('filtering/status');self.assertEqual(self.ftl.auth_count,1)
        self.ftl.sid='expired';self.store.agh('status');self.assertEqual(self.ftl.auth_count,2)
        state=json.dumps(self.store.snapshot());self.assertNotIn('test-app-password',state);self.assertNotIn('csrf-secret',state);self.assertNotIn('session-2',state)
    def test_both_subscription_types_keep_subdomain_semantics_and_one_gravity(self):
        self.store.config['sources']=[{'id':'x','name':'Source','url':'https://example.org/list','enabled':True}]
        self.store.caches={'x':{'rules':['||ads.example.net^','@@||content.example.net^']}}
        self.store.rebuild(False);result=self.store.publish_all();self.assertTrue(result['ok'],result)
        self.assertEqual(self.ftl.gravity,1);self.assertIn('||ads.example.net^',self.ftl.downloaded['block']);self.assertIn('@@||content.example.net^',self.ftl.downloaded['allow'])
        self.assertNotIn('@@',self.ftl.downloaded['block']);self.assertEqual(len(self.ftl.lists),2)
        self.store.publish_all();self.assertEqual(len(self.ftl.lists),2)
    def test_gravity_without_verified_database_update_is_not_success(self):
        self.ftl.lists=[{'address':'https://example.org/list','type':'block','enabled':True,'status':0,'date_updated':0}]
        original=self.store.pihole.call
        def busy(server,path,*args,**kwargs):
            if path=='action/gravity':return {'ok':True,'server_time':time.time()}
            return original(server,path,*args,**kwargs)
        with patch.object(self.store.pihole,'call',side_effect=busy):
            with self.assertRaisesRegex(ValueError,'bevestigt'):self.store.pihole.refresh(self.pi)
    def test_slow_gravity_confirms_download_from_start_of_round(self):
        item={'address':'https://example.org/list','type':'block','enabled':True,'status':1,'date_updated':1005}
        def call(server,path,*args,**kwargs):return {'ok':True,'server_time':1020} if path=='action/gravity' else {'lists':[item]}
        with patch.object(self.store.pihole,'call',side_effect=call),patch('providers.time.monotonic',side_effect=[100,120]):
            self.assertEqual(self.store.pihole.refresh(self.pi)['verified'],1)
    def test_exact_live_rule_does_not_replace_foreign_rules_or_require_gravity(self):
        foreign={'domain':'keep.example.net','type':'allow','kind':'exact','comment':'Existing user rule','enabled':True,'groups':[2]};self.ftl.domains=[copy.deepcopy(foreign)]
        self.store.config['rules']=[{'domain':'checkout.example.net','action':'allow','match':'exact','enabled':True}]
        result=self.store.apply_live_rules();self.assertTrue(result['ok'],result);self.assertEqual(self.ftl.gravity,0);self.assertIn(foreign,self.ftl.domains)
        managed=[r for r in self.ftl.domains if r['comment']=='VenGuard managed rule'];self.assertEqual(managed[0]['kind'],'exact')
        self.store.config['rules']=[];self.store.apply_live_rules();self.assertEqual(self.ftl.domains,[foreign])
    def test_single_blocking_switch_log_normalization_and_unsupported_editor(self):
        result=self.store.set_controls('protection',False);self.assertTrue(result['ok']);self.assertFalse(self.ftl.blocking)
        self.assertTrue(self.store.set_controls('protection',True)['ok']);self.store.poll();row=self.store.last_log[0]
        self.assertEqual(row['reason'],'FilteredBlackList');self.assertEqual(row['client'],'192.0.2.83');self.assertEqual(row['server_id'],'pi')
        with self.assertRaises(ValueError):self.store.central_read('dns')
        with self.assertRaises(ValueError):self.store.set_controls('filtering',False)
    def test_preserve_existing_groups_when_disabling_list(self):
        self.ftl.lists=[{'id':1,'address':'https://example.org/list.txt','type':'block','comment':'Own list','enabled':True,'groups':[2]}]
        self.store.agh('filtering/set_url',{'url':self.ftl.lists[0]['address'],'data':{'enabled':False},'whitelist':False})
        self.assertEqual(self.ftl.lists[0]['groups'],[2]);self.assertEqual(self.ftl.lists[0]['comment'],'Own list');self.assertFalse(self.ftl.lists[0]['enabled'])
    def test_mixed_protection_and_native_sync_never_posts_adguard_settings_to_pihole(self):
        agh=ThreadingHTTPServer(('127.0.0.1',0),AdGuard);agh.protection=True;agh.filtering=True;agh.filters=[];threading.Thread(target=agh.serve_forever,daemon=True).start()
        try:
            self.store.config['servers'].append({'id':'agh','name':'AdGuard','type':'adguard','url':'http://127.0.0.1:'+str(agh.server_port),'username':'','password':'','enabled':True})
            self.store.config['cluster_sync']['enabled']=True;result=self.store.set_controls('protection',False)
            self.assertTrue(result['ok'],result);self.assertFalse(self.ftl.blocking);self.assertFalse(agh.protection)
            self.store.run_cluster();self.assertFalse(any(path.startswith('control/') for method,path,body in self.ftl.calls))
        finally:agh.shutdown();agh.server_close()

if __name__=='__main__':unittest.main()
