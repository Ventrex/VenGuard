"""Regression coverage for real AdGuard response formats and filter controls."""
import copy
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from server import Store,Handler
from rules import compose
from test_hub import FakeStore,SERVERS

class AdGuard(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):self.handle_api()
    def do_POST(self):self.handle_api()
    def handle_api(self):
        path=self.path.split('?')[0];body=json.loads(self.rfile.read(int(self.headers.get('Content-Length',0))) or b'{}');s=self.server
        content='application/json'
        if path=='/control/status':out={'protection_enabled':s.protection,'version':'v0.107.test'}
        elif path=='/control/filtering/status':out={'enabled':s.filtering,'interval':24,'filters':s.filters,'user_rules':getattr(s,'user_rules',[])}
        elif path=='/control/protection':
            if self.command=='POST':s.protection=body['enabled']
            out=b'OK\n';content='text/plain'
        elif path=='/control/filtering/set_rules':s.user_rules=body['rules'];out=b'OK'
        elif path=='/control/filtering/add_url':s.filters.append({'id':42,'enabled':True,**body});out={}
        elif path=='/control/filtering/config':s.filtering=body['enabled'];out=b'OK'
        elif path=='/control/filtering/set_url':
            for f in s.filters:
                if f['url']==body['url']:f.update(body['data'])
            out=b'OK'
        elif path=='/control/filtering/refresh':out={'updated':len(s.filters)}
        elif path=='/control/not-json':out=b'<html>Login</html>';content='text/html'
        else:out={}
        raw=out if isinstance(out,bytes) else json.dumps(out).encode()
        self.send_response(200);self.send_header('Content-Type',content);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)

class ControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.env=patch.dict(os.environ,{'VENGUARD_PASSWORD':'test-only'});self.env.start();self.store=Store(self.tmp.name)
        self.agh=ThreadingHTTPServer(('127.0.0.1',0),AdGuard);self.agh.protection=False;self.agh.filtering=False;self.agh.filters=[{'name':'Existing','url':'https://example.org/list.txt','enabled':True}]
        self.store.config['adguard']={'url':'http://127.0.0.1:'+str(self.agh.server_port),'username':'','password':''}
        self.web=ThreadingHTTPServer(('127.0.0.1',0),Handler);self.web.store=self.store
        for server in (self.agh,self.web):threading.Thread(target=server.serve_forever,daemon=True).start()
        self.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor());self.call('login',{'password':'test-only'})
    def tearDown(self):
        for server in (self.web,self.agh):server.shutdown();server.server_close()
        self.tmp.cleanup();self.env.stop()
    def call(self,path,body=None):
        req=urllib.request.Request('http://127.0.0.1:'+str(self.web.server_port)+'/api/'+path,data=json.dumps(body).encode() if body is not None else None,headers={'X-VenGuard':'1','Content-Type':'application/json'})
        with self.opener.open(req,timeout=5) as r:return json.load(r)
    def test_plain_ok_actions_and_status_readback(self):
        r=self.call('central-protection',{'enabled':True});self.assertTrue(r['ok'])
        health=r['hub']['servers'][0]['health'];self.assertTrue(health['protection_enabled']);self.assertFalse(self.call('central-controls')['filtering_enabled'])
        r=self.call('central-filtering',{'enabled':True});self.assertTrue(r['hub']['servers'][0]['health']['filtering_enabled'])
        self.call('central-protection',{'enabled':False});self.assertFalse(self.agh.protection)
    def test_html_is_never_success_even_for_actions(self):
        for body in (None,{}):
            with self.assertRaisesRegex(ValueError,'geen JSON'):self.store.agh('not-json',body)
    def test_plain_ok_read_is_not_valid_json(self):
        # This endpoint mutates only in the mock; GET must still reject its plaintext response.
        with self.assertRaises(ValueError):self.store.agh('protection',query={'ignored':1})
    def test_manage_existing_filter_and_preserve_others(self):
        self.call('central-filters',{'action':'toggle','url':self.agh.filters[0]['url'],'enabled':False})
        self.assertFalse(self.call('central-filters')['filters'][0]['enabled'])
        with self.assertRaises(urllib.error.HTTPError):self.call('central-filters',{'action':'toggle','url':'https://unknown.example/list','enabled':False})
        self.assertEqual(len(self.agh.filters),1)
    def test_category_edit_toggle_and_optional_exceptions(self):
        with patch('server.valid_url',return_value='https://example.org/list'):
            self.call('sources',{'action':'add','name':'Extra','url':'https://example.org/list','category':'adult'})
        sid=self.store.config['sources'][-1]['id'];self.store.caches[sid]={'rules':['||adult.example.net^']}
        self.call('settings',{'categories':{'adult':False}});self.store.rebuild(False)
        self.assertNotIn('||adult.example.net^',(self.store.dir/'filter.txt').read_text())
        self.call('sources',{'action':'category','id':sid,'category':'custom'});self.store.rebuild(False)
        self.assertIn('||adult.example.net^',(self.store.dir/'filter.txt').read_text())
        self.assertNotIn('compatibility',self.call('state'))


class HealthRegressionTests(unittest.TestCase):
    def test_three_failed_checks_and_recovery(self):
        with tempfile.TemporaryDirectory() as d:
            s=FakeStore(d);s.config['servers']=copy.deepcopy(SERVERS);s.config['primary_id']='one';s.offline=set();s.calls=[]
            with patch('hub.dns_probe',return_value={'ok':True,'error':'','ms':1}):s.monitor()
            good=s.health['one']['last_success'];s.offline={'one'}
            with patch('hub.dns_probe',return_value={'ok':True,'error':'','ms':1}):
                s.monitor();self.assertEqual(s.health['one']['state'],'checking');self.assertEqual(s.health['one']['last_success'],good)
                s.monitor();self.assertEqual(s.health['one']['state'],'checking')
                s.monitor();self.assertEqual(s.health['one']['state'],'down')
                s.offline=set();s.monitor();self.assertEqual(s.health['one']['state'],'up');self.assertEqual(s.health['one']['failures'],0)
    def test_duplicates_are_exact_even_with_extra_packs_and_allows(self):
        cfg={'mode':'all','sources':[{'id':'a','enabled':True},{'id':'b','enabled':True}], 'packs':{},'rules':[]}
        cache={'a':{'rules':['||ads.example.net^','@@||allowed.example.net^']},'b':{'rules':['||ads.example.net^']}}
        lines,stats,_=compose(cfg,cache,{})
        self.assertEqual(sum(s['duplicates'] for s in stats),1);self.assertEqual(lines.count('||ads.example.net^'),1)

if __name__=='__main__':unittest.main()
