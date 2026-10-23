import copy
import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from rules import domain,parse_list,scope,compose,explain,rule_text
from server import Store,Handler,DEFAULT,utc,download

class DomainTests(unittest.TestCase):
    def test_normalize_idn(self):
        self.assertEqual(domain('  Méét.Example.NL. '),'xn--mt-bjaa.example.nl')
    def test_reject_wide_or_injected_patterns(self):
        for v in ['https://example.nl/a','*.example.nl','example.nl/path','com','127.0.0.1','example.nl$important','a..nl','example.nl:80','x\nfoo.nl','-bad.nl']:
            with self.subTest(v=v),self.assertRaises(ValueError):domain(v)
    def test_scope(self):
        self.assertEqual(scope('192.168.0.83'),'192.168.0.83')
        self.assertEqual(scope('192.168.0.83/24'),'192.168.0.0/24')
        self.assertEqual(scope('2001:db8::1'),'2001:db8::1')
        for v in ['everyone','a|b','192.0.2.1$important']:
            with self.assertRaises(ValueError):scope(v)
    def test_conservative_parser(self):
        text='''! header
[Adblock Plus 2.0]
||advert.example.nl^
@@||login.example.nl^
0.0.0.0 one.example.net two.example.net # comment
127.0.0.1 localhost
plain.example.net
||advert.example.nl^
example.org##.ad
||example.net/advert.js
||example.net^$third-party
@@||broad.example^$domain=narrow.example
https://example.org/file
/regex/
@@||path.example/ad
'''
        rules,counts,examples=parse_list(text)
        self.assertEqual(set(rules),{'||advert.example.nl^','@@||login.example.nl^','||one.example.net^','||two.example.net^','||plain.example.net^'})
        self.assertEqual(counts['skipped'],8)
        self.assertLessEqual(len(examples),5)
        self.assertNotIn('||example.net^',rules)
    def test_unknown_stays_unknown(self):
        self.assertFalse(explain('arbitrary.example.net')['known'])
        self.assertIsNone(explain('login.dpgmedia.net')['pack'])
        self.assertEqual(explain('some.amazonaws.com')['category'],'Niet geclassificeerd')
        self.assertFalse(explain('notamazonaws.com')['known'])
    def test_scoped_allow_rule(self):
        self.assertEqual(rule_text({'action':'allow','domain':'ads.example.net','client':'192.0.2.83'}),'@@||ads.example.net^$client=192.0.2.83')

class ComposeTests(unittest.TestCase):
    def setUp(self):
        self.c=copy.deepcopy(DEFAULT);self.c['packs']={};self.c['sources']=[{'id':'a','url':'https://example.org/a','name':'A','enabled':True},{'id':'b','url':'https://example.org/b','name':'B','enabled':True}]
        self.cache={'a':{'rules':['||example.net^','||unused.example.org^','@@||login.example.net^']},'b':{'rules':['||example.net^']}}
    def test_dedup_and_exception(self):
        lines,stats,_=compose(self.c,self.cache,{})
        self.assertEqual(lines.count('||example.net^'),1)
        self.assertIn('@@||login.example.net^',lines)
    def test_observed_parent_match_and_exceptions(self):
        self.c['mode']='observed'
        lines,_,_=compose(self.c,self.cache,{'sub.example.net':1})
        self.assertIn('||example.net^',lines)
        self.assertIn('@@||login.example.net^',lines)
        self.assertNotIn('||unused.example.org^',lines)
    def test_own_rule_survives_compact_mode(self):
        self.c['mode']='observed';self.c['rules']=[{'action':'block','domain':'manual.example.nl','enabled':True}]
        lines,_,_=compose(self.c,self.cache,{})
        self.assertIn('||manual.example.nl^',lines)
    def test_disabled_source(self):
        self.c['sources'][0]['enabled']=False;self.c['sources'][1]['enabled']=False
        self.assertEqual(compose(self.c,self.cache,{})[0],[])
    def test_direct_rules_do_not_leak_into_downloaded_subscription(self):
        self.c['direct_rules']=True;self.c['rules']=[{'domain':'payment.example.net','action':'allow','enabled':True}]
        lines,_,_=compose(self.c,self.cache,{})
        self.assertNotIn('@@||payment.example.net^',lines)
        self.assertIn('||example.net^',lines)

class MockAGH(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):self.handle_api()
    def do_POST(self):self.handle_api()
    def handle_api(self):
        self.server.calls.append((self.command,self.path))
        path=urllib.parse.urlsplit(self.path).path
        body=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))) or b'{}')
        if self.headers.get('Authorization')!='Basic dGVzdDpzZWNyZXQ=':
            self.send_response(401);self.end_headers();return
        if path=='/control/status': value={'version':'v0.107.test','protection_enabled':True}
        elif path=='/control/filtering/status': value={'enabled':True,'filters':self.server.filters,'user_rules':getattr(self.server,'user_rules',['@@||keep-existing.example.net^'])}
        elif path=='/control/querylog': value={'data':[{'time':utc(),'client':'192.0.2.83','question':{'name':'advertising-module.api.dpgmedia.cloud','type':'A'},'reason':'NotFilteredNotFound','status':'NOERROR','rules':[]},{'time':utc(),'client':'192.0.2.83','question':{'name':'tracker.example.net','type':'AAAA'},'reason':'FilteredBlackList','status':'NOERROR','rules':[{'text':'||tracker.example.net^','filter_list_id':1}]}]}
        elif path=='/control/clients':value={'clients':[]}
        elif path=='/control/filtering/check_host':
            self.server.last_check=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            value={'reason':'FilteredBlackList','rules':[{'text':'||tracker.example.net^','filter_list_id':42}]}
        elif path=='/control/filtering/set_rules':self.server.user_rules=body['rules'];value={}
        elif path=='/control/filtering/add_url':
            # A real callback from AdGuard to verify the list URL can be fetched without UI auth.
            with urllib.request.urlopen(body['url'],timeout=2) as r:self.server.downloaded=r.read().decode()
            self.server.filters.append({'id':42,'enabled':True,**body});value={}
        elif path=='/control/filtering/set_url':
            for f in self.server.filters:
                if f['url']==body['url']:f.update(body['data'])
            value={}
        elif path=='/control/filtering/refresh':value={'updated':1}
        else:self.send_response(404);self.end_headers();return
        raw=json.dumps(value).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)

class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env=patch.dict(os.environ,{'VENGUARD_PASSWORD':'test-admin-password'});cls.env.start()
        cls.tmp=tempfile.TemporaryDirectory();cls.s=Store(cls.tmp.name)
        cls.s.config['sources']=[];cls.s.rebuild(False)
        cls.web=ThreadingHTTPServer(('127.0.0.1',0),Handler);cls.web.store=cls.s
        cls.agh=ThreadingHTTPServer(('127.0.0.1',0),MockAGH);cls.agh.filters=[];cls.agh.calls=[]
        for server in [cls.web,cls.agh]:threading.Thread(target=server.serve_forever,daemon=True).start()
        cls.base='http://127.0.0.1:'+str(cls.web.server_port)
        cls.s.config['public_url']=cls.base
        cls.s.config['adguard']={'url':'http://127.0.0.1:'+str(cls.agh.server_port),'username':'test','password':'secret'}
        cls.s.save()
        cls.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
        cls.call('login',{'password':'test-admin-password'})
    @classmethod
    def tearDownClass(cls):
        cls.web.shutdown();cls.agh.shutdown();cls.web.server_close();cls.agh.server_close();cls.tmp.cleanup();cls.env.stop()
    @classmethod
    def call(cls,path,body=None,headers=None,opener=None):
        hdr={'X-VenGuard':'1'}
        if body is not None:hdr['Content-Type']='application/json'
        hdr.update(headers or {})
        req=urllib.request.Request(cls.base+'/api/'+path,data=None if body is None else json.dumps(body).encode(),headers=hdr)
        with (opener or cls.opener).open(req,timeout=3) as r:return json.load(r)
    def test_no_credentials_in_state_or_export(self):
        state=self.call('state');export=self.call('export')
        self.assertNotIn('password',state['config']['adguard'])
        self.assertTrue(state['config']['adguard']['password_set'])
        self.assertEqual(export['adguard']['password'],'')
        self.assertNotIn(self.s.feed_token,json.dumps(export))
    def test_unauthenticated_api_refused(self):
        with self.assertRaises(urllib.error.HTTPError) as e:self.call('state',opener=urllib.request.build_opener())
        self.assertEqual(e.exception.code,401)
    def test_csrf_refused(self):
        with self.assertRaises(urllib.error.HTTPError) as e:self.call('build',{},headers={'Origin':'http://evil.example'})
        self.assertEqual(e.exception.code,403)
    def test_valid_api_and_real_callback_sync(self):
        self.assertTrue(self.call('test-connection',{})['ok'])
        first=self.call('sync',{});second=self.call('sync',{})
        self.assertTrue(first['ok']);self.assertEqual(first['url'],second['url'])
        self.assertEqual(sum(x['url']==first['url'] for x in self.agh.filters),1)
        self.assertIn('VenGuard Custom DNS',self.agh.downloaded)
        self.assertIn('@@||keep-existing.example.net^',getattr(self.agh,'user_rules',['@@||keep-existing.example.net^']))
    def test_log_and_adguard_client_check(self):
        self.call('poll',{})
        result=self.call('log?status=allowed&client=192.0.2.83')
        self.assertEqual(len(result['data']),1)
        self.assertEqual(result['data'][0]['classification']['category'],'Mogelijke advertenties')
        checked=self.call('check?domain=tracker.example.net&client=192.0.2.83&type=AAAA')
        self.assertEqual(checked['adguard']['reason'],'FilteredBlackList')
        self.assertEqual(self.agh.last_check['client'],['192.0.2.83'])
        self.assertEqual(self.agh.last_check['qtype'],['AAAA'])
    def test_add_scoped_rule_persistence_and_rebuild(self):
        result=self.call('rules',{'action':'block','domain':'manual.example.net','client':'192.0.2.83','match':'suffix','note':'Test'});self.assertTrue(result['applied']['ok'])
        self.s.rebuild(False)
        self.assertIn('||manual.example.net^$client=192.0.2.83',self.agh.user_rules)
        self.assertNotIn('manual.example.net',(self.s.dir/'filter.txt').read_text())
        self.call('rules',{'action':'allow','domain':'manual.example.net','client':'192.0.2.83','match':'suffix'})
        self.s.rebuild(False)
        self.assertIn('@@||manual.example.net^$client=192.0.2.83',self.agh.user_rules)
        same=Store(self.tmp.name)
        self.assertEqual(len([r for r in same.config['rules'] if r['domain']=='manual.example.net']),1)
    def test_unchanged_build_does_not_repeat_remote_refresh(self):
        self.s.last_synced_revision=-1
        with patch.object(self.s,'sync',wraps=self.s.sync) as spy:
            self.s.rebuild(False)
            first=(self.s.dir/'filter.txt').read_text()
            self.s.rebuild(False)
            self.assertEqual(spy.call_count,1)
            self.assertEqual((self.s.dir/'filter.txt').read_text(),first)
            self.s.revision+=1
            self.s.rebuild(False)
            self.assertEqual(spy.call_count,2)
    def test_wrong_token_and_traversal_refused(self):
        for path in ['/lists/not-the-token/filter.txt','/../config.json','/config.json']:
            with self.subTest(path=path),self.assertRaises(urllib.error.HTTPError):urllib.request.urlopen(self.base+path)
    def test_password_retained_on_empty_update(self):
        self.call('settings',{'adguard':{'url':self.s.config['adguard']['url'],'username':'test','password':''}})
        self.assertEqual(self.s.config['adguard']['password'],'secret')
    def test_failed_source_fetch_keeps_last_good_cache(self):
        old=copy.deepcopy(self.s.config['sources']);oldcache=copy.deepcopy(self.s.caches)
        self.s.config['sources']=[{'id':'test','name':'Cached','url':'https://example.org/filter.txt','enabled':True}]
        self.s.caches={'test':{'rules':['||old.example.net^'],'fetched':utc()}}
        with patch('server.download',side_effect=TimeoutError()):self.s.rebuild(True)
        self.assertIn('||old.example.net^',(self.s.dir/'filter.txt').read_text())
        self.assertTrue(self.s.report['sources'][0]['cached_fallback'])
        self.s.config['sources']=old;self.s.caches=oldcache
    def test_shrinking_source_keeps_published_rules(self):
        old=copy.deepcopy(self.s.config['sources']);oldcache=copy.deepcopy(self.s.caches);publication=(self.s.dir/'filter.txt').read_text()
        try:
            self.s.config['sources']=[{'id':'guard','name':'Guard','url':'https://example.org/filter.txt','enabled':True}]
            rules=['||ad'+str(i)+'.example.net^' for i in range(1200)]
            self.s.caches={'guard':{'rules':rules,'fetched':utc()}};self.s.rebuild(False)
            with patch('server.download',return_value='||one.example.net^'):self.s.rebuild(True)
            self.assertEqual(self.s.report['count'],1200)
            self.assertIn('80%',self.s.caches['guard']['error'])
            self.s.caches={}
            with self.assertRaises(ValueError):self.s.rebuild(False)
            self.assertIn('||ad1199.example.net^',(self.s.dir/'filter.txt').read_text())
        finally:
            self.s.config['sources']=old;self.s.caches=oldcache;(self.s.dir/'filter.txt').write_text(publication);self.s.rebuild(False)
    def test_health_test_name_hidden_without_deleting_original_log(self):
        original=copy.deepcopy(self.s.last_log)
        try:
            self.s.last_log=[{'question':{'name':'example.org.'},'reason':'NotFilteredNotFound','status':'NOERROR'}, {'question':{'name':'content.example.net'},'reason':'NotFilteredNotFound','status':'NOERROR'}]
            hidden=self.call('log');self.assertEqual(hidden['hidden_tests'],1);self.assertEqual(len(hidden['data']),1)
            shown=self.call('log?tests=1');self.assertEqual(len(shown['data']),2);self.assertEqual(len(self.s.last_log),2)
        finally:self.s.last_log=original
    def test_import_only_enabled_sources_and_preserve_custom_rules(self):
        original=copy.deepcopy(self.agh.filters)
        self.agh.filters.extend([{'id':1,'name':'Enabled','url':'https://example.org/one.txt','enabled':True},{'id':2,'name':'Disabled','url':'https://example.org/two.txt','enabled':False}])
        with patch('server.valid_url',side_effect=lambda u,public=False:u):result=self.call('import-sources',{})
        self.assertEqual(result['added'],1)
        self.assertTrue(any(s['url']=='https://example.org/one.txt' for s in self.s.config['sources']))
        self.assertFalse(any(s['url']=='https://example.org/two.txt' for s in self.s.config['sources']))
        self.agh.filters=original
    def test_private_source_disallowed(self):
        with self.assertRaises(urllib.error.HTTPError) as e:self.call('sources',{'url':'https://127.0.0.1/filter.txt'})
        self.assertIn('publiek',json.load(e.exception)['error'])
    def test_failed_build_does_not_publish_stale_snapshot(self):
        # Simulate settings changing during a download. Old snapshot must not win.
        old=copy.deepcopy(self.s.config['sources']);self.s.config['sources']=[{'id':'stale','name':'Stale','url':'https://example.org/stale.txt','enabled':True}]
        before=(self.s.dir/'filter.txt').read_text()
        def mutate(_):
            with self.s.lock:self.s.revision+=1
            return '||stale.example.net^'
        with patch('server.download',side_effect=mutate):self.s.rebuild(True)
        self.assertEqual((self.s.dir/'filter.txt').read_text(),before)
        self.s.config['sources']=old

if __name__=='__main__':unittest.main()
