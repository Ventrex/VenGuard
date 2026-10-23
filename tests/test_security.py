import copy
import json
import os
import socket
import tempfile
import threading
import time
import unittest
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from unittest.mock import patch
from server import Store,Handler
from security import BoundedHTTPServer

class Indexer(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_POST(self):
        self.server.path=self.path;self.server.body=json.loads(self.rfile.read(int(self.headers.get('Content-Length',0))))
        if self.headers.get('Authorization')!='Basic cmVhZGVyOnJlYWQtb25seS1zZWNyZXQ=':self.send_response(401);self.end_headers();return
        result={'hits':{'total':{'value':2},'hits':[{'_source':{'timestamp':'2026-10-23T08:00:00Z','rule':{'id':'5712','level':10,'description':'Repeated failed authentication','groups':['sshd']},'agent':{'id':'1','name':'test-host'},'data':{'srcip':'198.51.100.7'},'full_log':'must-not-leak'}},{'_source':{'timestamp':'2026-10-23T08:00:00Z','rule':{'id':'2','level':5,'description':'Another signal'},'agent':{'name':'other'},'data':{'srcip':'<script>alert(1)</script>'}}}]}}
        raw=json.dumps(result).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)

class SecurityTests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.store=Store(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def test_untrusted_forwarded_ip_is_ignored_and_trusted_chain_unwrapped(self):
        s=self.store
        self.assertEqual(s.security_ip('192.0.2.1','198.51.100.8'),'192.0.2.1')
        s.save_security({'trusted_proxies':['192.0.2.0/24','10.0.0.0/24']})
        self.assertEqual(s.security_ip('192.0.2.1','198.51.100.8, 10.0.0.2'),'198.51.100.8')
        self.assertEqual(s.security_ip('192.0.2.1','bad-header'),'192.0.2.1')
        self.assertEqual(s.security_ip('192.0.2.1','1.1.1.1, 198.51.100.8'),'198.51.100.8')
        with self.assertRaises(ValueError):s.save_security({'trusted_proxies':['0.0.0.0/0']})
        with self.assertRaises(ValueError):s.save_security({'trusted_proxies':['::/0']})
    def test_rate_limiter_and_event_memory_are_bounded(self):
        for i in range(120):self.assertTrue(self.store.request_allowed('192.0.2.2'))
        self.assertFalse(self.store.request_allowed('192.0.2.2'));self.assertTrue(self.store.request_allowed('192.0.2.3'))
        with patch('security.write_private'):
            for i in range(510):self.store.security_event('login_failed','192.0.2.2','Failed')
        self.assertEqual(len(self.store.security_events),500)
    def test_read_only_wazuh_search_redacts_secrets_and_raw_logs(self):
        api=ThreadingHTTPServer(('127.0.0.1',0),Indexer);threading.Thread(target=api.serve_forever,daemon=True).start()
        try:
            self.store.save_security({'wazuh':{'enabled':True,'url':'http://127.0.0.1:'+str(api.server_port),'username':'reader','password':'read-only-secret'}})
            self.assertTrue(self.store.poll_wazuh()['ok'])
            self.assertEqual(api.path,'/wazuh-alerts-*/_search');self.assertEqual(api.body['size'],100)
            state=self.store.security_snapshot();text=json.dumps(state);self.assertNotIn('read-only-secret',text);self.assertNotIn('must-not-leak',text)
            self.assertEqual(state['wazuh']['total'],2);self.assertEqual(state['wazuh']['alerts'][0]['source_ip'],'198.51.100.7');self.assertEqual(state['wazuh']['alerts'][1]['source_ip'],'')
            self.assertFalse(state['coverage']['firewall_enforcement']);self.assertFalse(state['coverage']['network_flows'])
            self.store.save_security({'wazuh':{'password':''}});self.assertEqual(self.store.security_config['wazuh']['password'],'read-only-secret')
            self.assertEqual((self.store.dir/'security.json').stat().st_mode&0o777,0o600)
        finally:api.shutdown();api.server_close()
    def test_wazuh_authentication_failure_is_not_success(self):
        api=ThreadingHTTPServer(('127.0.0.1',0),Indexer);threading.Thread(target=api.serve_forever,daemon=True).start()
        try:
            self.store.save_security({'wazuh':{'enabled':True,'url':'http://127.0.0.1:'+str(api.server_port),'username':'reader','password':'wrong'}})
            self.assertFalse(self.store.poll_wazuh()['ok']);self.assertIn('401',self.store.security_snapshot()['wazuh']['error'])
        finally:api.shutdown();api.server_close()
    def test_connection_concurrency_has_a_real_bound_and_recovers(self):
        server=BoundedHTTPServer(('127.0.0.1',0),Handler,max_workers=1);server.store=self.store;threading.Thread(target=server.serve_forever,daemon=True).start()
        first=socket.create_connection(('127.0.0.1',server.server_port));first.sendall(b'GET /health HTTP/1.1\r\n')
        try:
            deadline=time.time()+2
            while server.slots.acquire(blocking=False):
                server.slots.release()
                if time.time()>deadline:self.fail('Request did not enter worker')
                time.sleep(.01)
            second=socket.create_connection(('127.0.0.1',server.server_port));second.settimeout(2);second.sendall(b'GET /health HTTP/1.0\r\n\r\n')
            try:self.assertEqual(second.recv(1024),b'')
            except ConnectionResetError:pass
            finally:second.close()
            first.sendall(b'Host: localhost\r\n\r\n');first.settimeout(2);self.assertIn(b'200',first.recv(1024));first.close()
            deadline=time.time()+2
            while not server.slots.acquire(blocking=False):
                if time.time()>deadline:self.fail('Worker slot was not released')
                time.sleep(.01)
            server.slots.release()
        finally:first.close();server.shutdown();server.server_close()

class AccessHTTPTests(unittest.TestCase):
    def test_bruteforce_is_local_to_login_and_cannot_spoof_xff(self):
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,{'VENGUARD_PASSWORD':'test-only-password'}):
            store=Store(d);server=BoundedHTTPServer(('127.0.0.1',0),Handler);server.store=store;threading.Thread(target=server.serve_forever,daemon=True).start()
            base='http://127.0.0.1:'+str(server.server_port)
            try:
                for i in range(10):
                    req=urllib.request.Request(base+'/api/login',data=b'{"password":"wrong"}',headers={'X-VenGuard':'1','X-Forwarded-For':f'198.51.100.{i}'})
                    with self.assertRaises(urllib.error.HTTPError) as e:urllib.request.urlopen(req)
                    self.assertEqual(e.exception.code,401)
                req=urllib.request.Request(base+'/api/login',data=b'{"password":"wrong"}',headers={'X-VenGuard':'1','X-Forwarded-For':'8.8.8.8'})
                with self.assertRaises(urllib.error.HTTPError) as e:urllib.request.urlopen(req)
                self.assertEqual(e.exception.code,429)
                self.assertEqual({x['ip'] for x in store.security_events},{'127.0.0.1'})
                self.assertTrue(json.load(urllib.request.urlopen(base+'/health'))['ok'])
                with self.assertRaises(urllib.error.HTTPError) as e:urllib.request.urlopen(base+'/api/security')
                self.assertEqual(e.exception.code,401)
            finally:server.shutdown();server.server_close()

if __name__=='__main__':unittest.main()
