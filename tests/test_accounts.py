import copy
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from accounts import totp,code_step,password_hash,password_matches
from server import Store,Handler

class AccountTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.env=patch.dict(os.environ,{'VENGUARD_PASSWORD':'bootstrap-only'});self.env.start()
        self.store=Store(self.temp.name)
    def tearDown(self):self.temp.cleanup();self.env.stop()
    def create(self):return self.store.account_action({'action':'save','username':'eigenaar','password':'mijn-lange-wachtwoord','current_password':'bootstrap-only'},'session')
    def test_rfc6238_sha1_vectors_and_window(self):
        secret='GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
        for timestamp,expected in [(59,'94287082'),(1111111109,'07081804'),(1111111111,'14050471'),(1234567890,'89005924'),(2000000000,'69279037'),(20000000000,'65353130')]:
            self.assertEqual(totp(secret,timestamp//30,8),expected)
        self.assertEqual(code_step(secret,totp(secret,100),3001),100)
        self.assertIsNone(code_step(secret,totp(secret,97),3001))
    def test_password_hash_salt_and_rejection(self):
        a=password_hash('long-enough-password');b=password_hash('long-enough-password')
        self.assertNotEqual(a,b);self.assertTrue(password_matches('long-enough-password',a));self.assertFalse(password_matches('wrong',a))
    def test_account_disables_bootstrap_persists_and_redacts(self):
        self.store.sessions['old']=time.time()+100;self.create();self.assertFalse(self.store.sessions)
        self.assertFalse(self.store.login_owner({'password':'bootstrap-only'}))
        self.assertTrue(self.store.login_owner({'username':'eigenaar','password':'mijn-lange-wachtwoord'}))
        self.assertFalse(self.store.login_owner({'username':'wrong','password':'mijn-lange-wachtwoord'}))
        self.assertNotIn('mijn-lange',json.dumps(self.store.account))
        self.assertNotIn('password',json.dumps(self.store.account_public()))
        self.assertEqual(Store(self.temp.name).account['username'],'eigenaar')
        self.assertEqual((Path(self.temp.name)/'account.json').stat().st_mode&0o777,0o600)
    def test_enrollment_confirmation_replay_recovery_and_disable(self):
        self.create();setup=self.store.account_action({'action':'setup','current_password':'mijn-lange-wachtwoord'},'s')
        with self.assertRaises(ValueError):self.store.account_action({'action':'confirm','code':'000000'},'other-session')
        code=totp(setup['secret'],int(time.time()//30))
        result=self.store.account_action({'action':'confirm','code':code},'s');self.assertEqual(len(result['recovery_codes']),10)
        self.assertFalse(self.store.verify_owner('mijn-lange-wachtwoord',code))
        recovery=result['recovery_codes'][0]
        self.assertTrue(self.store.verify_owner('mijn-lange-wachtwoord',recovery));self.assertFalse(self.store.verify_owner('mijn-lange-wachtwoord',recovery))
        self.store.account_action({'action':'disable','current_password':'mijn-lange-wachtwoord','code':result['recovery_codes'][1]},'s')
        self.assertFalse(self.store.account_public()['two_factor'])
    def test_sensitive_actions_throttled(self):
        for i in range(10):
            with self.assertRaises(ValueError):self.store.account_action({'current_password':'bad'},'s')
        with self.assertRaisesRegex(ValueError,'Te veel'):self.store.account_action({'current_password':'bootstrap-only'},'s')
    def test_unicode_username_and_password(self):
        self.store.account_action({'action':'save','username':'beheerder_é','password':'lang-één-wachtwoord','current_password':'bootstrap-only'},'s')
        self.assertTrue(self.store.login_owner({'username':'beheerder_é','password':'lang-één-wachtwoord'}))
        self.assertIsNone(code_step('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ','１２３４５６'))
    def test_pending_setup_expires(self):
        self.create();self.store.account_action({'action':'setup','current_password':'mijn-lange-wachtwoord'},'s')
        self.store.pending_totp['s']['expires']=0
        with self.assertRaisesRegex(ValueError,'verlopen'):self.store.account_action({'action':'confirm','code':'123456'},'s')

class AccountHTTPTests(unittest.TestCase):
    def test_owner_enrollment_requires_session_and_old_sessions_expire(self):
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,{'VENGUARD_PASSWORD':'bootstrap-only'}):
            store=Store(d);server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.store=store
            threading.Thread(target=server.serve_forever,daemon=True).start()
            base='http://127.0.0.1:'+str(server.server_port)+'/api/'
            opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
            def call(path,body=None):
                req=urllib.request.Request(base+path,data=json.dumps(body).encode() if body is not None else None,headers={'X-VenGuard':'1','Content-Type':'application/json'})
                with opener.open(req) as response:return json.load(response)
            try:
                data={'action':'save','username':'owner','password':'strong-new-password','current_password':'bootstrap-only'}
                with self.assertRaises(urllib.error.HTTPError) as e:call('account',data)
                self.assertEqual(e.exception.code,401)
                call('login',{'password':'bootstrap-only'});call('account',data)
                self.assertFalse(call('session')['authenticated'])
                with self.assertRaises(urllib.error.HTTPError):call('login',{'password':'bootstrap-only'})
                call('login',{'username':'owner','password':'strong-new-password'})
                self.assertEqual(call('account')['username'],'owner')
                setup=call('account',{'action':'setup','current_password':'strong-new-password'})
                result=call('account',{'action':'confirm','code':totp(setup['secret'],int(time.time()//30))})
                with self.assertRaises(urllib.error.HTTPError):call('login',{'username':'owner','password':'strong-new-password'})
                call('login',{'username':'owner','password':'strong-new-password','code':result['recovery_codes'][0]})
                self.assertTrue(call('session')['authenticated'])
            finally:server.shutdown();server.server_close()

if __name__=='__main__':unittest.main()
