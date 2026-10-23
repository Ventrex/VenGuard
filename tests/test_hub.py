import copy
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from server import Store
from hub import HUB_DEFAULT,native_config,parse_sync_results,dns_probe,digest

SERVERS=[{'id':'one','name':'NUC','url':'http://192.0.2.10:3000','username':'admin','password':'one-secret','enabled':True,'dns_host':'192.0.2.10','dns_port':53},{'id':'two','name':'Zima','url':'http://192.0.2.11:3000','username':'admin','password':'two-secret','enabled':True,'dns_host':'192.0.2.11','dns_port':53}]
class FakeStore(Store):
    def agh(self,path,body=None,query=None,settings=None,method=None):
        s=settings or self.config['adguard'];sid=s.get('id','one')
        self.calls.append((sid,path,copy.deepcopy(body),method))
        if sid in self.offline:raise urllib.error.URLError('unavailable')
        if path=='status':return {'version':'v0.107.79','protection_enabled':True}
        if path=='filtering/status':return {'enabled':True,'interval':24,'filters':[],'user_rules':self.user_rules[sid]}
        if path=='querylog':return {'data':[{'time':'2026-10-23T07:00:00Z','client':'192.0.2.83','question':{'name':sid+'.example.net','type':'A'},'reason':'NotFilteredNotFound','status':'NOERROR'}]}
        if path=='dns_info':return {'upstream_dns':['https://dns.example.net/dns-query'],'bind_hosts':['0.0.0.0'],'port':53}
        if path=='clients':return {'clients':[]}
        if path=='rewrite/list':return []
        if path=='filtering/set_rules':self.user_rules[sid]=body['rules']
        return {}
class HubTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=FakeStore(self.tmp.name)
        self.store.calls=[];self.store.offline=set();self.store.user_rules={'one':['||original.example.net^'],'two':['@@||replica.example.net^']}
        self.store.config['servers']=copy.deepcopy(SERVERS);self.store.config['primary_id']='one';self.store.align_primary();self.store.config['public_url']='http://192.0.2.20:8098'
    def tearDown(self):self.tmp.cleanup()
    def test_rule_counts_survive_a_management_outage(self):
        self.store.health['one']={'active_lists':4,'active_filters':3,'server_filter_rules':600000,'native_rules':2,'filter_counts_at':'last-good','last_success':'last-good'}
        self.store.offline={'one'}
        self.store.monitor(include_dns=False)
        health=self.store.health['one'];self.assertFalse(health['api_ok']);self.assertEqual(health['server_filter_rules'],600000);self.assertEqual(health['filter_counts_at'],'last-good')
    def test_partial_feed_does_not_skip_healthy_server(self):
        self.store.offline={'one'};result=self.store.publish_all()
        self.assertFalse(result['ok']);self.assertTrue(result['results']['two']['ok'])
        self.assertEqual(self.store.user_rules['two'],['@@||replica.example.net^'])
        self.assertEqual(self.store.config['primary_id'],'one')
    def test_aggregate_logs_survive_one_offline(self):
        self.store.poll();self.store.offline={'one'};rows=self.store.poll()
        self.assertEqual({r['server_id'] for r in rows},{'one','two'})
        self.assertTrue(self.store.poll_error)
        self.assertTrue(any(r['server_name']=='Zima' for r in rows))
    def test_health_api_and_dns_separate(self):
        self.store.offline={'one'}
        with patch('hub.dns_probe',return_value={'ok':True,'error':'','ms':1.2}):self.store.monitor()
        h=self.store.hub_snapshot()['servers'][0]['health']
        self.assertFalse(h['api_ok']);self.assertTrue(h['dns']['ok'])
        self.store.health['one']['checked_epoch']=0
        self.assertTrue(self.store.hub_snapshot()['servers'][0]['health']['stale'])
    def test_no_passwords_in_dashboard(self):
        self.store.save();data=json.dumps(self.store.snapshot())
        self.assertNotIn('one-secret',data);self.assertNotIn('two-secret',data)
    def test_safe_native_config(self):
        c=native_config(SERVERS,'one',copy.deepcopy(HUB_DEFAULT))
        self.assertEqual(c['api']['port'],0)
        self.assertFalse(c['origin']['autoSetup']);self.assertFalse(c['replicas'][0]['insecureSkipVerify'])
        self.assertFalse(c['features']['dhcp']['serverConfig']);self.assertFalse(c['features']['tlsConfig'])
        self.assertTrue(c['continueOnError']);self.assertEqual(c['origin']['password'],'one-secret')
    def test_parser_requires_real_completion_per_replica(self):
        lines=[json.dumps({'level':'info','msg':'Connected to replica','to':'192.0.2.11:3000'})]
        self.assertEqual(parse_sync_results(lines,SERVERS,'one')['two']['state'],'error')
        lines.append(json.dumps({'level':'INFO','msg':'Sync done','to':'192.0.2.11:3000'}))
        self.assertEqual(parse_sync_results(lines,SERVERS,'one')['two']['state'],'success')
        lines.append(json.dumps({'level':'error','msg':'Sync done','to':'192.0.2.11:3000'}))
        self.assertEqual(parse_sync_results(lines,SERVERS,'one')['two']['state'],'error')
    def test_offline_origin_never_promoted_and_no_fake_success(self):
        self.store.config['cluster_sync']['enabled']=True;self.store.offline={'one'}
        with patch('hub.shutil.which',return_value='/not-executed'),patch('hub.subprocess.Popen') as process:result=self.store.run_cluster()
        self.assertFalse(result['ok']);self.assertEqual(self.store.sync_status['state'],'error');process.assert_not_called()
        self.assertEqual(self.store.config['primary_id'],'one')
    def test_native_exit_zero_without_completion_is_failure(self):
        self.store.config['cluster_sync']['enabled']=True
        process=unittest.mock.Mock();process.stdout=[];process.wait.return_value=0;process.poll.return_value=0
        # stdout is also closed after reading.
        class Lines(list):
            def close(self):pass
        process.stdout=Lines([])
        with patch('hub.shutil.which',return_value='/fake'),patch.object(self.store,'backup_central'),patch('hub.subprocess.Popen',return_value=process):result=self.store.run_cluster()
        self.assertFalse(result['ok']);self.assertFalse((self.store.dir/'adguard-sync-runtime.yaml').exists())
    def test_central_etag_and_native_rules_preservation(self):
        read=self.store.central_read('rules')
        with self.assertRaises(ValueError):self.store.central_write('rules',['||new.example.net^'],'stale')
        self.store.central_write('rules',['||new.example.net^'],read['etag'])
        self.assertEqual(self.store.user_rules['one'],['||new.example.net^'])
        self.assertEqual(self.store.user_rules['two'],['@@||replica.example.net^'])
        self.assertTrue(list((self.store.dir/'settings-backups').glob('*.json')))
    def test_central_dns_never_copies_listen_interface(self):
        read=self.store.central_read('dns');self.assertNotIn('bind_hosts',read['value'])
        with self.assertRaises(ValueError):self.store.central_write('dns',{'bind_hosts':['127.0.0.1']},read['etag'])
    def test_put_settings_use_documented_method(self):
        read=self.store.central_read('querylog');self.store.central_write('querylog',{'enabled':True},read['etag'])
        self.assertIn(('one','querylog/config/update',{'enabled':True},'PUT'),self.store.calls)
    def test_legacy_configuration_migrates(self):
        temp=Path(self.tmp.name)/'migration';temp.mkdir()
        cfg=copy.deepcopy(self.store.config);cfg.pop('servers');cfg.pop('primary_id');cfg.pop('cluster_sync')
        (temp/'config.json').write_text(json.dumps(cfg))
        migrated=Store(temp)
        self.assertEqual(len(migrated.servers()),1);self.assertEqual(migrated.primary()['url'],SERVERS[0]['url'])
        self.assertEqual(migrated.primary()['password'],'one-secret')
        self.assertFalse(migrated.config['cluster_sync']['enabled'])

class DNSTests(unittest.TestCase):
    def test_real_udp_dns_probe(self):
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        def answer():
            data,addr=sock.recvfrom(4096)
            sock.sendto(data[:2]+struct.pack('!HHHHH',0x8183,1,0,0,0)+data[12:],addr);sock.close()
        thread=threading.Thread(target=answer,daemon=True);thread.start()
        result=dns_probe('127.0.0.1',port,timeout=1);self.assertTrue(result['ok']);self.assertEqual(result['rcode'],3);thread.join(1)
    def test_timeout_is_not_success(self):
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind(('127.0.0.1',0))
        try:self.assertFalse(dns_probe('127.0.0.1',sock.getsockname()[1],timeout=.05)['ok'])
        finally:sock.close()

class HubHTTPTests(unittest.TestCase):
    def setUp(self):
        import urllib.request
        from http.server import ThreadingHTTPServer
        from server import Handler
        self.tmp=tempfile.TemporaryDirectory();self.env=patch.dict(os.environ,{'VENGUARD_PASSWORD':'test-only'});self.env.start()
        self.store=FakeStore(self.tmp.name);self.store.calls=[];self.store.offline=set();self.store.user_rules={'one':[],'two':[]}
        self.web=ThreadingHTTPServer(('127.0.0.1',0),Handler);self.web.store=self.store
        threading.Thread(target=self.web.serve_forever,daemon=True).start()
        self.base='http://127.0.0.1:'+str(self.web.server_port)
        self.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
        self.call('login',{'password':'test-only'})
    def tearDown(self):self.web.shutdown();self.web.server_close();self.tmp.cleanup();self.env.stop()
    def call(self,path,body=None):
        import urllib.request
        req=urllib.request.Request(self.base+'/api/'+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json','X-VenGuard':'1'})
        with self.opener.open(req,timeout=3) as r:return json.load(r)
    def test_two_servers_secret_preservation_and_no_credential_export(self):
        for s in SERVERS:self.call('servers',{'action':'save',**{k:v for k,v in s.items() if k!='id'}})
        state=self.call('state');one,two=state['hub']['servers'];self.assertEqual(len(state['hub']['servers']),2)
        self.assertNotIn('secret',json.dumps(state))
        self.call('servers',{'action':'save',**one,'password':''})
        self.assertEqual(self.store.selected(one['id'])['password'],'one-secret')
        self.assertNotIn('secret',json.dumps(self.call('export')))
        self.call('servers',{'action':'primary','id':two['id']})
        self.assertEqual(self.store.config['adguard']['password'],'two-secret')
        with self.assertRaises(urllib.error.HTTPError):self.call('servers',{'action':'delete','id':two['id']})
        self.call('servers',{'action':'delete','id':one['id']})
        self.assertEqual(len(self.store.servers()),1)
    def test_sync_enable_requires_two_servers(self):
        with self.assertRaises(urllib.error.HTTPError):self.call('cluster-settings',{'enabled':True})
        self.assertFalse(self.store.config['cluster_sync']['enabled'])
    def test_central_edits_blocked_during_native_round(self):
        self.store.config['servers']=copy.deepcopy(SERVERS);self.store.config['primary_id']='one';self.store.align_primary()
        self.store.cluster_lock.acquire()
        try:
            with self.assertRaises(urllib.error.HTTPError) as e:self.call('central-protection',{'enabled':False})
            self.assertEqual(e.exception.code,409)
            self.assertFalse(any(path=='protection' for sid,path,body,method in self.store.calls))
        finally:self.store.cluster_lock.release()

if __name__=='__main__':unittest.main()
