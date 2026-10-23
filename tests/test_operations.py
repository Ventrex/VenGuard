import copy
import json
import os
import re
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch
from server import Store
from hub import error_text,native_config,HUB_DEFAULT
from operations import native_rules,BEGIN,END
from rules import rule_text
from migrations import migrate
from test_hub import FakeStore,SERVERS

class OperationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.s=FakeStore(self.tmp.name);self.s.config['servers']=copy.deepcopy(SERVERS);self.s.config['primary_id']='one';self.s.align_primary();self.s.calls=[];self.s.offline=set();self.s.user_rules={'one':['@@||keep.example.net^'],'two':['||local.example.net^']}
    def tearDown(self):self.tmp.cleanup()
    def test_already_enabled_is_noop_without_full_sync(self):
        self.s.config['cluster_sync']['enabled']=True
        r=self.s.set_controls('protection',True)
        self.assertTrue(r['ok']);self.assertEqual(set(r['results']),{'one','two'})
        self.assertFalse(any(body is not None for sid,path,body,method in self.s.calls))
        self.assertFalse(self.s.cluster_event.is_set())
    def test_offline_replica_does_not_prevent_confirmation_and_is_retried(self):
        self.s.config['cluster_sync']['enabled']=True;self.s.offline={'two'}
        r=self.s.set_controls('protection',True)
        self.assertTrue(r['results']['one']['ok']);self.assertFalse(r['results']['two']['ok'])
        self.assertIn('two',self.s.control_intents);self.s.offline=set();self.s.reconcile_controls()
        self.assertFalse(self.s.control_intents)
    def test_live_exact_allow_preserves_other_rules_and_expiry_removes_only_owned(self):
        r={'id':'new','domain':'checkout.example.net','action':'allow','match':'exact','client':'192.0.2.83','enabled':True,'expires_at':time.time()+900}
        self.s.config['rules']=[r];self.assertTrue(self.s.apply_live_rules()['ok'])
        self.assertIn('@@||keep.example.net^',self.s.user_rules['one']);self.assertIn('||local.example.net^',self.s.user_rules['two'])
        rule=rule_text(r);pattern=rule[3:rule.rfind('/')]
        self.assertRegex('checkout.example.net',pattern);self.assertIsNone(re.search(pattern,'ads.checkout.example.net'))
        self.assertIn(rule,self.s.user_rules['one']);self.assertFalse(self.s.cluster_event.is_set())
        r['expires_at']=1;self.s.expire_rules();self.assertTrue(self.s.apply_live_rules()['ok'])
        self.assertEqual(self.s.user_rules['one'],['@@||keep.example.net^']);self.assertEqual(self.s.user_rules['two'],['||local.example.net^'])
    def test_latest_edit_during_application_stays_pending(self):
        self.s.config['rules']=[{'domain':'one.example.net','action':'block','enabled':True}]
        original=self.s.agh
        def change(path,body=None,**kwargs):
            if path=='filtering/set_rules':self.s.revision+=1
            return original(path,body,**kwargs)
        with patch.object(self.s,'agh',side_effect=change):self.s.apply_live_rules()
        self.assertTrue(self.s.rules_pending)
    def test_ambiguous_marker_is_never_erased(self):
        with self.assertRaises(ValueError):native_rules(['keep',BEGIN,'other'],[])
    def test_sync_running_queues_live_rule_without_overwriting(self):
        self.s.cluster_lock.acquire()
        try:self.assertTrue(self.s.apply_live_rules()['queued']);self.assertEqual(self.s.user_rules['one'],['@@||keep.example.net^'])
        finally:self.s.cluster_lock.release()
    def test_protocol_specific_errors_do_not_invent_certificate_issue(self):
        import socket,ssl,errno
        self.assertIn('route',error_text(urllib.error.URLError(OSError(errno.EHOSTUNREACH,'unreachable'))))
        self.assertNotIn('certificaat',error_text(urllib.error.URLError(ConnectionRefusedError())))
        self.assertIn('DNS-naam',error_text(urllib.error.URLError(socket.gaierror())))
        self.assertIn('certificaat',error_text(urllib.error.URLError(ssl.SSLCertVerificationError())))
    def test_legacy_choices_migrate_once_without_public_brand_presets(self):
        cfg={'rules':[],'packs':{'dpg_ads':True},'compatibility':{'ing':True}}
        migrate(cfg);before=copy.deepcopy(cfg);migrate(cfg);self.assertEqual(before,cfg)
        self.assertTrue(any(r['action']=='block' for r in cfg['rules']))
        self.assertTrue(all(not r['enabled'] for r in cfg['rules'] if r['action']=='allow'))
        self.assertNotIn('compatibility',cfg);self.assertEqual(cfg['packs'],{})
    def test_automatic_native_round_omits_dns_reconfiguration(self):
        self.s.config['cluster_sync']['enabled']=True
        class Lines(list):
            def close(self):pass
        process=unittest.mock.Mock();process.stdout=Lines([]);process.wait.return_value=0;process.poll.return_value=0
        capture={}
        def start(*args,**kwargs):capture.update(json.loads((self.s.dir/'adguard-sync-runtime.yaml').read_text()));return process
        with patch('hub.shutil.which',return_value='/fake'),patch.object(self.s,'backup_central'),patch('hub.subprocess.Popen',side_effect=start):self.s.run_cluster()
        self.assertFalse(capture['features']['dns']['serverConfig'])
        with patch('hub.shutil.which',return_value='/fake'),patch.object(self.s,'backup_central'),patch('hub.subprocess.Popen',side_effect=start):self.s.run_cluster(allow_dns=True)
        self.assertTrue(capture['features']['dns']['serverConfig'])

if __name__=='__main__':unittest.main()
