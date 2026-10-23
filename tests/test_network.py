import copy,json,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from server import Store
from scanner_agent import parse_nmap,audit_domain,scan
from migrations import migrate

class NetworkTests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.s=Store(self.tmp.name);self.s.network_settings({'enabled':True,'subnets':['192.168.0.0/24']})
    def tearDown(self):self.tmp.cleanup()
    def report(self,rows,complete=True,error=''):
        return self.s.scanner_report({'devices':rows,'subnets':['192.168.0.0/24'],'complete':complete,'error':error},self.s.network_token)
    def test_names_persist_online_offline_and_failed_scan_is_unknown(self):
        device={'ip':'192.168.0.50','mac':'aa:bb:cc:dd:ee:ff','hostname':'device','vendor':'Example'}
        self.report([device]);self.s.network_device({'id':device['mac'],'name':'Mijn lamp','type':'Lamp'})
        self.report([device|{'hostname':'changed'}]);self.assertEqual(self.s.network_snapshot()['devices'][0]['name'],'Mijn lamp')
        for _ in range(3):self.report([])
        d=self.s.network_snapshot()['devices'][0];self.assertEqual(d['state'],'offline');self.assertTrue(d['last_seen'])
        self.s.network['agent_seen']=0;self.assertEqual(self.s.network_snapshot()['devices'][0]['state'],'unknown')
        loaded=Store(self.tmp.name);self.assertEqual(loaded.network['devices'][device['mac']]['name'],'Mijn lamp')
    def test_incomplete_scan_does_not_mark_devices_offline(self):
        self.report([{'ip':'192.168.0.20'}])
        for _ in range(4):self.report([],complete=False,error='scan failed')
        self.assertEqual(self.s.network['devices']['192.168.0.20']['missed'],0)
    def test_agent_auth_private_scope_and_secret_redaction(self):
        with self.assertRaises(PermissionError):self.s.scanner_report({},'bad')
        for subnet in ('8.8.8.0/24','192.168.0.0/16','0.0.0.0/0','127.0.0.0/24'):
            with self.assertRaises(ValueError):self.s.network_settings({'subnets':[subnet]})
        self.report([{'ip':'8.8.8.8'}]);self.assertFalse(self.s.network['devices'])
        self.assertNotIn(self.s.network_token,json.dumps(self.s.snapshot()))
    def test_nmap_hostname_vendor_parsing(self):
        xml=b'<nmaprun><host><status state="up" reason="arp-response"/><address addr="192.168.0.50" addrtype="ipv4"/><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Example"/><hostnames><hostname name="lamp"/></hostnames></host></nmaprun>'
        device=parse_nmap(xml)[0];self.assertEqual(device['hostname'],'lamp');self.assertEqual(device['vendor'],'Example')
    def test_timeout_does_not_delete_filter_rules(self):
        self.s.config['rules']=[{'domain':'ads.example.net','action':'block','enabled':True}];before=copy.deepcopy(self.s.config['rules'])
        self.s.network['agent_seen']=time.time();self.s.request_audit({'domain':'ads.example.net'});job=self.s.network['audit_job']
        self.s.scanner_report({'audit_id':job['id'],'audit':{'ads.example.net':{'dns':True,'ping':False,'message':'timeout'}},'devices':[]},self.s.network_token)
        self.assertEqual(self.s.config['rules'],before);self.assertFalse(self.s.network['audit']['ads.example.net']['ping'])
    def test_stable_list_migration_is_idempotent(self):
        cfg={'mode':'observed','rules':[]};migrate(cfg);self.assertEqual(cfg['mode'],'all');before=copy.deepcopy(cfg);migrate(cfg);self.assertEqual(cfg,before)
