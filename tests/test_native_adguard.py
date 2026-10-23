"""Disposable official AdGuard Home containers only, enabled explicitly by CI."""
import json,os,sys,tempfile,time,unittest,urllib.request
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from server import Store

@unittest.skipUnless(os.getenv('VENGUARD_AGH_DISPOSABLE')=='1','Official clean AdGuard containers are tested in CI')
class CleanAdGuardTests(unittest.TestCase):
    def test_profile_survives_origin_outage_and_configures_clean_replica(self):
        urls=['http://127.0.0.1:19081','http://127.0.0.1:19082'];password='ci-only-adguard-password'
        for i,url in enumerate(urls):
            data={'web':{'ip':'0.0.0.0','port':3000},'dns':{'ip':'0.0.0.0','port':5353+i},'username':'admin','password':password}
            # The public install wizard creates the only per-server credentials/bindings.
            req=urllib.request.Request(url+'/control/install/configure',data=json.dumps(data).encode(),headers={'Content-Type':'application/json'})
            try:
                with urllib.request.urlopen(req,timeout=15) as response:self.assertEqual(response.status,200)
            except Exception:
                # A web-server restart can close the wizard response; status below must authenticate.
                pass
        with tempfile.TemporaryDirectory() as folder:
            store=Store(folder);store.config['sources']=[]
            store.config['servers']=[{'id':str(i),'name':'Clean '+str(i),'type':'adguard','url':url,'username':'admin','password':password,'enabled':True,'dns_host':'127.0.0.1','dns_port':5353+i} for i,url in enumerate(urls)]
            store.config['primary_id']='0';store.align_primary()
            for server in store.servers():
                for attempt in range(20):
                    try:store.agh('status',settings=server);break
                    except Exception:
                        if attempt==19:raise
                        time.sleep(.5)
            # Read all supported shared settings once, then VenGuard is authoritative.
            store.adopt_server('0')
            dns=store.desired_read('dns');dns['value']['upstream_dns']=['1.1.1.1'];dns['value']['bootstrap_dns']=['9.9.9.9']
            store.desired_write('dns',dns['value'],dns['etag'])
            rewrite=store.desired_read('rewrites');store.desired_write('rewrites',[{'domain':'venguard-test.home.arpa','answer':'192.0.2.50','enabled':True}],rewrite['etag'])
            # Take the configured origin out of the management path; the clean replica must still apply.
            store.config['servers'][0]['url']='http://127.0.0.1:1'
            result=store.apply_management()
            self.assertFalse(result['results']['0']['ok']);self.assertTrue(result['results']['1']['ok'],result['results']['1'])
            actual=store.agh('dns_info',settings=store.selected('1'))
            self.assertEqual(actual['upstream_dns'],['1.1.1.1']);self.assertEqual(actual['port'],5354)
            self.assertTrue(any(r['domain']=='venguard-test.home.arpa' for r in store.agh('rewrite/list',settings=store.selected('1'))))
            self.assertEqual(Store(folder).desired['sections']['dns']['upstream_dns'],['1.1.1.1'])
