"""Opt-in integration against a fresh official Pi-hole Docker container only."""
import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
import urllib.parse
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from server import Store,Handler

@unittest.skipUnless(os.getenv('VENGUARD_PIHOLE_DISPOSABLE')=='1','Official Pi-hole is tested in a disposable Docker job')
class NativePiHoleTest(unittest.TestCase):
    def test_official_pihole_sessions_gravity_exact_rules_and_blocking(self):
        base=os.environ['VENGUARD_PIHOLE_URL']
        assert urllib.parse.urlsplit(base).hostname in ('127.0.0.1','localhost'), 'Integration may only use a disposable local container'
        with tempfile.TemporaryDirectory() as folder:
            store=Store(folder);store.config.update(auto_sync=False,sources=[{'id':'fixture','name':'Fixture','url':'https://example.org/fixture','enabled':True}])
            store.config['servers']=[{'id':'pi','type':'pihole','name':'Disposable Pi-hole','url':base,'password':os.environ['VENGUARD_PIHOLE_PASSWORD'],'username':'','enabled':True,'dns_host':'','dns_port':53}];store.config['primary_id']='pi';store.align_primary()
            web=ThreadingHTTPServer(('0.0.0.0',18181),Handler);web.store=store;threading.Thread(target=web.serve_forever,daemon=True).start()
            store.config['public_url']='http://host.docker.internal:18181'
            try:
                self.assertIn('version',store.agh('status'))
                # The test owns this fresh container; avoid downloading unrelated default lists.
                for item in store.pihole.call(store.primary(),'lists').get('lists',[]):
                    store.pihole.call(store.primary(),'lists/'+urllib.parse.quote(item['address'],safe='')+'?type='+item.get('type','block'),method='DELETE')
                store.caches={'fixture':{'rules':['||ads.integration.test^','@@||content.integration.test^']}};store.rebuild(False)
                result=store.publish_all();self.assertTrue(result['ok'],result)
                lists=store.pihole.call(store.primary(),'lists').get('lists',[]);self.assertEqual(len(lists),2);self.assertEqual({r['type'] for r in lists},{'allow','block'})
                # Real Gravity must parse each dedicated ABP subscription, including its suffix semantics.
                self.assertTrue(all((r.get('number',0)+r.get('abp_entries',0))>0 for r in lists),lists)
                store.config['rules']=[{'id':'one','domain':'checkout.integration.test','action':'allow','match':'exact','enabled':True}]
                self.assertTrue(store.apply_live_rules()['ok'])
                values=store.pihole.call(store.primary(),'domains/allow/exact').get('domains',[])
                self.assertTrue(any(r['domain']=='checkout.integration.test' and r['enabled'] for r in values),values)
                self.assertTrue(store.set_controls('protection',False)['ok']);self.assertFalse(store.agh('status')['protection_enabled'])
                self.assertTrue(store.set_controls('protection',True)['ok']);self.assertTrue(store.agh('status')['protection_enabled'])
                store.config['rules']=[];self.assertTrue(store.apply_live_rules()['ok'])
                self.assertFalse(any(r['domain']=='checkout.integration.test' for r in store.pihole.call(store.primary(),'domains').get('domains',[])))
            finally:web.shutdown();web.server_close()

if __name__=='__main__':unittest.main()
