import copy,json,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from server import Store
from hub import digest
from operations import BEGIN,END
from test_hub import SERVERS

class ManagedStore(Store):
    def agh(self,path,body=None,query=None,settings=None,method=None):
        server=settings or self.primary();sid=server['id'];self.calls.append((sid,path,copy.deepcopy(body)))
        if sid in self.offline:raise TimeoutError()
        state=self.remote[sid]
        if path=='status':return {'version':'v0.107.79','protection_enabled':state['protection']}
        if path=='dns_info':return {**copy.deepcopy(state['dns']),'bind_hosts':['127.0.0.1'],'port':5353}
        if path=='dns_config':state['dns'].update(body)
        if path=='filtering/status':return {'enabled':state['filtering'],'interval':24,'filters':copy.deepcopy(state['filters']),'whitelist_filters':[],'user_rules':copy.deepcopy(state['rules'])}
        if path=='filtering/set_rules':state['rules']=body['rules']
        if path=='protection':state['protection']=body['enabled']
        if path=='filtering/config':state['filtering']=body['enabled']
        if path=='filtering/add_url':state['filters'].append({'enabled':True,**body})
        if path=='filtering/set_url':
            item=next(f for f in state['filters'] if f['url']==body['url']);item.update(body['data'])
        if path=='filtering/remove_url':state['filters']=[f for f in state['filters'] if f['url']!=body['url']]
        if path=='rewrite/list':return copy.deepcopy(state['rewrites'])
        if path=='rewrite/add':state['rewrites'].append(body)
        if path=='rewrite/delete':state['rewrites']=[r for r in state['rewrites'] if r['domain']!=body['domain'] or r['answer']!=body['answer']]
        if path=='clients':return {'clients':copy.deepcopy(state['clients'])}
        if path=='clients/add':state['clients'].append(body)
        if path=='clients/delete':state['clients']=[c for c in state['clients'] if c['name']!=body['name']]
        return {}

class ManagementTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.s=ManagedStore(self.tmp.name);self.s.config['sources']=[]
        self.s.config['servers']=copy.deepcopy(SERVERS);self.s.config['primary_id']='one';self.s.align_primary()
        self.s.calls=[];self.s.offline=set();self.s.remote={sid:{'dns':{'upstream_dns':['9.9.9.9'],'bootstrap_dns':['9.9.9.9'],'cache_size':1000},'rules':[],'rewrites':[],'clients':[],'filters':[],'protection':True,'filtering':True} for sid in ('one','two')}
    def tearDown(self):self.tmp.cleanup()
    def save(self,section,value):return self.s.desired_write(section,value,self.s.desired_read(section)['etag'])
    def test_profile_edit_and_new_server_do_not_depend_on_origin(self):
        self.save('dns',{'upstream_dns':['1.1.1.1']});self.s.offline={'one'}
        result=self.s.apply_management();self.assertFalse(result['ok']);self.assertTrue(result['results']['two']['ok']);self.assertEqual(self.s.remote['two']['dns']['upstream_dns'],['1.1.1.1'])
        self.assertTrue((self.s.dir/'desired-settings.json').exists());self.s.calls=[];self.s.apply_management()
        self.assertFalse(any(path=='dns_config' for sid,path,body in self.s.calls))
    def test_capture_and_reapply_with_primary_offline(self):
        self.s.adopt_server('one');self.assertTrue(self.s.desired['captured']);self.assertNotIn('bind_hosts',self.s.desired['sections']['dns'])
        self.s.offline={'one'};self.save('dns',{'upstream_dns':['1.1.1.1']});self.assertTrue(self.s.apply_management()['results']['two']['ok'])
    def test_native_rule_update_preserves_live_block(self):
        for sid in self.s.remote:self.s.remote[sid]['rules']=['old',BEGIN,'@@||checkout.example.net^',END]
        self.save('rules',['||new.example.net^']);self.assertTrue(self.s.apply_management()['ok'])
        self.assertEqual(self.s.remote['two']['rules'],['||new.example.net^',BEGIN,'@@||checkout.example.net^',END])
    def test_noop_periodic_apply_never_rewrites_dns(self):
        self.save('dns',{'upstream_dns':['9.9.9.9']});self.s.apply_management();self.s.calls=[];self.s.apply_management()
        self.assertFalse(any(p=='dns_config' for _,p,_ in self.s.calls))
    def test_server_defaults_do_not_recreate_clients_or_rewrites(self):
        self.save('clients',[{'name':'Lamp','ids':['192.168.0.50']}]);self.save('rewrites',[{'domain':'nas.home.arpa','answer':'192.168.0.51'}])
        for remote in self.s.remote.values():
            remote['clients']=[{'name':'Lamp','ids':['192.168.0.50'],'use_global_settings':True,'filtering_enabled':True}]
            remote['rewrites']=[{'domain':'nas.home.arpa','answer':'192.168.0.51','enabled':True}]
        self.assertTrue(self.s.apply_management()['ok'])
        self.assertFalse(any(p.endswith(('/add','/delete')) for _,p,_ in self.s.calls))
    def test_clean_server_null_collections_are_imported(self):
        self.s.remote['one']['rules']=None;self.s.remote['one']['clients']=None
        self.s.adopt_server('one');self.assertEqual(self.s.desired['sections']['rules'],[]);self.assertEqual(self.s.desired['sections']['clients'],[])
    def test_profile_can_be_configured_before_servers_exist(self):
        self.s.config['servers']=[];self.s.config['adguard']['url']=''
        self.save('dns',{'upstream_dns':['1.1.1.1']});self.assertTrue(self.s.desired_controls('protection',False)['ok'])
        loaded=Store(self.tmp.name);self.assertEqual(loaded.desired['sections']['dns']['upstream_dns'],['1.1.1.1'])
    def test_forbidden_fields_and_stale_edits_rejected(self):
        with self.assertRaises(ValueError):self.save('dns',{'bind_hosts':['0.0.0.0']})
        with self.assertRaises(ValueError):self.s.desired_write('dns',{'upstream_dns':['1.1.1.1']},'wrong')
    def test_authoritative_filters_survive_origin_outage(self):
        self.s.remote['one']['filters']=[{'name':'source','url':'https://example.org/filters','enabled':False}]
        self.s.remote['two']['filters']=[{'name':'old','url':'https://example.net/old','enabled':True}]
        self.s.adopt_server('one');self.s.offline={'one'};self.s.apply_management()
        self.assertEqual(self.s.remote['two']['filters'][0]['url'],'https://example.org/filters');self.assertFalse(self.s.remote['two']['filters'][0]['enabled'])
