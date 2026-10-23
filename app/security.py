"""VenGuard access protection and read-only Wazuh alert visibility.

No routing, packet interception, firewall mutation or claim of volumetric DDoS mitigation.
"""
import base64
import copy
import ipaddress
import json
import threading
import time
import urllib.parse
import urllib.request
from collections import deque
from http.server import ThreadingHTTPServer
from hub import now_iso,error_text,write_private
from providers import NoRedirect

class BoundedHTTPServer(ThreadingHTTPServer):
    daemon_threads=True
    request_queue_size=64
    def __init__(self,*args,max_workers=32,**kwargs):
        self.slots=threading.BoundedSemaphore(max_workers);super().__init__(*args,**kwargs)
    def get_request(self):
        request,address=super().get_request();request.settimeout(15);return request,address
    def process_request(self,request,client_address):
        if not self.slots.acquire(blocking=False):self.shutdown_request(request);return
        try:super().process_request(request,client_address)
        except Exception:self.slots.release();raise
    def process_request_thread(self,request,client_address):
        try:super().process_request_thread(request,client_address)
        finally:self.slots.release()

class SecurityMixin:
    def init_security(self):
        self.security_config={'trusted_proxies':[],'wazuh':{'enabled':False,'url':'','username':'','password':''}}
        path=self.dir/'security.json'
        if path.exists():self.security_config.update(json.loads(path.read_text()))
        self.security_events=deque(maxlen=500);self.request_rates={};self.wazuh_lock=threading.Lock()
        self.wazuh_status={'checked_at':None,'ok':None,'error':'','alerts':[],'total':None}
        path=self.dir/'access-events.json'
        if path.exists():self.security_events.extend(json.loads(path.read_text())[-500:])
    def security_ip(self,address,forwarded=''):
        """Trust proxy headers only when the socket peer is an explicitly trusted proxy."""
        try:
            peer=ipaddress.ip_address(address);trusted=[ipaddress.ip_network(x) for x in self.security_config['trusted_proxies']]
            if not any(peer in network for network in trusted):return str(peer)
            chain=[ipaddress.ip_address(x.strip()) for x in forwarded.split(',') if x.strip()]
            if len(chain)>16:return str(peer)
            for candidate in reversed(chain):
                if not any(candidate in network for network in trusted):return str(candidate)
            return str(chain[0]) if chain else str(peer)
        except ValueError:return address
    def security_event(self,category,ip,description):
        event={'at':now_iso(),'epoch':time.time(),'category':category,'ip':ip,'description':description}
        with self.lock:
            self.security_events.append(event);write_private(self.dir/'access-events.json',list(self.security_events))
    def request_allowed(self,ip):
        now=time.time()
        with self.lock:
            self.request_rates={k:v for k,v in self.request_rates.items() if v and now-v[-1]<60}
            # Bound memory even when many different source addresses arrive.
            if ip not in self.request_rates and len(self.request_rates)>=4096:return False
            history=[t for t in self.request_rates.get(ip,[]) if now-t<60]
            if len(history)>=120:return False
            self.request_rates[ip]=history+[now];return True
    def security_snapshot(self):
        with self.lock:
            config=copy.deepcopy(self.security_config);config['wazuh']['password_set']=bool(config['wazuh'].pop('password',''))
            events=list(self.security_events);now=time.time();recent=[e for e in events if now-e['epoch']<86400]
            failed=[e for e in recent if e['category']=='login_failed']
            limited=[{'ip':ip,'until':max(history)+300} for ip,history in self.attempts.items() if not ip.startswith('account:') and len([t for t in history if now-t<300])>=10]
            return {'config':config,'events':events[-200:],'failed_24h_retained':len(failed),'limited':limited,'wazuh':copy.deepcopy(self.wazuh_status),'coverage':{'venguard_login':True,'dns':True,'server_logins':None if self.security_config['wazuh']['enabled'] else False,'network_flows':False,'firewall_enforcement':False,'upstream_ddos':False}}
    def save_security(self,data):
        with self.lock:
            config=copy.deepcopy(self.security_config)
            if 'trusted_proxies' in data:
                values=data['trusted_proxies']
                if not isinstance(values,list) or len(values)>20:raise ValueError('Gebruik maximaal 20 vertrouwde proxy-IP’s of CIDR-bereiken.')
                networks=[ipaddress.ip_network(str(x).strip(),strict=False) for x in values]
                if any(n.prefixlen==0 for n in networks):raise ValueError('Vertrouw niet alle IP-adressen als proxy. Gebruik de echte proxy-IP’s of een afgebakend subnet.')
                config['trusted_proxies']=[str(n) for n in networks]
            if 'wazuh' in data:
                source=data['wazuh'];old=config['wazuh'];url=str(source.get('url',old['url'])).strip().rstrip('/')
                if url:
                    parsed=urllib.parse.urlsplit(url)
                    if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:raise ValueError('Gebruik het volledige Wazuh indexer-adres zonder credentials of queryparameters.')
                new={'enabled':bool(source.get('enabled',old['enabled'])),'url':url,'username':str(source.get('username',old['username']))[:200],'password':str(source.get('password') or old['password'])}
                if source.get('clear_password'):new['password']=''
                if new['enabled'] and not url:raise ValueError('Vul het Wazuh indexer-adres in.')
                config['wazuh']=new
            self.security_config=config;write_private(self.dir/'security.json',config)
            self.wazuh_status={'checked_at':None,'ok':None,'error':'','alerts':[],'total':None}
        return {'ok':True}
    def poll_wazuh(self):
        if not self.wazuh_lock.acquire(blocking=False):return {'ok':False,'message':'Wazuh wordt al opgehaald.'}
        try:
            with self.lock:config=copy.deepcopy(self.security_config['wazuh'])
            if not config['enabled']:return {'ok':False,'message':'Wazuh is niet gekoppeld.'}
            # Fixed read-only query: never proxy arbitrary OpenSearch operations from the UI.
            query={'size':100,'track_total_hits':True,'sort':[{'timestamp':{'order':'desc','unmapped_type':'date'}}],
              '_source':['timestamp','rule.id','rule.level','rule.description','rule.groups','agent.id','agent.name','data.srcip','data.src_ip','data.dest_ip','data.dstip','data.srcport','data.dstport'],
              'query':{'bool':{'filter':[{'range':{'timestamp':{'gte':'now-30m'}}},{'range':{'rule.level':{'gte':5}}}]}}}
            token=base64.b64encode((config['username']+':'+config['password']).encode()).decode()
            request=urllib.request.Request(config['url']+'/wazuh-alerts-*/_search',data=json.dumps(query).encode(),headers={'Content-Type':'application/json','Authorization':'Basic '+token,'Accept':'application/json'})
            with urllib.request.build_opener(NoRedirect()).open(request,timeout=12) as response:
                raw=response.read(2*1024*1024+1)
                if len(raw)>2*1024*1024:raise ValueError('Wazuh-antwoord te groot; gebruik een account met toegang tot de bedoelde alertindexen.')
                try:result=json.loads(raw)
                except ValueError:raise ValueError('Wazuh geeft geen JSON terug. Gebruik de indexer-API, meestal poort 9200, niet het dashboard of de manager-API.')
            if result.get('error') or result.get('timed_out') or result.get('_shards',{}).get('failed',0):raise ValueError('De Wazuh-indexer kon de volledige alertzoekopdracht niet afronden.')
            hits=result.get('hits')
            if not isinstance(hits,dict) or not isinstance(hits.get('hits'),list):raise ValueError('Onverwacht Wazuh indexer-antwoord; controleer het API-adres en de leesrechten op de alertindexen.')
            alerts=[]
            for hit in hits.get('hits',[])[:100]:
                value=hit.get('_source',{});rule=value.get('rule',{});data=value.get('data',{});agent=value.get('agent',{})
                source=str(data.get('srcip') or data.get('src_ip') or '')
                try:source=str(ipaddress.ip_address(source))
                except ValueError:source=''
                alerts.append({'at':value.get('timestamp'),'level':rule.get('level'),'rule_id':str(rule.get('id',''))[:80],'description':str(rule.get('description',''))[:500],'agent':str(agent.get('name') or agent.get('id') or '')[:200],'source_ip':source,'groups':rule.get('groups',[])[:20]})
            total=hits.get('total',0);total=total.get('value',0) if isinstance(total,dict) else total
            status={'ok':True,'checked_at':now_iso(),'error':'','alerts':alerts,'total':total}
        except Exception as e:status={'ok':False,'checked_at':now_iso(),'error':error_text(e),'alerts':[],'total':None}
        finally:self.wazuh_lock.release()
        with self.lock:
            if config!=self.security_config['wazuh']:return {'ok':False,'message':'De Wazuh-koppeling is intussen gewijzigd; haal opnieuw op.'}
            self.wazuh_status=status
        return {'ok':status['ok'],'message':'Wazuh-meldingen opgehaald.' if status['ok'] else status['error']}
    def security_worker(self):
        while not self.stop.is_set():
            if self.security_config['wazuh']['enabled']:self.poll_wazuh()
            self.stop.wait(60)
