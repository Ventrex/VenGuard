"""Multiple independent AdGuard servers and the real AdGuardHome Sync engine.

DNS traffic never goes through VenGuard. A fixed origin is authoritative;
replicas are never promoted automatically while it is unavailable.
"""
import base64
import copy
import errno
import ssl
import hashlib
import ipaddress
import json
import os
import secrets
import shutil
import socket
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from providers import kind
from datetime import datetime,timezone
from pathlib import Path

SYNC_VERSION='0.9.4'
FEATURES={
 'filters':('Filterlijsten, uitzonderingen en eigen regels',True),
 'general':('Algemene bescherming, Safe Browsing en Safe Search',True),
 'dns':('DNS-instellingen, upstreams en toegangsregels',True),
 'rewrites':('DNS-herschrijvingen',True),
 'clients':('Apparaatinstellingen',True),
 'services':('Geblokkeerde diensten',True),
 'querylog':('Instellingen verzoekenlog',True),
 'statistics':('Instellingen statistieken',True),
}
HUB_DEFAULT={'enabled':False,'interval_minutes':5,'features':{k:v[1] for k,v in FEATURES.items()}}
# These editors are backed by documented AdGuard endpoints, not arbitrary proxy URLs.
SECTIONS={
 'rules':{'name':'Eigen AdGuard-regels','get':'filtering/status','key':'user_rules','set':'filtering/set_rules'},
 'dns':{'name':'DNS & upstreams','get':'dns_info','set':'dns_config','keys':['upstream_dns','upstream_dns_file','bootstrap_dns','fallback_dns','upstream_mode','use_dnssec','cache_size','cache_ttl_min','cache_ttl_max','cache_optimistic','ratelimit','blocking_mode','blocked_response_ttl','resolve_clients','use_private_ptr_resolvers','local_ptr_upstreams','edns_cs_enabled']},
 'rewrites':{'name':'DNS-herschrijvingen','get':'rewrite/list'},
 'clients':{'name':'Apparaatinstellingen','get':'clients','key':'clients'},
 'services':{'name':'Geblokkeerde diensten','get':'blocked_services/get','set':'blocked_services/update','method':'PUT'},
 'querylog':{'name':'Verzoekenlog','get':'querylog/config','set':'querylog/config/update','method':'PUT'},
 'statistics':{'name':'Statistieken','get':'stats/config','set':'stats/config/update','method':'PUT'},
 'access':{'name':'DNS-toegangsregels','get':'access/list','set':'access/set'},
}

def now_iso():return datetime.now(timezone.utc).isoformat(timespec='seconds')
def error_text(e):
    if isinstance(e,urllib.error.HTTPError):return f'Beheer-API: HTTP {e.code}. '+('Inloggegevens of API-rechten geweigerd.' if e.code in (401,403) else 'Controleer het beheeradres en de serverlog.')
    if isinstance(e,ValueError):return str(e)
    reason=getattr(e,'reason',e)
    if isinstance(reason,ssl.SSLCertVerificationError):return 'HTTPS-certificaat geweigerd; controleer de certificaatketen en hostnaam.'
    if isinstance(reason,ssl.SSLError):return 'TLS-verbinding mislukt; controleer de HTTPS-poort en TLS-configuratie.'
    if isinstance(reason,socket.gaierror):return 'De DNS-naam van het beheeradres kan vanaf VenGuard niet worden opgelost.'
    if isinstance(reason,(TimeoutError,socket.timeout)):return 'Beheer-API: timeout na maximaal 12 seconden. Controleer bereikbaarheid en of de server opnieuw wordt geconfigureerd.'
    if isinstance(reason,ConnectionRefusedError):return 'Beheer-API: verbinding geweigerd. Controleer de beheerpoort en of de dienst draait.'
    if isinstance(reason,ConnectionResetError):return 'De server heeft de beheerverbinding verbroken. VenGuard controleert de werkelijke stand opnieuw.'
    if getattr(reason,'errno',None) in (errno.EHOSTUNREACH,errno.ENETUNREACH):return 'Geen netwerkroute naar het beheeradres vanaf VenGuard. Controleer host, firewall en Docker-netwerk.'
    return 'Beheerverbinding mislukt; de actuele stand is niet bevestigd. Controleer de server en de recente acties in VenGuard.'
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def write_private(path,value):
    temp=path.with_name(path.name+'.tmp')
    with open(temp,'w',encoding='utf-8') as f:
        os.chmod(temp,0o600);json.dump(value,f,ensure_ascii=False,indent=2);f.flush();os.fsync(f.fileno())
    os.replace(temp,path)

def dns_probe(host,port=53,timeout=2):
    # Kept as a public seam for existing callers and protocol tests.
    from connectivity import dns_probe as probe
    return probe(host,port,timeout)

def native_config(servers,primary_id,options):
    active=[s for s in servers if s.get('enabled',True)]
    origin=next((s for s in active if s['id']==primary_id),None)
    replicas=[s for s in active if s['id']!=primary_id]
    if not origin or not replicas:raise ValueError('Kies één ingeschakelde bronserver en minimaal één replica.')
    def instance(s):
        url=s['url'].rstrip('/')
        if url.endswith('/control'):url=url[:-8]
        return {'url':url,'apiPath':'/control','username':s.get('username',''),'password':s.get('password',''),'autoSetup':False,'insecureSkipVerify':False}
    f=options['features']
    return {'runOnStart':True,'continueOnError':True,'httpClientTimeout':'6s','api':{'port':0},
      'origin':instance(origin),'replicas':[instance(s) for s in replicas],
      'features':{'dns':{'accessLists':f['dns'],'serverConfig':f['dns'],'rewrites':f['rewrites']},
       'dhcp':{'serverConfig':False,'staticLeases':False},'generalSettings':f['general'],'protectionStatus':f['general'],
       'queryLogConfig':f['querylog'],'statsConfig':f['statistics'],'clientSettings':f['clients'],'services':f['services'],
       'filters':{'blacklist':f['filters'],'whitelist':f['filters'],'userRules':f['filters']},'theme':False,'tlsConfig':False}}

def parse_sync_results(lines,servers,primary_id):
    """Use real per-replica completion messages; an exit code alone is not success."""
    outcomes={s['id']:{'state':'error','message':'Geen geslaagde afronding gemeld door AdGuard Sync.'} for s in servers if s['id']!=primary_id and s.get('enabled',True)}
    for line in lines:
        try:record=json.loads(line)
        except (ValueError,TypeError):continue
        if record.get('msg')!='Sync done':continue
        target=record.get('to','')
        matches=[s for s in servers if s['id'] in outcomes and target in (urllib.parse.urlsplit(s['url']).netloc,urllib.parse.urlsplit(s['url']).hostname)]
        if len(matches)==1:
            ok=str(record.get('level','')).lower()=='info'
            outcomes[matches[0]['id']]={'state':'success' if ok else 'error','message':'AdGuard Sync meldt dat alle gekozen onderdelen zijn verwerkt.' if ok else 'AdGuard Sync meldt een fout bij deze replica; instellingen kunnen gedeeltelijk zijn verwerkt.'}
    return outcomes

class HubMixin:
    def init_hub(self):
        self.config.setdefault('servers',[]);self.config.setdefault('primary_id','')
        if not self.config['servers'] and self.config.get('adguard',{}).get('url'):
            a=self.config['adguard'];hostname=urllib.parse.urlsplit(a['url']).hostname or ''
            try:ipaddress.ip_address(hostname);dns_host=hostname
            except ValueError:dns_host=''
            self.config['servers']=[{'id':'primary','name':'AdGuard 1',**copy.deepcopy(a),'enabled':True,'dns_host':dns_host,'dns_port':53}];self.config['primary_id']='primary'
        self.config['cluster_sync']={**copy.deepcopy(HUB_DEFAULT),**self.config.get('cluster_sync',{})}
        self.config['cluster_sync']['features']={**HUB_DEFAULT['features'],**self.config['cluster_sync'].get('features',{})}
        self.health={};self.feed_results={};self.logs_by_server={};self.health_checked=None
        self.monitor_lock=threading.Lock();self.cluster_event=threading.Event();self.cluster_lock=threading.Lock();self.process=None
        self.sync_status={'state':'idle','running':False,'last_attempt':None,'last_success':None,'results':{},'error':'','version':SYNC_VERSION}
        path=self.dir/'cluster-status.json'
        if path.exists():
            try:self.sync_status.update(json.loads(path.read_text()));self.sync_status['running']=False
            except (ValueError,OSError):pass
        if self.sync_status['state'] in ('running','queued'):
            self.sync_status.update(state='error',error='De vorige ronde is onderbroken; start opnieuw om de actuele toestand te controleren.')
        (self.dir/'adguard-sync-runtime.yaml').unlink(missing_ok=True)
        self.last_cluster_attempt=0;self.allow_dns_sync=False;self.last_live_attempt=0
    def servers(self):
        with self.lock:
            data=copy.deepcopy(self.config.get('servers',[]))
            # Compatibility with old API clients and unit tests using adguard directly.
            if not data and self.config.get('adguard',{}).get('url'):
                data=[{'id':'legacy','name':'AdGuard 1',**copy.deepcopy(self.config['adguard']),'enabled':True,'dns_host':'','dns_port':53}]
            return data
    def primary(self):
        items=self.servers();pid=self.config.get('primary_id')
        result=next((s for s in items if s['id']==pid),None) or (items[0] if items else None)
        if not result:raise ValueError('Voeg eerst een AdGuard-server toe.')
        return result
    def selected(self,sid=''):
        if not sid:return self.primary()
        result=next((s for s in self.servers() if s['id']==sid),None)
        if not result:raise ValueError('AdGuard-server niet gevonden.')
        return result
    def align_primary(self):
        items=self.config.get('servers',[])
        if not items:return
        origin=next((s for s in items if s['id']==self.config.get('primary_id')),None)
        if origin:
            self.config['adguard']={k:origin.get(k,'') for k in ['url','username','password']}
            self.config['adguard']['type']=kind(origin)
    def hub_snapshot(self):
        with self.lock:
            items=[]
            for server in self.servers():
                server.pop('password',None)
                server['password_set']=bool(self.selected(server['id']).get('password'))
                health=copy.deepcopy(self.health.get(server['id'],{}))
                health['stale']=not health.get('checked_at') or time.time()-health.get('checked_epoch',0)>90
                from connectivity import assessment
                health['assessment']=assessment(health)
                server['health']=health;server['feed']=copy.deepcopy(self.feed_results.get(server['id'],{}));items.append(server)
            return {'servers':items,'primary_id':self.config.get('primary_id') or (items[0]['id'] if items else ''),
                    'sync':copy.deepcopy(self.sync_status),'features':[{'id':k,'name':v[0]} for k,v in FEATURES.items()],
                    'connectivity':self.connectivity_snapshot(),'checked':self.health_checked,'live_results':copy.deepcopy(getattr(self,'live_results',{})),'pending_controls':copy.deepcopy(getattr(self,'control_intents',{})),'events':copy.deepcopy(getattr(self,'events',[]))[-20:],'binary_available':bool(shutil.which(os.getenv('ADGUARD_SYNC_BINARY','adguardhome-sync')))}
    def read_controls(self):
        origin=self.primary();status=self.agh('status',settings=origin);filtering=self.agh('filtering/status',settings=origin)
        result={'protection_enabled':status.get('protection_enabled'),'filtering_enabled':filtering.get('enabled'),'controls_checked_at':now_iso(),'controls_epoch':time.time()}
        with self.lock:self.health.setdefault(origin['id'],{}).update(result)
        return result
    def monitor(self,include_dns=True):
        if not self.monitor_lock.acquire(blocking=False):return
        try:
            items=[s for s in self.servers() if s.get('enabled',True)]
            def inspect(s):
                with self.lock:previous=copy.deepcopy(self.health.get(s['id'],{}))
                health={'checked_at':now_iso(),'checked_epoch':time.time(),'api_ok':False,'error':'','protection_enabled':None,'filtering_enabled':None,'last_success':previous.get('last_success')}
                for attempt in range(2):
                    try:
                        start=time.monotonic();result=self.agh('status',settings=s)
                        health.update(api_ok=True,version=result.get('version',''),protection_enabled=result.get('protection_enabled'),api_ms=round((time.monotonic()-start)*1000,1),error='',last_success=now_iso())
                        break
                    except Exception as e:
                        health['error']=error_text(e)
                        if isinstance(e,(urllib.error.HTTPError,ValueError)):break
                if health['api_ok']:
                    try:
                        filtering=self.agh('filtering/status',settings=s)
                        health['filtering_enabled']=filtering.get('enabled');health['controls_checked_at']=now_iso();health['controls_epoch']=time.time()
                        health['active_filters']=sum(bool(f.get('enabled')) for f in filtering.get('filters',[]))
                        health['native_rules']=len(filtering.get('user_rules',[]))
                        health['venguard_feed']=any(f.get('enabled') and f.get('url')==self.feed_url() for f in filtering.get('filters',[])) if self.config.get('public_url') else None
                    except Exception as e:health['filtering_error']=error_text(e)
                if include_dns:
                    health['dns']=dns_probe(s.get('dns_host',''),s.get('dns_port',53))
                    if health['dns']['ok'] is False:health['dns']=dns_probe(s.get('dns_host',''),s.get('dns_port',53))
                    health['dns'].update(checked_at=now_iso(),checked_epoch=time.time())
                else:
                    with self.lock:health['dns']=copy.deepcopy(self.health.get(s['id'],{}).get('dns',{'ok':None}))
                failed=not health['api_ok'] or health['dns']['ok'] is False
                health['checked_at']=now_iso();health['checked_epoch']=time.time()
                health['failures']=previous.get('failures',0)+1 if failed else 0
                health['state']='down' if failed and health['failures']>=3 else 'checking' if failed else 'up'
                return s['id'],health
            with ThreadPoolExecutor(max_workers=8) as pool:
                results=list(pool.map(inspect,items))
            with self.lock:
                ids={s['id'] for s in self.servers()}
                for sid,h in results:
                    if sid not in ids:continue
                    current=self.health.get(sid,{})
                    if current.get('controls_epoch',0)>h.get('controls_epoch',0):
                        for key in ('protection_enabled','filtering_enabled','controls_checked_at','controls_epoch'):h[key]=current.get(key)
                    if current.get('dns',{}).get('checked_epoch',0)>h.get('dns',{}).get('checked_epoch',0):h['dns']=current['dns']
                    self.health[sid]=h
                    self.track_connection(sid+':api',h['api_ok'],h.get('error',''),h['checked_at'],h['checked_epoch'])
                self.health_checked=now_iso()
        finally:self.monitor_lock.release()
    def monitor_worker(self):
        # This loop is independent from source downloads and synchronization jobs.
        while not self.stop.is_set():
            try:self.monitor(include_dns=False);self.poll()
            except Exception as e:
                with self.lock:self.poll_error=error_text(e)
            self.stop.wait(30)
    def publish_all(self):
        items=[s for s in self.servers() if s.get('enabled',True)]
        if not items:raise ValueError('Voeg eerst een DNS-server toe.')
        with self.agh_lock:
            rev=self.revision
            def publish(server):
                try:
                    if kind(server)=='pihole':
                        for filename,whitelist in [('pihole-block.txt',False),('pihole-allow.txt',True)]:self.ensure_feed(server,self.feed_url(filename),whitelist)
                        self.agh('filtering/refresh',{'whitelist':False,'verify_urls':[self.feed_url('pihole-block.txt'),self.feed_url('pihole-allow.txt')]},settings=server)
                    else:
                        self.ensure_feed(server,self.feed_url(),False)
                        self.agh('filtering/refresh',{'whitelist':False},settings=server)
                    return server['id'],{'ok':True,'at':now_iso(),'revision':rev,'error':''}
                except Exception as e:return server['id'],{'ok':False,'at':now_iso(),'revision':rev,'error':error_text(e)}
            with ThreadPoolExecutor(max_workers=4) as pool:results=dict(pool.map(publish,items))
            with self.lock:
                self.feed_results.update(results);ok=all(r['ok'] for r in results.values())
                self.job['sync_error']='; '.join(server['name']+': '+results[server['id']]['error'] for server in items if not results[server['id']]['ok'])
                if ok:self.job['last_sync']=now_iso();self.last_synced_revision=rev
        return {'ok':ok,'partial':not ok,'results':results,'url':self.feed_url(),'message':f"Lijst aangeboden aan {sum(r['ok'] for r in results.values())} van {len(items)} servers. Niet bereikbare servers worden later opnieuw geprobeerd."}
    def ensure_feed(self,server,url,whitelist):
        status=self.agh('filtering/status',settings=server)
        found=next((f for f in status.get('whitelist_filters' if whitelist else 'filters',[]) if f.get('url')==url),None)
        if found is None:self.agh('filtering/add_url',{'name':'VenGuard uitzonderingen' if whitelist else 'VenGuard Custom DNS','url':url,'whitelist':whitelist},settings=server)
        elif not found.get('enabled'):self.agh('filtering/set_url',{'url':url,'whitelist':whitelist,'data':{'url':url,'name':found.get('name','VenGuard'),'enabled':True}},settings=server)
    def poll_cluster_logs(self):
        items=[s for s in self.servers() if s.get('enabled',True)]
        if not items:raise ValueError('Voeg eerst een AdGuard-server toe.')
        def fetch(s):
            try:
                result=self.agh('querylog',query={'limit':1000},settings=s)
                return s['id'],[dict(r,server_id=s['id'],server_name=s['name'],collected_at=now_iso()) for r in result.get('data',[])],''
            except Exception as e:return s['id'],None,error_text(e)
        with ThreadPoolExecutor(max_workers=8) as pool:results=list(pool.map(fetch,items))
        now=time.time();errors=[]
        with self.lock:
            active_ids={s['id'] for s in items}
            for sid,rows,error in results:
                if rows is not None:self.logs_by_server[sid]=rows
                else:errors.append(sid+': '+error)
            self.logs_by_server={sid:r for sid,r in self.logs_by_server.items() if sid in active_ids}
            self.last_log=sorted([r for rows in self.logs_by_server.values() for r in rows],key=lambda r:r.get('time',''),reverse=True)[:5000]
            self.last_poll=now;self.poll_error='; '.join(errors)
            from rules import domain
            for sid,rows,error in results:
                for row in rows or []:
                    try:self.observed[domain(row.get('question',{}).get('name',''))]=now
                    except ValueError:pass
            self.observed={d:t for d,t in sorted(self.observed.items(),key=lambda x:x[1],reverse=True)[:50000] if now-t<30*86400}
            write_private(self.dir/'observed.json',self.observed)
            if self.config['mode']=='observed':self.request_build()
        return self.last_log
    def request_cluster(self,allow_dns=False):
        if allow_dns:self.allow_dns_sync=True
        self.cluster_event.set()
        with self.lock:
            if not self.sync_status['running']:self.sync_status['state']='queued'
    def backup_central(self,server,reason):
        folder=self.dir/'settings-backups';folder.mkdir(exist_ok=True)
        snapshot={'at':now_iso(),'server':server['name'],'reason':reason,'sections':{},'errors':[]}
        try:self.agh('status',settings=server)
        except Exception:
            snapshot['errors'].append('Server niet bereikbaar; geen actuele back-up beschikbaar.')
            write_private(folder/(str(time.time_ns())+'.json'),snapshot)
            return
        for key in SECTIONS:
            try:snapshot['sections'][key]=self.central_read(key,server['id'])['value']
            except Exception as e:
                snapshot['errors'].append(key)
                if isinstance(e,(urllib.error.URLError,TimeoutError)) and not isinstance(e,urllib.error.HTTPError):break
        try:snapshot['sections']['filtering']=self.agh('filtering/status',settings=server)
        except Exception:snapshot['errors'].append('filtering')
        write_private(folder/(str(time.time_ns())+'.json'),snapshot)
        for p in sorted(folder.glob('*.json'))[:-20]:p.unlink()
    def run_cluster(self,allow_dns=False):
        if not self.cluster_lock.acquire(blocking=False):return {'ok':False,'message':'Synchronisatie is al bezig.'}
        config_path=self.dir/'adguard-sync-runtime.yaml'
        try:
            with self.lock:
                options=copy.deepcopy(self.config['cluster_sync']);pid=self.config.get('primary_id') or self.primary()['id']
                self.sync_status.update(state='running',running=True,last_attempt=now_iso(),error='')
            self.record_event('Synchronisatie',pid,'started','Instellingen vergelijken en gekozen onderdelen synchroniseren.')
            if not options['enabled']:raise ValueError('Schakel centrale synchronisatie eerst in.')
            all_items=self.servers();items=[s for s in all_items if kind(s)=='adguard']
            active=[s for s in items if s.get('enabled',True)]
            if not any(s['id']==pid for s in active) or len(active)<2:
                results={sid:{'state':'success' if value.get('ok') else 'error','message':'Gedeelde VenGuard-lijst: '+('aangeboden' if value.get('ok') else value.get('error','niet bevestigd'))} for sid,value in self.feed_results.items()}
                self.sync_status.update(state='success' if results and all(r['state']=='success' for r in results.values()) else 'partial' if results else 'idle',results=results,error='Geavanceerde instellingen worden uitsluitend tussen AdGuard-servers met een AdGuard-bron gekopieerd. Pi-hole gebruikt de gedeelde lijsten en domeinregels.')
                if self.sync_status['state']=='success':self.sync_status['last_success']=now_iso()
                return {'ok':self.sync_status['state']=='success','status':copy.deepcopy(self.sync_status)}
            if not allow_dns:options['features']['dns']=False
            config=native_config(items,pid,options)
            binary=shutil.which(os.getenv('ADGUARD_SYNC_BINARY','adguardhome-sync'))
            if not binary:raise ValueError('AdGuard Sync ontbreekt. Werk het Docker-image bij met bash update.sh.')
            # Never clone an unavailable origin or silently select a new authority.
            self.agh('status',settings=self.selected(pid))
            for s in items:
                if s.get('enabled',True):self.backup_central(s,'Vóór AdGuard Sync')
            write_private(config_path,config)
            env={k:v for k,v in os.environ.items() if k in ('PATH','SSL_CERT_FILE','SSL_CERT_DIR','TZ')}
            env.update(LOG_FORMAT='json',LOG_LEVEL='info',HOME='/tmp')
            # The engine is a child process, not a second DNS proxy or Docker socket client.
            process=subprocess.Popen([binary,'run','--config',str(config_path)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,env=env)
            with self.lock:self.process=process
            try:
                # Drain incrementally to keep log memory bounded; raw upstream logs aren't saved or exposed.
                lines=[];total=0;deadline=time.monotonic()+180
                def limit_runtime():
                    if process.poll() is None:process.kill()
                guard=threading.Timer(180,limit_runtime);guard.start()
                try:
                    for line in process.stdout:
                        total+=len(line)
                        if total>8*1024*1024:process.kill();raise ValueError('AdGuard Sync produceerde te veel uitvoer.')
                        lines.append(line)
                    code=process.wait(timeout=5)
                finally:guard.cancel();process.stdout.close()
                outcomes=parse_sync_results(lines,items,pid)
                ok=code==0 and outcomes and all(r['state']=='success' for r in outcomes.values())
                with self.lock:
                    self.sync_status.update(state='success' if ok else ('partial' if any(r['state']=='success' for r in outcomes.values()) else 'error'),results=outcomes,error='' if ok else 'Niet alle replica’s zijn gesynchroniseerd. Een bronfout kan de hele ronde stoppen; bereikbaarheid is een aparte controle.')
                    if ok:self.sync_status['last_success']=now_iso()
            finally:
                if process.poll() is None:process.kill();process.wait(timeout=5)
        except Exception as e:
            with self.lock:self.sync_status.update(state='error',error=error_text(e))
        finally:
            with self.lock:
                self.process=None;self.sync_status['running']=False;self.last_cluster_attempt=time.time()
                write_private(self.dir/'cluster-status.json',self.sync_status)
            config_path.unlink(missing_ok=True);self.cluster_lock.release()
            self.record_event('Synchronisatie',self.config.get('primary_id',''),'success' if self.sync_status['state']=='success' else 'error','Ronde afgerond: '+self.sync_status['state']+'. DNS-configuratie '+('meegenomen op uitdrukkelijk verzoek.' if allow_dns else 'niet meegenomen.'))
        return {'ok':self.sync_status['state']=='success','message':'Synchronisatieronde afgerond.','status':copy.deepcopy(self.sync_status)}
    def cluster_worker(self):
        while not self.stop.is_set():
            self.cluster_event.wait(1)
            with self.lock:enabled=self.config['cluster_sync']['enabled'];minutes=self.config['cluster_sync']['interval_minutes']
            if self.cluster_event.is_set() or (enabled and time.time()-self.last_cluster_attempt>minutes*60):
                self.cluster_event.clear();allow_dns=self.allow_dns_sync;self.allow_dns_sync=False
                if self.config.get('public_url') and self.config.get('auto_sync') and (self.last_synced_revision!=self.revision or bool(self.job['sync_error'])):
                    try:self.publish_all()
                    except Exception as e:
                        with self.lock:self.job['sync_error']=error_text(e)
                if enabled:self.run_cluster(allow_dns=allow_dns)
    def central_read(self,section,sid=''):
        spec=SECTIONS.get(section)
        if not spec:raise ValueError('Onbekend instellingenonderdeel.')
        server=self.selected(sid)
        if kind(server)!='adguard':raise ValueError('Deze geavanceerde editor is voor AdGuard Home. Gebruik voor Pi-hole de gedeelde lijsten en domeinregels of Eigen beheer.')
        value=self.agh(spec['get'],settings=server)
        if spec.get('key'):value=value.get(spec['key'],[])
        if spec.get('keys'):value={k:v for k,v in value.items() if k in spec['keys']}
        return {'section':section,'name':spec['name'],'value':value,'etag':digest(value),'server_id':server['id']}
    def central_write(self,section,value,etag):
        server=self.primary();before=self.central_read(section)
        if not etag or before['etag']!=etag:raise ValueError('Instellingen zijn intussen gewijzigd. Laad opnieuw voordat je opslaat.')
        spec=SECTIONS[section]
        # Full AdGuard rules are kept separately from the conservatively parsed list sources.
        if section=='rules':
            if not isinstance(value,list) or not all(isinstance(x,str) for x in value):raise ValueError('Eigen regels moeten een lijst teksten zijn.')
            body={'rules':value}
        elif section=='clients':
            raise ValueError('Apparaatinstellingen wijzig je per apparaat via de apparaat-editor.')
        elif section=='rewrites':
            raise ValueError('Gebruik Toevoegen of Verwijderen voor een DNS-herschrijving.')
        else:
            if not isinstance(value,dict):raise ValueError('Gebruik een JSON-object.')
            if spec.get('keys') and set(value)-set(spec['keys']):raise ValueError('Onbekende of serverspecifieke DNS-velden.')
            body=value
        self.backup_central(server,'Vóór centraal wijzigen van '+section)
        self.agh(spec['set'],body,settings=server,method=spec.get('method','POST'))
        self.request_cluster(allow_dns=section in ('dns','access'))
        return {'ok':True,'message':'Opgeslagen op de bronserver. Synchronisatie naar replica’s is aangevraagd.'}
