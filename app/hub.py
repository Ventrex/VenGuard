"""Multiple independent AdGuard servers and the real AdGuardHome Sync engine.

DNS traffic never goes through VenGuard. A fixed origin is authoritative;
replicas are never promoted automatically while it is unavailable.
"""
import base64
import copy
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
    if isinstance(e,urllib.error.HTTPError):return f'Beheer-API antwoordt met HTTP {e.code}; controleer adres en inloggegevens.'
    if isinstance(e,ValueError):return str(e)
    return 'Geen verbinding of ongeldige reactie; controleer adres, poort, certificaat en netwerk.'
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def write_private(path,value):
    temp=path.with_name(path.name+'.tmp')
    with open(temp,'w',encoding='utf-8') as f:
        os.chmod(temp,0o600);json.dump(value,f,ensure_ascii=False,indent=2);f.flush();os.fsync(f.fileno())
    os.replace(temp,path)

def dns_probe(host,port=53,timeout=2):
    """A real UDP DNS probe, independent from the HTTP admin endpoint."""
    if not host:return {'ok':None,'error':'Geen DNS-IP ingesteld.','ms':None}
    try:
        address=ipaddress.ip_address(host)
        transaction=secrets.randbelow(65536)
        question=b''.join(bytes([len(p)])+p.encode('ascii') for p in ['example','org'])+b'\x00'+struct.pack('!HH',1,1)
        packet=struct.pack('!HHHHHH',transaction,0x100,1,0,0,0)+question
        start=time.monotonic()
        with socket.socket(socket.AF_INET6 if address.version==6 else socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout);sock.connect((host,int(port)));sock.send(packet);response=sock.recv(4096)
        if len(response)<12:raise ValueError('Te kort DNS-antwoord.')
        tid,flags,qd,an,ns,ar=struct.unpack('!HHHHHH',response[:12])
        if tid!=transaction or not flags&0x8000 or qd!=1:raise ValueError('Onverwacht DNS-antwoord.')
        code=flags&15
        if code not in (0,3):raise ValueError(f'DNS antwoordt met foutcode {code}.')
        return {'ok':True,'error':'','rcode':code,'ms':round((time.monotonic()-start)*1000,1)}
    except Exception as e:
        return {'ok':False,'error':str(e) if isinstance(e,ValueError) else 'Geen bruikbaar UDP DNS-antwoord binnen de timeout.','ms':None}

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
        self.last_cluster_attempt=0
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
    def hub_snapshot(self):
        with self.lock:
            items=[]
            for server in self.servers():
                server.pop('password',None)
                server['password_set']=bool(self.selected(server['id']).get('password'))
                health=copy.deepcopy(self.health.get(server['id'],{}))
                health['stale']=not health.get('checked_at') or time.time()-health.get('checked_epoch',0)>90
                server['health']=health;server['feed']=copy.deepcopy(self.feed_results.get(server['id'],{}));items.append(server)
            return {'servers':items,'primary_id':self.config.get('primary_id') or (items[0]['id'] if items else ''),
                    'sync':copy.deepcopy(self.sync_status),'features':[{'id':k,'name':v[0]} for k,v in FEATURES.items()],
                    'checked':self.health_checked,'binary_available':bool(shutil.which(os.getenv('ADGUARD_SYNC_BINARY','adguardhome-sync')))}
    def monitor(self):
        if not self.monitor_lock.acquire(blocking=False):return
        try:
            items=[s for s in self.servers() if s.get('enabled',True)]
            def inspect(s):
                health={'checked_at':now_iso(),'checked_epoch':time.time(),'api_ok':False,'error':'','protection_enabled':None}
                try:
                    start=time.monotonic();result=self.agh('status',settings=s)
                    health.update(api_ok=True,version=result.get('version',''),protection_enabled=result.get('protection_enabled'),api_ms=round((time.monotonic()-start)*1000,1))
                except Exception as e:health['error']=error_text(e)
                health['dns']=dns_probe(s.get('dns_host',''),s.get('dns_port',53))
                return s['id'],health
            with ThreadPoolExecutor(max_workers=8) as pool:
                results=list(pool.map(inspect,items))
            with self.lock:
                ids={s['id'] for s in self.servers()};self.health.update({sid:h for sid,h in results if sid in ids});self.health_checked=now_iso()
        finally:self.monitor_lock.release()
    def monitor_worker(self):
        # This loop is independent from source downloads and synchronization jobs.
        while not self.stop.is_set():
            try:self.monitor();self.poll()
            except Exception as e:
                with self.lock:self.poll_error=error_text(e)
            self.stop.wait(30)
    def publish_all(self):
        url=self.feed_url();items=[s for s in self.servers() if s.get('enabled',True)]
        if not items:raise ValueError('Voeg eerst een AdGuard-server toe.')
        with self.agh_lock:
            rev=self.revision
            def publish(s):
                try:
                    status=self.agh('filtering/status',settings=s)
                    found=next((f for f in status.get('filters',[]) if f.get('url')==url),None)
                    if found is None:self.agh('filtering/add_url',{'name':'VenGuard Custom DNS','url':url,'whitelist':False},settings=s)
                    elif not found.get('enabled'):
                        self.agh('filtering/set_url',{'url':url,'whitelist':False,'data':{'url':url,'name':found.get('name','VenGuard Custom DNS'),'enabled':True}},settings=s)
                    self.agh('filtering/refresh',{'whitelist':False},settings=s)
                    return s['id'],{'ok':True,'at':now_iso(),'revision':rev,'error':''}
                except Exception as e:return s['id'],{'ok':False,'at':now_iso(),'revision':rev,'error':error_text(e)}
            with ThreadPoolExecutor(max_workers=8) as pool:results=dict(pool.map(publish,items))
            with self.lock:
                self.feed_results.update(results);ok=all(r['ok'] for r in results.values())
                self.job['sync_error']='; '.join(s['name']+': '+results[s['id']]['error'] for s in items if not results[s['id']]['ok'])
                if ok:self.job['last_sync']=now_iso();self.last_synced_revision=rev
        return {'ok':ok,'partial':not ok,'results':results,'url':url,'message':f"Lijst aangeboden aan {sum(r['ok'] for r in results.values())} van {len(items)} servers. Offline servers worden later opnieuw geprobeerd."}
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
    def request_cluster(self):
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
    def run_cluster(self):
        if not self.cluster_lock.acquire(blocking=False):return {'ok':False,'message':'Synchronisatie is al bezig.'}
        config_path=self.dir/'adguard-sync-runtime.yaml'
        try:
            with self.lock:
                options=copy.deepcopy(self.config['cluster_sync']);pid=self.config.get('primary_id') or self.primary()['id']
                self.sync_status.update(state='running',running=True,last_attempt=now_iso(),error='')
            if not options['enabled']:raise ValueError('Schakel centrale synchronisatie eerst in.')
            items=self.servers();config=native_config(items,pid,options)
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
        return {'ok':self.sync_status['state']=='success','message':'Synchronisatieronde afgerond.','status':copy.deepcopy(self.sync_status)}
    def cluster_worker(self):
        while not self.stop.is_set():
            self.cluster_event.wait(1)
            with self.lock:enabled=self.config['cluster_sync']['enabled'];minutes=self.config['cluster_sync']['interval_minutes']
            if self.cluster_event.is_set() or (enabled and time.time()-self.last_cluster_attempt>minutes*60):
                self.cluster_event.clear()
                if self.config.get('public_url') and self.config.get('auto_sync'):
                    try:self.publish_all()
                    except Exception as e:
                        with self.lock:self.job['sync_error']=error_text(e)
                if enabled:self.run_cluster()
    def central_read(self,section,sid=''):
        spec=SECTIONS.get(section)
        if not spec:raise ValueError('Onbekend instellingenonderdeel.')
        server=self.selected(sid);value=self.agh(spec['get'],settings=server)
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
        self.request_cluster()
        return {'ok':True,'message':'Opgeslagen op de bronserver. Synchronisatie naar replica’s is aangevraagd.'}
