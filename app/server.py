#!/usr/bin/env python3
"""VenGuard: self-hosted DNS list workbench. Python standard library only."""
import base64
import copy
import hashlib
import hmac
import http.cookies
import ipaddress
import json
import logging
import os
import secrets
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from rules import domain, scope, parse_list, explain, compose, PACKS, rule_text
from catalog import CATEGORIES, PRESETS
from accounts import AccountMixin
from providers import PiHole,kind
from operations import OperationsMixin
from migrations import migrate
from security import SecurityMixin,BoundedHTTPServer
from hub import HubMixin, SECTIONS, FEATURES, HUB_DEFAULT, write_private, error_text

ROOT=Path(__file__).parent
MAX_DOWNLOAD=24*1024*1024

def utc(): return datetime.now(timezone.utc).isoformat(timespec='seconds')
def atomic(path, data):
    temp=path.with_name(path.name+'.tmp')
    with open(temp,'w',encoding='utf-8') as f:
        os.chmod(temp,0o600); f.write(data); f.flush(); os.fsync(f.fileno())
    os.replace(temp,path)

def read_json(path,default):
    if not path.exists(): return copy.deepcopy(default)
    return json.loads(path.read_text())

def valid_url(value,public=False):
    if not isinstance(value,str) or len(value)>2000: raise ValueError('Ongeldige URL.')
    p=urllib.parse.urlsplit(value.strip())
    if p.query or any(ord(c)<32 for c in value): raise ValueError('Gebruik een URL zonder queryparameters of besturingstekens.')
    if p.scheme not in (('https',) if public else ('http','https')) or not p.hostname or p.username or p.password or p.fragment:
        raise ValueError('Gebruik een volledige '+('https://' if public else 'http:// of https://')+' URL zonder inloggegevens of fragment.')
    if public:
        addresses=socket.getaddrinfo(p.hostname,p.port or 443,type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
            raise ValueError('Externe filterbronnen moeten een publiek HTTPS-adres gebruiken.')
    return urllib.parse.urlunsplit(p).rstrip('/')

class PublicRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        valid_url(newurl,public=True)
        return super().redirect_request(req,fp,code,msg,headers,newurl)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None

def download(url):
    valid_url(url,public=True)
    request=urllib.request.Request(url,headers={'User-Agent':'VenGuard/1.0 (+local DNS list merger)'})
    with urllib.request.build_opener(PublicRedirect()).open(request,timeout=25) as response:
        data=response.read(MAX_DOWNLOAD+1)
        if len(data)>MAX_DOWNLOAD: raise ValueError('Bron groter dan 24 MiB; kies een kleinere DNS-lijst.')
        text=data.decode('utf-8-sig',errors='replace')
        if text.lstrip().lower().startswith(('<!doctype html','<html')): raise ValueError('Deze URL levert een webpagina in plaats van een filterlijst.')
        return text

def safe_network_error(error):return error_text(error)

DEFAULT={
 'version':1,'mode':'all','public_url':'','auto_refresh_hours':24,'auto_sync':True,
 'packs':{p['id']:p['enabled'] for p in PACKS},
 'sources':[{'id':'hagezi-light','name':'HaGeZi Light — rustige basis','url':'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt','enabled':True}],
 'rules':[], 'adguard':{'url':'','username':'','password':''}
}

from connectivity import ConnectivityMixin
from management import ManagementMixin
from network import NetworkMixin

class Store(HubMixin,AccountMixin,OperationsMixin,SecurityMixin,ConnectivityMixin,ManagementMixin,NetworkMixin):
    def __init__(self,directory):
        self.dir=Path(directory); self.dir.mkdir(parents=True,exist_ok=True)
        self.lock=threading.RLock(); self.agh_lock=threading.Lock()
        self.config=read_json(self.dir/'config.json',DEFAULT)
        self.config.setdefault('categories',{k:True for k in CATEGORIES})
        migrate(self.config)
        self.config['direct_rules']=True
        self.pihole=PiHole()
        for source in self.config['sources']:source.setdefault('category','ads' if 'hagezi' in source.get('id','') else 'custom')
        self.observed=read_json(self.dir/'observed.json',{})
        self.caches=read_json(self.dir/'cache.json',{})
        self.feed_token=self.secret('feed-token')
        self.password=os.getenv('VENGUARD_PASSWORD','') or self.secret('admin-password')
        self.sessions={}; self.attempts={}; self.event=threading.Event(); self.stop=threading.Event()
        self.fetch_requested=False; self.job={'running':False,'error':'','last_build':None,'last_sync':None,'sync_error':''}
        self.report=read_json(self.dir/'report.json',{'count':0,'sources':[],'built':None,'added':0,'removed':0})
        self.origins={}; self.last_log=[]; self.last_poll=0; self.poll_error=''; self.last_refresh=0
        self.revision=0; self.last_synced_revision=-1
        self.init_hub();self.init_accounts();self.init_operations();self.init_security();self.init_connectivity();self.init_management();self.init_network()
        self.save()
        if not (self.dir/'filter.txt').exists():
            lines,_,_=compose(self.config,self.caches,self.observed)
            atomic(self.dir/'filter.txt',self.feed_text(lines))
        self.request_build(fetch=not bool(self.caches))
    def secret(self,name):
        path=self.dir/name
        if path.exists(): return path.read_text().strip()
        value=secrets.token_urlsafe(32); atomic(path,value); return value
    def save(self):
        atomic(self.dir/'config.json',json.dumps(self.config,ensure_ascii=False,indent=2))
    def changed(self):
        self.revision+=1; self.save(); self.request_build()
        if hasattr(self,'network'):self.write_scanner_config()
    def request_build(self,fetch=False):
        with self.lock:
            self.fetch_requested |= fetch; self.event.set()
    def feed_text(self,lines):
        return '! Title: VenGuard Custom DNS\n! Generated: '+utc()+'\n! DNS-only; source licenses apply. See the VenGuard dashboard.\n'+'\n'.join(lines)+'\n'
    def agh(self,path,body=None,query=None,settings=None,method=None):
        with self.lock: cfg=copy.deepcopy(settings or (self.primary() if self.config.get('servers') else self.config['adguard']))
        if kind(cfg)=='pihole':return self.pihole.adapter(cfg,path,body,query,method)
        if not cfg.get('url'): raise ValueError('Koppel eerst AdGuard Home bij Instellingen.')
        url=valid_url(cfg['url'])
        if url.endswith('/control'): url=url[:-8]
        target=url+'/control/'+path
        if query: target+='?'+urllib.parse.urlencode(query)
        headers={'Accept':'application/json','User-Agent':'VenGuard/1.0'}
        if cfg.get('username') or cfg.get('password'):
            token=base64.b64encode((cfg.get('username','')+':'+cfg.get('password','')).encode()).decode()
            headers['Authorization']='Basic '+token
        data=None if body is None else json.dumps(body).encode()
        if data is not None: headers['Content-Type']='application/json'
        req=urllib.request.Request(target,data=data,headers=headers,method=method)
        with urllib.request.build_opener(NoRedirect()).open(req,timeout=12) as response:
            raw=response.read(16*1024*1024+1)
            if len(raw)>16*1024*1024: raise ValueError('AdGuard-antwoord te groot.')
            if not raw.strip():
                if body is not None or method in ('POST','PUT','DELETE'):return {}
                raise ValueError('AdGuard gaf geen JSON terug; controleer de beheer-URL en poort.')
            if (body is not None or method in ('POST','PUT','DELETE')) and raw.strip() in (b'OK',b'Ok',b'ok'): return {}
            try:
                value=json.loads(raw)
                # Fresh AdGuard instances serialize empty collections as null.
                if path=='filtering/status' and isinstance(value,dict):
                    for key in ('filters','whitelist_filters','user_rules'):
                        if value.get(key) is None:value[key]=[]
                if path=='clients' and isinstance(value,dict) and value.get('clients') is None:value['clients']=[]
                if path=='rewrite/list' and value is None:value=[]
                return value
            except json.JSONDecodeError: raise ValueError('AdGuard gaf geen JSON terug; controleer de beheer-URL en poort.')
    def feed_url(self,filename="filter.txt"):
        with self.lock: base=self.config['public_url']
        if not base: raise ValueError('Vul bij Instellingen het LAN-adres van VenGuard in, bijvoorbeeld http://192.168.0.10:8098.')
        return base+'/lists/'+self.feed_token+'/'+filename
    def sync(self):
        result=self.publish_all()
        return result
    def poll(self):
        return self.poll_cluster_logs()
    def rebuild(self,fetch=False):
        with self.lock:
            self.job.update(running=True,error=''); config=copy.deepcopy(self.config); rev=self.revision
        source_ids={s['id'] for s in config['sources']}
        caches={k:v for k,v in self.caches.items() if k in source_ids}
        if fetch:
            for source in config['sources']:
                if not source['enabled']: continue
                sid=source['id']
                try:
                    text=download(source['url']); rules,counts,examples=parse_list(text)
                    if not rules: raise ValueError('Geen ondersteunde DNS-regels gevonden. Bestaande cache blijft behouden.')
                    if len(rules)+sum(len(v.get('rules',[])) for k,v in caches.items() if k!=sid)>1000000:
                        raise ValueError('Samen meer dan 1 miljoen bronregels. Verwijder een overlappende bron; vorige cache blijft behouden.')
                    previous=caches.get(sid,{})
                    if len(previous.get('rules',[]))>=1000 and len(rules)<len(previous['rules'])*.2:raise ValueError('Bron is meer dan 80% gekrompen. De laatste goede bron blijft actief; controleer de bron-URL.')
                    caches[sid]={'rules':rules,'counts':counts,'examples':examples,'fetched':utc(),'error':''}
                except Exception as e:
                    caches[sid]={**caches.get(sid,{}),'error':safe_network_error(e)}
        with self.lock:
            # Don't publish a stale snapshot if the user edited while downloading.
            if self.revision!=rev:
                self.event.set(); self.job['running']=False
                for s in config['sources']:
                    current=next((x for x in self.config['sources'] if x['id']==s['id'] and x['url']==s['url']),None)
                    if current and s['id'] in caches: self.caches[s['id']]=caches[s['id']]
                atomic(self.dir/'cache.json',json.dumps(self.caches)); return
            self.caches=caches
            lines,stats,origins=compose(config,caches,self.observed)
            old=set(l for l in (self.dir/'filter.txt').read_text().splitlines() if l and not l.startswith('!'))
            if len(old)>=1000 and any(source['enabled'] and config.get('categories',{}).get(source.get('category','custom'),True) and not caches.get(source['id'],{}).get('rules') for source in config['sources']):raise ValueError('Een actieve bron ontbreekt. De vorige gepubliceerde lijst blijft behouden.')
            changed=set(lines)!=old
            previous=self.dir/'filter.txt'
            backups=self.dir/'backups'; backups.mkdir(exist_ok=True)
            # A short local history for recovery; credentials never enter these files.
            if changed and previous.exists():
                atomic(backups/(str(time.time_ns())+'.txt'),previous.read_text())
                for file in sorted(backups.glob('*.txt'))[:-10]: file.unlink()
            if changed or not previous.exists(): atomic(previous,self.feed_text(lines))
            self.origins=origins
            self.report={'count':len(lines),'sources':stats,'built':utc(),'added':len(set(lines)-old),'removed':len(old-set(lines)),'mode':config['mode'],'observed':len(self.observed),'duplicates':sum(x.get('duplicates',0) for x in stats)}
            atomic(self.dir/'cache.json',json.dumps(caches)); atomic(self.dir/'report.json',json.dumps(self.report,ensure_ascii=False))
            self.job.update(running=False,last_build=utc())
            sync=config.get('auto_sync',False) and bool(config['public_url']) and bool(config['adguard']['url']) and (changed or self.last_synced_revision!=rev or bool(self.job['sync_error']))
        if sync:
            try: self.sync()
            except Exception as e:
                with self.lock: self.job['sync_error']=safe_network_error(e)
    def worker(self):
        while not self.stop.is_set():
            signaled=self.event.wait(1)
            now=time.time()
            if signaled:
                with self.lock: self.event.clear(); fetch=self.fetch_requested; self.fetch_requested=False
                try: self.rebuild(fetch)
                except Exception as error:
                    logging.exception('List build failed')
                    with self.lock: self.job.update(running=False,error=error_text(error) if isinstance(error,ValueError) else 'Lijst opbouwen mislukt. De laatst gepubliceerde lijst blijft beschikbaar.')
                if fetch: self.last_refresh=now
            with self.lock:
                hours=self.config['auto_refresh_hours']
            if now-self.last_refresh>hours*3600:
                self.last_refresh=now; self.request_build(fetch=True)
    def snapshot(self):
        with self.lock:
            config=copy.deepcopy(self.config)
            config['adguard']['password_set']=bool(config['adguard'].pop('password',''))
            for server in config.get('servers',[]):
                server['password_set']=bool(server.pop('password',''))
            return {'config':config,'packs':PACKS,'categories':CATEGORIES,'presets':PRESETS,'report':copy.deepcopy(self.report),'job':dict(self.job),'observed':len(self.observed),'poll_error':self.poll_error,'last_poll':self.last_poll or None,'feed_url':self.feed_url() if config['public_url'] else '', 'feed_path':'/lists/'+self.feed_token+'/filter.txt','version':'2.0.0','hub':self.hub_snapshot(),'management':self.management_snapshot(),'network':self.network_snapshot()}

class Handler(BaseHTTPRequestHandler):
    server_version='VenGuard'
    def log_message(self,fmt,*args):
        # List URLs contain a token; no URLs, credentials or query logs in stdout.
        pass
    @property
    def store(self): return self.server.store
    def respond(self,data,status=200,ctype='application/json',headers=None):
        raw=json.dumps(data,ensure_ascii=False).encode() if ctype=='application/json' else (data.encode() if isinstance(data,str) else data)
        self.send_response(status)
        self.send_header('Content-Type',ctype+('; charset=utf-8' if ctype.startswith('text/') or ctype=='application/json' else ''))
        self.send_header('Content-Length',str(len(raw))); self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        if headers:
            for k,v in headers.items(): self.send_header(k,v)
        self.end_headers(); self.wfile.write(raw)
    def auth(self):
        try:
            cookie=http.cookies.SimpleCookie(self.headers.get('Cookie','')); value=cookie['vg_session'].value
            with self.store.lock:
                expires=self.store.sessions.get(value,0)
                if expires<time.time(): self.store.sessions.pop(value,None); return False
                return True
        except (KeyError,http.cookies.CookieError): return False
    def body(self):
        try: length=int(self.headers.get('Content-Length','0'))
        except ValueError: raise ValueError('Ongeldige aanvraag.')
        if length<0 or length>512*1024: raise ValueError('Aanvraag te groot (maximaal 512 KiB).')
        try: value=json.loads(self.rfile.read(length) or b'{}')
        except (ValueError,UnicodeDecodeError): raise ValueError('Ongeldige JSON.')
        if not isinstance(value,dict): raise ValueError('Verwacht een JSON-object.')
        return value
    def do_GET(self):
        try: self.get()
        except (BrokenPipeError,ConnectionResetError): pass
        except Exception as e: self.respond({'error':safe_network_error(e)},400)
    def get(self):
        parsed=urllib.parse.urlsplit(self.path); path=parsed.path
        q={k:v[0] for k,v in urllib.parse.parse_qs(parsed.query).items()}
        if path.startswith('/api/'):
            ip=self.store.security_ip(self.client_address[0],self.headers.get('X-Forwarded-For',''))
            if not self.store.request_allowed(ip):return self.respond({'error':'Te veel beheeropdrachten; probeer over een minuut opnieuw.'},429,headers={'Retry-After':'60'})
        if path=='/health': return self.respond({'ok':True})
        if path.startswith('/lists/'):
            filename=path.rsplit('/',1)[-1];expected='/lists/'+self.store.feed_token+'/'+filename
            if filename not in ('filter.txt','pihole-block.txt','pihole-allow.txt') or not hmac.compare_digest(path,expected):return self.respond({'error':'Niet gevonden.'},404)
            raw=(self.store.dir/'filter.txt').read_text()
            if filename!='filter.txt':
                prefix='@@||' if filename=='pihole-allow.txt' else '||'
                raw='# VenGuard DNS subscription\n'+'\n'.join(line for line in raw.splitlines() if line.startswith(prefix) and '$' not in line)+'\n'
            return self.respond(raw,ctype='text/plain')
        if path=='/api/session': return self.respond({'authenticated':self.auth(),'account_configured':bool(self.store.account),'two_factor':bool((self.store.account or {}).get('totp_secret'))})
        if path.startswith('/api/'):
            if not self.auth(): return self.respond({'error':'Log eerst in.'},401)
            if path=='/api/state': return self.respond(self.store.snapshot())
            if path=='/api/network':return self.respond(self.store.network_snapshot())
            if path=='/api/profile':return self.respond(self.store.management_snapshot())
            if path=='/api/profile/section':return self.respond(self.store.desired_read(q.get('section','dns')))
            if path=='/api/connectivity':return self.respond(self.store.connectivity_snapshot())
            if path=='/api/connectivity/export':return self.respond(self.store.connectivity_snapshot(report=True),headers={'Content-Disposition':'attachment; filename="VenGuard-storingsrapport.json"'})
            if path=='/api/security':return self.respond(self.store.security_snapshot())
            if path=='/api/events':return self.respond({'events':copy.deepcopy(self.store.events),'rules':copy.deepcopy(self.store.live_results),'pending':copy.deepcopy(self.store.control_intents)})
            if path=='/api/account': return self.respond(self.store.account_public())
            if path=='/api/central-controls': return self.respond(self.store.read_controls())
            if path=='/api/central-filters': return self.respond(self.store.desired_filters() if self.store.desired['captured'] else self.store.agh('filtering/status',settings=self.store.primary()))
            if path=='/api/hub': return self.respond(self.store.hub_snapshot())
            if path=='/api/central': return self.respond(self.store.central_read(q.get('section','rules'),q.get('server','')))
            if path=='/api/log':
                with self.store.lock: rows=copy.deepcopy(self.store.last_log); error=self.store.poll_error
                search=q.get('search','').lower(); selected=q.get('status','all'); client=q.get('client',''); output=[];hidden_tests=0
                for row in rows:
                    d=row.get('question',{}).get('name',''); reason=row.get('reason',''); category='blocked' if reason.startswith('Filtered') and reason!='FilteredSafeSearch' else ('rewritten' if reason.startswith('Rewrite') or reason=='FilteredSafeSearch' else ('error' if reason=='NotFilteredError' or row.get('status') not in ('NOERROR','NXDOMAIN') else ('allowed' if row.get('status')=='NOERROR' else 'other')))
                    if d.rstrip('.').lower()=='example.org' and q.get('tests')!='1':hidden_tests+=1;continue
                    if search and search not in (d+' '+row.get('client','')+' '+row.get('client_info',{}).get('name','')).lower(): continue
                    if selected!='all' and selected!=category: continue
                    if client and row.get('client')!=client: continue
                    if q.get('server') and row.get('server_id')!=q['server']: continue
                    annotation=explain(d)
                    with self.store.lock:
                        custom=[r for r in self.store.config['rules'] if d==r['domain'] or (r.get('match','suffix')=='suffix' and d.endswith('.'+r['domain']))]
                    output.append({**row,'classification':annotation,'outcome':category,'custom':custom})
                return self.respond({'hidden_tests':hidden_tests,'data':output,'count_sample':len(rows),'last_poll':self.store.last_poll,'error':error,'limit':1000,'servers':len(self.store.servers())})
            if path=='/api/check':
                d=domain(q.get('domain','')); result=self.store.agh('filtering/check_host',query={'name':d,'client':q.get('client',''),'qtype':q.get('type','A')},settings=self.store.selected(q.get('server','')))
                return self.respond({'domain':d,'adguard':result,'explanation':explain(d),'note':'Dit is een actuele AdGuard-regelcontrole, geen DNS-verzoek vanaf je iPhone.'})
            if path=='/api/diagnostics':
                server=self.store.selected(q.get('server',''))
                return self.respond({'status':self.store.agh('status',settings=server),'filtering':self.store.agh('filtering/status',settings=server),'clients':self.store.agh('clients',settings=server) if kind(server)=='adguard' else {'clients':[],'unsupported':True}})
            if path=='/api/export':
                with self.store.lock:
                    config=copy.deepcopy(self.store.config); config['adguard']={'url':config['adguard']['url'],'username':'','password':''}
                    for server in config.get('servers',[]):
                        server['password']='';server['username']=''
                return self.respond(config,headers={'Content-Disposition':'attachment; filename="VenGuard-instellingen.json"'})
            if path=='/api/preview':
                with self.store.lock:
                    lines=(self.store.dir/'filter.txt').read_text().splitlines()
                search=q.get('search','').lower()
                filtered=[l for l in lines if not l.startswith('!') and (not search or search in l.lower())]
                offset=max(0,min(int(q.get('offset',0)),1000000))
                return self.respond({'lines':filtered[offset:offset+100],'total':len(filtered),'offset':offset})
            return self.respond({'error':'Niet gevonden.'},404)
        files={'/':'index.html','/app.js':'app.js','/style.css':'style.css','/hub.js':'hub.js','/theme.js':'theme.js','/account.js':'account.js','/filters.js':'filters.js','/security.js':'security.js','/simple.js':'simple.js','/workspace.js':'workspace.js'}
        if path not in files: return self.respond({'error':'Niet gevonden.'},404)
        file=ROOT/'static'/files[path]
        return self.respond(file.read_bytes(),ctype={'html':'text/html','js':'text/javascript','css':'text/css'}[file.suffix[1:]])
    def do_POST(self):
        try:
            origin=self.headers.get('Origin')
            if origin and urllib.parse.urlsplit(origin).netloc!=self.headers.get('Host'):
                return self.respond({'error':'Ongeldige herkomst.'},403)
            if self.headers.get('X-VenGuard')!='1': return self.respond({'error':'Ontbrekende aanvraagbeveiliging.'},403)
            path=urllib.parse.urlsplit(self.path).path
            ip=self.store.security_ip(self.client_address[0],self.headers.get('X-Forwarded-For',''))
            if not self.store.request_allowed(ip):return self.respond({'error':'Te veel beheeropdrachten; probeer over een minuut opnieuw.'},429,headers={'Retry-After':'60'})
            body=self.body()
            if path.startswith('/api/central'):
                if not self.store.cluster_lock.acquire(blocking=False):return self.respond({'error':'Synchronisatie is bezig; probeer de wijziging daarna opnieuw.'},409)
                try:self.post(path,body)
                finally:self.store.cluster_lock.release()
            else:self.post(path,body)
        except (BrokenPipeError,ConnectionResetError): pass
        except Exception as e: self.respond({'error':safe_network_error(e)},400)
    def post(self,path,data):
        s=self.store
        if path=='/api/network/report':
            try:return self.respond(s.scanner_report(data,self.headers.get('X-VenGuard-Agent','')))
            except PermissionError:return self.respond({'error':'Ongeldige scanneragent.'},403)
        if path=='/api/login':
            ip=s.security_ip(self.client_address[0],self.headers.get('X-Forwarded-For','')); now=time.time()
            with s.lock:
                history=[t for t in s.attempts.get(ip,[]) if now-t<300]
                s.attempts={k:v for k,v in s.attempts.items() if v and now-v[-1]<300}
                if len(history)>=10:
                    return self.respond({'error':'Te veel pogingen. Wacht vijf minuten.'},429,headers={'Retry-After':'300'})
                if not s.login_owner(data):
                    s.attempts[ip]=history+[now];s.security_event('login_failed',ip,'Mislukte aanmelding bij VenGuard.');return self.respond({'error':'Onjuiste inloggegevens of 2FA-code. Een code is eenmalig bruikbaar.'},401)
                token=secrets.token_urlsafe(32); s.sessions={k:v for k,v in s.sessions.items() if v>now}; s.sessions[token]=now+12*3600; s.attempts.pop(ip,None)
            s.security_event('login_success',ip,'Geslaagde aanmelding bij VenGuard.')
            secure='; Secure' if self.headers.get('X-Forwarded-Proto')=='https' else ''
            return self.respond({'ok':True},headers={'Set-Cookie':f'vg_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200'+secure})
        if not self.auth(): return self.respond({'error':'Log eerst in.'},401)
        if path=='/api/network/settings':return self.respond(s.network_settings(data))
        if path=='/api/network/device':return self.respond(s.network_device(data))
        if path=='/api/network/audit':return self.respond(s.request_audit(data))
        if path=='/api/profile':
            if data.get('action')=='adopt':return self.respond(s.adopt_server(data.get('server','')))
            if data.get('action')=='apply':s.management_event.set();return self.respond({'ok':True,'message':'Centraal profiel wordt naar de servers gestuurd.'})
            return self.respond(s.desired_write(data.get('section','dns'),data.get('value'),data.get('etag','')))
        if path=='/api/security':return self.respond(s.save_security(data))
        if path=='/api/security/check':return self.respond(s.poll_wazuh())
        if path=='/api/account':
            cookie=http.cookies.SimpleCookie(self.headers.get('Cookie',''));token=cookie['vg_session'].value
            return self.respond(s.account_action(data,token))
        if path=='/api/logout':
            cookie=http.cookies.SimpleCookie(self.headers.get('Cookie',''))
            with s.lock:
                if 'vg_session' in cookie: s.sessions.pop(cookie['vg_session'].value,None)
            return self.respond({'ok':True},headers={'Set-Cookie':'vg_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'})
        if path=='/api/servers':
            with s.lock:
                if s.sync_status['running']:raise ValueError('Wacht tot de synchronisatie is afgerond.')
                items=copy.deepcopy(s.config['servers']);action=data.get('action','save');sid=data.get('id','')
                current=next((x for x in items if x['id']==sid),None)
                if action=='delete':
                    if not current:raise ValueError('Server niet gevonden.')
                    if current['id']==s.config['primary_id'] and not s.desired['captured']:raise ValueError('Kies eerst een andere bronserver voordat je deze verwijdert.')
                    items.remove(current)
                    if current['id']==s.config['primary_id']:s.config['primary_id']=items[0]['id'] if items else ''
                    if not items:s.config['adguard']={'url':'','username':'','password':''}
                elif action=='primary':
                    if not current or not current.get('enabled',True):raise ValueError('Kies een ingeschakelde server.')
                    if s.sync_status['running']:raise ValueError('Wacht tot de synchronisatie is afgerond.')
                    s.config['primary_id']=sid
                elif action=='save':
                    if current is None:
                        if len(items)>=10:raise ValueError('Maximaal 10 DNS-servers.')
                        current={'id':secrets.token_hex(6),'password':''};items.append(current)
                    previous_type=current.get('type','adguard');server_type=data.get('type',previous_type)
                    if server_type not in ('adguard','pihole'):raise ValueError('Kies AdGuard Home of Pi-hole v6.')
                    url=valid_url(data.get('url',''))
                    if any(x['id']!=current['id'] and x['url'].removesuffix('/control')==url.removesuffix('/control') for x in items):raise ValueError('Dit AdGuard-adres staat al in de lijst.')
                    dns_host=str(data.get('dns_host','')).strip()
                    if dns_host:ipaddress.ip_address(dns_host)
                    port=int(data.get('dns_port',53))
                    if not 1<=port<=65535:raise ValueError('Ongeldige DNS-poort.')
                    enabled=bool(data.get('enabled',True))
                    if current['id']==s.config['primary_id'] and not enabled and not s.desired['captured']:raise ValueError('Kies eerst een andere bronserver voordat je deze uitschakelt.')
                    current.update(type=server_type,name=str(data.get('name') or ('Pi-hole' if server_type=='pihole' else 'AdGuard'))[:100],url=url,username=str(data.get('username',''))[:200],dns_host=dns_host,dns_port=port,enabled=enabled)
                    if previous_type!=server_type and not data.get('password'):current['password']=''
                    if data.get('password'):current['password']=str(data['password'])
                    if data.get('clear_password'):current['password']=''
                    if not s.config['primary_id']:s.config['primary_id']=current['id']
                else:raise ValueError('Onbekende serveractie.')
                if s.sync_status['running']:raise ValueError('Wacht tot de synchronisatie is afgerond voordat je servers wijzigt.')
                s.config['servers']=items;s.align_primary();s.changed();s.last_cluster_attempt=0
                s.rules_pending=True
                s.management_event.set();s.health.pop(sid,None);s.sync_status['results']={};s.sync_status['state']='queued' if s.config['cluster_sync']['enabled'] else 'idle'
            return self.respond({'ok':True})
        if path=='/api/hub/check':
            s.request_connectivity()
            threading.Thread(target=s.monitor,kwargs={'include_dns':False},daemon=True).start()
            return self.respond({'ok':True,'message':'Nieuwe controle gestart. Resultaten verschijnen automatisch.','hub':s.hub_snapshot()})
        if path=='/api/connectivity/check':return self.respond(s.request_connectivity())
        if path=='/api/cluster-settings':
            with s.lock:
                options=copy.deepcopy(s.config['cluster_sync'])
                if 'enabled' in data:options['enabled']=bool(data['enabled'])
                if 'interval_minutes' in data:
                    minutes=int(data['interval_minutes'])
                    if minutes not in (1,5,15,30,60):raise ValueError('Kies 1, 5, 15, 30 of 60 minuten.')
                    options['interval_minutes']=minutes
                if 'features' in data:options['features']={key:bool(data['features'].get(key,False)) for key in FEATURES}
                if s.sync_status['running']:raise ValueError('Wacht tot de synchronisatie is afgerond.')
                if options['enabled']:
                    active=[x for x in s.servers() if x.get('enabled',True)]
                    if len(active)<2:raise ValueError('Voeg minimaal twee ingeschakelde servers toe.')
                    if not any(options['features'].values()):raise ValueError('Kies minimaal één te synchroniseren onderdeel.')
                s.config['cluster_sync']=options;s.save();s.last_cluster_attempt=0;s.sync_status['results']={}
                if options['enabled']:s.request_cluster()
                else:s.sync_status.update(state='disabled',error='')
            return self.respond({'ok':True})
        if path=='/api/cluster-sync':
            if not s.config['cluster_sync']['enabled']:raise ValueError('Schakel centrale synchronisatie eerst in bij Servers & Sync.')
            s.request_cluster(allow_dns=True);return self.respond({'ok':True,'message':'Synchronisatie naar alle ingeschakelde replica’s is aangevraagd.'})
        if path=='/api/central':return self.respond(s.central_write(data.get('section',''),data.get('value'),data.get('etag','')))
        if path in ('/api/central-protection','/api/central-filtering'):
            return self.respond(s.desired_controls('protection' if path.endswith('protection') else 'filtering',data.get('enabled')))
        if path=='/api/central-filters':
            if s.desired['captured']:return self.respond(s.desired_filter_action(data))
            origin=s.primary();status=s.agh('filtering/status',settings=origin);action=data.get('action')
            if action=='refresh':
                s.agh('filtering/refresh',{'whitelist':False},settings=origin)
                if kind(origin)=='adguard':s.agh('filtering/refresh',{'whitelist':True},settings=origin)
            elif action in ('toggle','delete'):
                whitelist=bool(data.get('whitelist'));items=status.get('whitelist_filters' if whitelist else 'filters',[])
                item=next((f for f in items if f.get('url')==data.get('url')),None)
                if not item:raise ValueError('Lijst gewijzigd of niet gevonden; laad opnieuw.')
                if '/lists/'+s.feed_token+'/' in item['url']:raise ValueError('Beheer de VenGuard-lijst via Mijn filterlijst; wijzig hier alleen je overige AdGuard-lijsten.')
                s.backup_central(origin,'Vóór filterlijst wijzigen')
                if action=='delete':s.agh('filtering/remove_url',{'url':item['url'],'whitelist':whitelist},settings=origin)
                else:s.agh('filtering/set_url',{'url':item['url'],'whitelist':whitelist,'data':{'name':item.get('name',''),'url':item['url'],'enabled':bool(data.get('enabled'))}},settings=origin)
            else:raise ValueError('Ongeldige lijstactie.')
            s.request_cluster();return self.respond({'ok':True})
        if path=='/api/central-rewrite':
            if s.desired['captured']:return self.respond(s.desired_collection('rewrites',data))
            origin=s.primary();action=data.get('action')
            if action not in ('add','delete'):raise ValueError('Ongeldige actie.')
            host=str(data.get('domain','')).strip();answer=str(data.get('answer','')).strip()
            if not host or not answer or len(host)>253 or len(answer)>253:raise ValueError('Vul domein en antwoord in.')
            s.backup_central(origin,'Vóór DNS-herschrijving wijzigen')
            s.agh('rewrite/'+action,{'domain':host,'answer':answer},settings=origin)
            s.request_cluster();return self.respond({'ok':True})
        if path=='/api/central-client':
            if s.desired['captured']:return self.respond(s.desired_collection('clients',data))
            origin=s.primary();value=data.get('value');action=data.get('action')
            if action not in ('add','update','delete') or not isinstance(value,dict):raise ValueError('Ongeldige apparaatactie.')
            if action=='update':
                if not data.get('etag') or s.central_read('clients')['etag']!=data['etag']:raise ValueError('Apparaten zijn intussen gewijzigd; laad opnieuw.')
                body={'name':str(data.get('original_name','')),'data':value}
            elif action=='delete':body={'name':str(value.get('name',''))}
            else:body=value
            s.backup_central(origin,'Vóór apparaat wijzigen')
            s.agh('clients/'+action,body,settings=origin)
            s.request_cluster();return self.respond({'ok':True})
        if path=='/api/settings':
            with s.lock:
                new=copy.deepcopy(s.config)
                mode=data.get('mode',new['mode'])
                if mode not in ('all','observed'): raise ValueError('Ongeldige lijstmodus.')
                new['mode']=mode
                if 'public_url' in data: new['public_url']=valid_url(data['public_url']) if data['public_url'].strip() else ''
                if 'auto_refresh_hours' in data:
                    hours=int(data['auto_refresh_hours'])
                    if hours not in (6,12,24,48): raise ValueError('Kies 6, 12, 24 of 48 uur.')
                    new['auto_refresh_hours']=hours
                if 'categories' in data:new['categories']={k:bool(data['categories'].get(k,True)) for k in CATEGORIES}
                if 'auto_sync' in data: new['auto_sync']=bool(data['auto_sync'])
                if 'packs' in data:
                    new['packs']={p['id']:bool(data['packs'].get(p['id'],False)) for p in PACKS}
                if 'adguard' in data:
                    a=data['adguard']; old=new['adguard']
                    new['adguard']={'url':valid_url(a.get('url','')) if a.get('url','').strip() else '', 'username':str(a.get('username',''))[:200], 'password':str(a['password']) if a.get('password') else old['password']}
                    if a.get('clear_password'): new['adguard']['password']=''
                if 'adguard' in data and new.get('servers'):
                    primary=next(x for x in new['servers'] if x['id']==new['primary_id'])
                    primary.update(new['adguard'])
                s.config=new; s.changed()
            return self.respond({'ok':True})
        if path=='/api/sources':
            action=data.get('action','add')
            with s.lock:
                if action=='add':
                    if len(s.config['sources'])>=30: raise ValueError('Maximaal 30 bronnen.')
                    url=valid_url(data.get('url',''),public=True)
                    if url==s.config['public_url'] or '/lists/'+s.feed_token+'/' in url: raise ValueError('Je eigen VenGuard-lijst kan geen bron zijn.')
                    if any(x['url']==url for x in s.config['sources']): raise ValueError('Deze bron bestaat al.')
                    s.config['sources'].append({'id':secrets.token_hex(6),'name':str(data.get('name') or 'Eigen bron')[:120],'url':url,'enabled':True,'category':str(data.get('category','custom')) if data.get('category','custom') in CATEGORIES else 'custom'})
                else:
                    item=next((x for x in s.config['sources'] if x['id']==data.get('id')),None)
                    if item is None: raise ValueError('Bron niet gevonden.')
                    if action=='delete': s.config['sources'].remove(item)
                    elif action=='toggle': item['enabled']=bool(data.get('enabled'))
                    elif action=='category':
                        if data.get('category') not in CATEGORIES:raise ValueError('Onbekende categorie.')
                        item['category']=data['category']
                    else: raise ValueError('Ongeldige bronactie.')
                s.changed(); s.request_build(fetch=True)
            return self.respond({'ok':True})
        if path=='/api/live-rules':return self.respond(s.apply_live_rules())
        if path=='/api/rules':
            with s.lock:
                action=data.get('action')
                if action=='delete':
                    s.config['rules']=[r for r in s.config['rules'] if r['id']!=data.get('id')]
                elif action=='toggle':
                    item=next((r for r in s.config['rules'] if r['id']==data.get('id')),None)
                    if not item: raise ValueError('Regel niet gevonden.')
                    item['enabled']=bool(data.get('enabled'))
                else:
                    if action not in ('block','allow'): raise ValueError('Kies blokkeren of toestaan.')
                    d=domain(data.get('domain','')); client=scope(data.get('client',''));match=data.get('match','exact')
                    if match not in ('exact','suffix'):raise ValueError('Kies alleen dit domein of ook subdomeinen.')
                    duration=int(data.get('duration',0))
                    if duration not in (0,900,3600,86400):raise ValueError('Kies blijvend, 15 minuten, 1 uur of 1 dag.')
                    if client and any(kind(x)=='pihole' and x.get('enabled',True) for x in s.servers()):raise ValueError('Apparaatregels vereisen Pi-hole-groepen en kunnen niet veilig over beide systemen worden toegepast. Laat apparaat leeg of gebruik Eigen beheer.')
                    retained=[r for r in s.config['rules'] if not (r['domain']==d and r.get('client','')==client)]
                    if len(retained)>=3000: raise ValueError('Maximaal 3.000 eigen regels.')
                    s.config['rules']=retained
                    s.config['rules'].append({'id':secrets.token_hex(6),'domain':d,'action':action,'client':client,'note':str(data.get('note',''))[:500],'match':match,'expires_at':time.time()+duration if duration else None,'enabled':True,'created':utc()})
                s.changed();s.rules_pending=True;s.live_results={}
            applied=s.apply_live_rules();return self.respond({'ok':True,'applied':applied,'message':applied['message']})
        if path=='/api/build': s.request_build(fetch=bool(data.get('fetch',False))); return self.respond({'ok':True})
        if path=='/api/poll':
            try: rows=s.poll(); return self.respond({'ok':True,'count':len(rows)})
            except Exception as e:
                with s.lock: s.poll_error=safe_network_error(e)
                raise
        if path=='/api/test-connection':
            status=s.agh('status'); return self.respond({'ok':True,'version':status.get('version'),'protection_enabled':status.get('protection_enabled')})
        if path=='/api/sync': return self.respond(s.sync())
        if path=='/api/import-sources':
            result=s.desired_filters() if s.desired['captured'] else s.agh('filtering/status'); added=0; ignored=[]
            with s.lock:
                for item in result.get('filters',[]):
                    url=item.get('url','')
                    if '/lists/'+s.feed_token+'/' in url: continue
                    if any(x['url']==url for x in s.config['sources']): continue
                    if len(s.config['sources'])>=30: ignored.append('Limiet van 30 bronnen bereikt.'); break
                    # Import only the enabled blocklists; allowlists & user rules stay in AGH.
                    if not item.get('enabled'): continue
                    try: valid_url(url,public=True)
                    except Exception: ignored.append(item.get('name','Onbekende bron')+': geen bereikbare publieke HTTPS-bron.'); continue
                    s.config['sources'].append({'id':secrets.token_hex(6),'name':item.get('name','AdGuard-import')[:120],'url':url,'enabled':True}); added+=1
                s.changed(); s.request_build(fetch=True)
            return self.respond({'ok':True,'added':added,'ignored':ignored,'message':'Bron-URLs gekopieerd. Bestaande lijsten, uitzonderingen en eigen AdGuard-regels zijn ongewijzigd.'})
        if path=='/api/clear-observed':
            with s.lock: s.observed={}; atomic(s.dir/'observed.json','{}'); s.request_build()
            return self.respond({'ok':True})
        return self.respond({'error':'Niet gevonden.'},404)

def main():
    logging.basicConfig(level=logging.INFO,format='%(levelname)s %(message)s')
    store=Store(os.getenv('VENGUARD_DATA','/data'))
    if not os.getenv('VENGUARD_PASSWORD'):
        logging.info('Beheerwachtwoord staat in het databestand admin-password. Bekijk dit alleen op je eigen host.')
    server=BoundedHTTPServer(('0.0.0.0',int(os.getenv('VENGUARD_PORT','8098'))),Handler)
    server.store=store; server.daemon_threads=True
    for target in (store.worker,store.monitor_worker,store.cluster_worker,store.operations_worker,store.security_worker,store.connectivity_worker,store.management_worker):
        threading.Thread(target=target,daemon=True).start()
    logging.info('VenGuard gestart op poort %s',server.server_port)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally:
        store.stop.set();store.event.set();store.cluster_event.set()
        if store.process is not None:store.process.terminate()
        server.server_close()
if __name__=='__main__': main()
