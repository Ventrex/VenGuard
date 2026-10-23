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

def safe_network_error(error):
    if isinstance(error,urllib.error.HTTPError):
        return {401:'Inloggegevens geweigerd (401).',403:'Toegang geweigerd (403).',404:'Adres niet gevonden (404); controleer de URL en poort.',429:'Te veel verzoeken; probeer het later opnieuw.'}.get(error.code,f'HTTP-fout {error.code}.')
    if isinstance(error,(TimeoutError,socket.timeout)): return 'Verbinding verlopen; controleer adres, poort en netwerk.'
    if isinstance(error,urllib.error.URLError): return 'Netwerk- of certificaatfout; controleer URL, DNS en TLS-certificaat.'
    if isinstance(error,ValueError): return str(error)
    return 'Verzoek mislukt; controleer de configuratie.'

DEFAULT={
 'version':1,'mode':'all','public_url':'','auto_refresh_hours':24,'auto_sync':True,
 'packs':{p['id']:p['enabled'] for p in PACKS},
 'sources':[{'id':'hagezi-light','name':'HaGeZi Light — rustige basis','url':'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt','enabled':True}],
 'rules':[], 'adguard':{'url':'','username':'','password':''}
}

class Store:
    def __init__(self,directory):
        self.dir=Path(directory); self.dir.mkdir(parents=True,exist_ok=True)
        self.lock=threading.RLock(); self.agh_lock=threading.Lock()
        self.config=read_json(self.dir/'config.json',DEFAULT)
        self.observed=read_json(self.dir/'observed.json',{})
        self.caches=read_json(self.dir/'cache.json',{})
        self.feed_token=self.secret('feed-token')
        self.password=os.getenv('VENGUARD_PASSWORD','') or self.secret('admin-password')
        self.sessions={}; self.attempts={}; self.event=threading.Event(); self.stop=threading.Event()
        self.fetch_requested=False; self.job={'running':False,'error':'','last_build':None,'last_sync':None,'sync_error':''}
        self.report=read_json(self.dir/'report.json',{'count':0,'sources':[],'built':None,'added':0,'removed':0})
        self.origins={}; self.last_log=[]; self.last_poll=0; self.poll_error=''; self.last_refresh=0
        self.revision=0
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
    def request_build(self,fetch=False):
        with self.lock:
            self.fetch_requested |= fetch; self.event.set()
    def feed_text(self,lines):
        return '! Title: VenGuard Custom DNS\n! Generated: '+utc()+'\n! DNS-only; source licenses apply. See the VenGuard dashboard.\n'+'\n'.join(lines)+'\n'
    def agh(self,path,body=None,query=None,settings=None):
        with self.lock: cfg=copy.deepcopy(settings or self.config['adguard'])
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
        req=urllib.request.Request(target,data=data,headers=headers)
        with urllib.request.build_opener(NoRedirect()).open(req,timeout=15) as response:
            raw=response.read(16*1024*1024+1)
            if len(raw)>16*1024*1024: raise ValueError('AdGuard-antwoord te groot.')
            if not raw.strip(): return {}
            try: return json.loads(raw)
            except json.JSONDecodeError: raise ValueError('AdGuard gaf geen JSON terug; controleer de beheer-URL en poort.')
    def feed_url(self):
        with self.lock: base=self.config['public_url']
        if not base: raise ValueError('Vul bij Instellingen het LAN-adres van VenGuard in, bijvoorbeeld http://192.168.0.10:8098.')
        return base+'/lists/'+self.feed_token+'/filter.txt'
    def sync(self):
        # Only add/re-enable our single list, never overwrite custom rules or other lists.
        with self.agh_lock:
            url=self.feed_url(); status=self.agh('filtering/status')
            found=next((f for f in status.get('filters',[]) if f.get('url')==url),None)
            if found is None:
                self.agh('filtering/add_url',{'name':'VenGuard Custom DNS','url':url,'whitelist':False})
            elif not found.get('enabled'):
                self.agh('filtering/set_url',{'url':url,'whitelist':False,'data':{'url':url,'name':found.get('name','VenGuard Custom DNS'),'enabled':True}})
            self.agh('filtering/refresh',{'whitelist':False})
            with self.lock: self.job['last_sync']=utc(); self.job['sync_error']=''
            return {'ok':True,'message':'VenGuard-lijst aangeboden en een filterverversing aangevraagd. Controleer met Domein testen wat AdGuard nu toepast.','url':url}
    def poll(self):
        result=self.agh('querylog',query={'limit':1000})
        data=result.get('data',[])
        now=time.time()
        with self.lock:
            self.last_log=data; self.last_poll=now; self.poll_error=''
            for row in data:
                try: d=domain(row.get('question',{}).get('name',''))
                except ValueError: continue
                self.observed[d]=now
            self.observed={d:t for d,t in sorted(self.observed.items(),key=lambda x:x[1],reverse=True)[:50000] if now-t<30*86400}
            atomic(self.dir/'observed.json',json.dumps(self.observed))
            if self.config['mode']=='observed': self.request_build()
        return data
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
            text=self.feed_text(lines)
            previous=self.dir/'filter.txt'
            backups=self.dir/'backups'; backups.mkdir(exist_ok=True)
            # A short local history for recovery; credentials never enter these files.
            if set(lines)!=old and previous.exists():
                atomic(backups/(str(time.time_ns())+'.txt'),previous.read_text())
                for file in sorted(backups.glob('*.txt'))[:-10]: file.unlink()
            atomic(previous,text)
            self.origins=origins
            self.report={'count':len(lines),'sources':stats,'built':utc(),'added':len(set(lines)-old),'removed':len(old-set(lines)),'mode':config['mode'],'observed':len(self.observed)}
            atomic(self.dir/'cache.json',json.dumps(caches)); atomic(self.dir/'report.json',json.dumps(self.report,ensure_ascii=False))
            self.job.update(running=False,last_build=utc())
            sync=config.get('auto_sync',False) and bool(config['public_url']) and bool(config['adguard']['url'])
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
                except Exception:
                    logging.exception('List build failed')
                    with self.lock: self.job.update(running=False,error='Lijst opbouwen mislukt. De laatst gepubliceerde lijst blijft beschikbaar.')
                if fetch: self.last_refresh=now
            with self.lock:
                configured=bool(self.config['adguard']['url']); hours=self.config['auto_refresh_hours']
            if configured and now-self.last_poll>60:
                self.last_poll=now
                try: self.poll()
                except Exception as e:
                    with self.lock: self.poll_error=safe_network_error(e)
            if now-self.last_refresh>hours*3600:
                self.last_refresh=now; self.request_build(fetch=True)
    def snapshot(self):
        with self.lock:
            config=copy.deepcopy(self.config)
            config['adguard']['password_set']=bool(config['adguard'].pop('password',''))
            return {'config':config,'packs':PACKS,'report':copy.deepcopy(self.report),'job':dict(self.job),'observed':len(self.observed),'poll_error':self.poll_error,'last_poll':self.last_poll or None,'feed_url':self.feed_url() if config['public_url'] else '', 'feed_path':'/lists/'+self.feed_token+'/filter.txt','version':'1.0.0'}

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
        if path=='/health': return self.respond({'ok':True})
        if path.startswith('/lists/'):
            expected='/lists/'+self.store.feed_token+'/filter.txt'
            if not hmac.compare_digest(path,expected): return self.respond({'error':'Niet gevonden.'},404)
            return self.respond((self.store.dir/'filter.txt').read_bytes(),ctype='text/plain')
        if path=='/api/session': return self.respond({'authenticated':self.auth()})
        if path.startswith('/api/'):
            if not self.auth(): return self.respond({'error':'Log eerst in.'},401)
            if path=='/api/state': return self.respond(self.store.snapshot())
            if path=='/api/log':
                with self.store.lock: rows=copy.deepcopy(self.store.last_log); error=self.store.poll_error
                search=q.get('search','').lower(); selected=q.get('status','all'); client=q.get('client',''); output=[]
                for row in rows:
                    d=row.get('question',{}).get('name',''); reason=row.get('reason',''); category='blocked' if reason.startswith('Filtered') and reason!='FilteredSafeSearch' else ('rewritten' if reason.startswith('Rewrite') or reason=='FilteredSafeSearch' else ('error' if reason=='NotFilteredError' or row.get('status') not in ('NOERROR','NXDOMAIN') else ('allowed' if row.get('status')=='NOERROR' else 'other')))
                    if search and search not in (d+' '+row.get('client','')+' '+row.get('client_info',{}).get('name','')).lower(): continue
                    if selected!='all' and selected!=category: continue
                    if client and row.get('client')!=client: continue
                    annotation=explain(d)
                    with self.store.lock:
                        custom=[r for r in self.store.config['rules'] if d==r['domain'] or d.endswith('.'+r['domain'])]
                    output.append({**row,'classification':annotation,'outcome':category,'custom':custom})
                return self.respond({'data':output,'count_sample':len(rows),'last_poll':self.store.last_poll,'error':error,'limit':1000})
            if path=='/api/check':
                d=domain(q.get('domain','')); result=self.store.agh('filtering/check_host',query={'name':d,'client':q.get('client',''),'qtype':q.get('type','A')})
                return self.respond({'domain':d,'adguard':result,'explanation':explain(d),'note':'Dit is een actuele AdGuard-regelcontrole, geen DNS-verzoek vanaf je iPhone.'})
            if path=='/api/diagnostics':
                return self.respond({'status':self.store.agh('status'),'filtering':self.store.agh('filtering/status'),'clients':self.store.agh('clients')})
            if path=='/api/export':
                with self.store.lock:
                    config=copy.deepcopy(self.store.config); config['adguard']={'url':config['adguard']['url'],'username':'','password':''}
                return self.respond(config,headers={'Content-Disposition':'attachment; filename="VenGuard-instellingen.json"'})
            if path=='/api/preview':
                with self.store.lock:
                    lines=(self.store.dir/'filter.txt').read_text().splitlines()
                search=q.get('search','').lower()
                filtered=[l for l in lines if not l.startswith('!') and (not search or search in l.lower())]
                offset=max(0,min(int(q.get('offset',0)),1000000))
                return self.respond({'lines':filtered[offset:offset+100],'total':len(filtered),'offset':offset})
            return self.respond({'error':'Niet gevonden.'},404)
        files={'/':'index.html','/app.js':'app.js','/style.css':'style.css'}
        if path not in files: return self.respond({'error':'Niet gevonden.'},404)
        file=ROOT/'static'/files[path]
        return self.respond(file.read_bytes(),ctype={'html':'text/html','js':'text/javascript','css':'text/css'}[file.suffix[1:]])
    def do_POST(self):
        try:
            origin=self.headers.get('Origin')
            if origin and urllib.parse.urlsplit(origin).netloc!=self.headers.get('Host'):
                return self.respond({'error':'Ongeldige herkomst.'},403)
            if self.headers.get('X-VenGuard')!='1': return self.respond({'error':'Ontbrekende aanvraagbeveiliging.'},403)
            self.post(urllib.parse.urlsplit(self.path).path,self.body())
        except (BrokenPipeError,ConnectionResetError): pass
        except Exception as e: self.respond({'error':safe_network_error(e)},400)
    def post(self,path,data):
        s=self.store
        if path=='/api/login':
            ip=self.client_address[0]; now=time.time()
            with s.lock:
                history=[t for t in s.attempts.get(ip,[]) if now-t<300]
                s.attempts={k:v for k,v in s.attempts.items() if v and now-v[-1]<300}
                if len(history)>=10: return self.respond({'error':'Te veel pogingen. Wacht vijf minuten.'},429)
                if not hmac.compare_digest(str(data.get('password','')),s.password):
                    s.attempts[ip]=history+[now]; return self.respond({'error':'Onjuist wachtwoord.'},401)
                token=secrets.token_urlsafe(32); s.sessions={k:v for k,v in s.sessions.items() if v>now}; s.sessions[token]=now+12*3600; s.attempts.pop(ip,None)
            secure='; Secure' if self.headers.get('X-Forwarded-Proto')=='https' else ''
            return self.respond({'ok':True},headers={'Set-Cookie':f'vg_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200'+secure})
        if not self.auth(): return self.respond({'error':'Log eerst in.'},401)
        if path=='/api/logout':
            cookie=http.cookies.SimpleCookie(self.headers.get('Cookie',''))
            with s.lock:
                if 'vg_session' in cookie: s.sessions.pop(cookie['vg_session'].value,None)
            return self.respond({'ok':True},headers={'Set-Cookie':'vg_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'})
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
                if 'auto_sync' in data: new['auto_sync']=bool(data['auto_sync'])
                if 'packs' in data:
                    new['packs']={p['id']:bool(data['packs'].get(p['id'],False)) for p in PACKS}
                if 'adguard' in data:
                    a=data['adguard']; old=new['adguard']
                    new['adguard']={'url':valid_url(a.get('url','')) if a.get('url','').strip() else '', 'username':str(a.get('username',''))[:200], 'password':str(a['password']) if a.get('password') else old['password']}
                    if a.get('clear_password'): new['adguard']['password']=''
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
                    s.config['sources'].append({'id':secrets.token_hex(6),'name':str(data.get('name') or 'Eigen bron')[:120],'url':url,'enabled':True})
                else:
                    item=next((x for x in s.config['sources'] if x['id']==data.get('id')),None)
                    if item is None: raise ValueError('Bron niet gevonden.')
                    if action=='delete': s.config['sources'].remove(item)
                    elif action=='toggle': item['enabled']=bool(data.get('enabled'))
                    else: raise ValueError('Ongeldige bronactie.')
                s.changed(); s.request_build(fetch=True)
            return self.respond({'ok':True})
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
                    d=domain(data.get('domain','')); client=scope(data.get('client',''))
                    retained=[r for r in s.config['rules'] if not (r['domain']==d and r.get('client','')==client)]
                    if len(retained)>=3000: raise ValueError('Maximaal 3.000 eigen regels.')
                    s.config['rules']=retained
                    s.config['rules'].append({'id':secrets.token_hex(6),'domain':d,'action':action,'client':client,'note':str(data.get('note',''))[:500],'enabled':True,'created':utc()})
                s.changed()
            return self.respond({'ok':True,'message':'Eigen regel opgeslagen. De lijst wordt opnieuw opgebouwd.'})
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
            result=s.agh('filtering/status'); added=0; ignored=[]
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
    server=ThreadingHTTPServer(('0.0.0.0',int(os.getenv('VENGUARD_PORT','8098'))),Handler)
    server.store=store; server.daemon_threads=True
    worker=threading.Thread(target=store.worker,daemon=True); worker.start()
    logging.info('VenGuard gestart op poort %s',server.server_port)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: store.stop.set(); store.event.set(); server.server_close()
if __name__=='__main__': main()
