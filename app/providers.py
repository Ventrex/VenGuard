"""Pi-hole v6 adapter. Only capabilities actually shared with AdGuard are mapped."""
import hashlib
import email.utils
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime,timezone

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

def kind(server):return server.get('type','adguard')
def api_root(server):
    root=server['url'].rstrip('/')
    for suffix in ('/admin','/api'):
        if root.endswith(suffix):root=root[:-len(suffix)]
    return root+'/api/'

class PiHole:
    def __init__(self):self.sessions={};self.lock=threading.RLock()
    def raw(self,server,path,body=None,method=None,headers=None,stream=False):
        req=urllib.request.Request(api_root(server)+path,data=None if body is None else json.dumps(body).encode(),headers={'Accept':'application/json','Content-Type':'application/json',**(headers or {})},method=method)
        with urllib.request.build_opener(NoRedirect()).open(req,timeout=180 if stream else 12) as response:
            raw=response.read(8*1024*1024+1)
            if len(raw)>8*1024*1024:raise ValueError('Pi-hole-antwoord te groot.')
            if stream:
                if b'<html' in raw[:300].lower() or b'<!doctype' in raw[:300].lower():raise ValueError('Pi-hole geeft een webpagina terug; gebruik het beheeradres van Pi-hole v6.')
                text=raw.decode('utf-8',errors='replace').lower()
                if 'gravity failed' in text or 'gravity is already running' in text or 'unable to acquire' in text:raise ValueError('Pi-hole heeft Gravity nog niet afgerond of geweigerd omdat een andere update loopt. De lijststatus is nog niet bevestigd.')
                try:server_time=email.utils.parsedate_to_datetime(response.headers.get('Date','')).timestamp()
                except (ValueError,TypeError):server_time=time.time()
                return {'ok':True,'server_time':server_time}
            if not raw.strip() and (method or ('POST' if body is not None else 'GET'))=='DELETE':return {}
            try:result=json.loads(raw)
            except (ValueError,UnicodeError):raise ValueError('Pi-hole geeft geen JSON terug; controleer het beheeradres en gebruik Pi-hole v6.')
            if not isinstance(result,dict):raise ValueError('Onverwacht Pi-hole-antwoord.')
            if result.get('error'):raise ValueError('Pi-hole heeft de API-opdracht geweigerd; controleer rechten en de serverlog.')
            return result
    def session(self,server,reset=False):
        key=server.get('id',server['url']);signature=hashlib.sha256((server['url']+'\0'+server.get('password','')).encode()).hexdigest()
        with self.lock:
            old=self.sessions.get(key,{})
            if old.get('signature')==signature and old.get('expires',0)>time.time() and not reset:return old
            if old.get('signature')==signature and old.get('blocked_until',0)>time.time():raise ValueError('Pi-hole-inloggen tijdelijk gepauzeerd na een fout; controleer het (app-)wachtwoord.')
            try:
                data=self.raw(server,'auth',{'password':server.get('password','')})['session']
                if not data.get('valid'):raise ValueError('Pi-hole weigert het wachtwoord. Gebruik bij 2FA een app-wachtwoord.')
            except (ValueError,urllib.error.HTTPError):
                self.sessions[key]={'signature':signature,'blocked_until':time.time()+60};raise
            value={'signature':signature,'sid':data.get('sid'),'csrf':data.get('csrf'),'validity':max(10,int(data.get('validity',300))),'expires':time.time()+max(5,int(data.get('validity',300))-5)}
            self.sessions[key]=value;return value
    def call(self,server,path,body=None,method=None,stream=False):
        for attempt in range(2):
            session=self.session(server,reset=attempt>0)
            headers={k:v for k,v in {'X-FTL-SID':session.get('sid'),'X-FTL-CSRF':session.get('csrf')}.items() if v}
            try:
                result=self.raw(server,path,body,method,headers,stream)
                with self.lock:session['expires']=time.time()+session['validity']-5
                processed=result.get('processed') or {}
                if processed.get('errors'):raise ValueError('Pi-hole kon niet alle items verwerken; controleer de bestaande domein- of lijstinstellingen.')
                return result
            except urllib.error.HTTPError as e:
                if e.code!=401 or attempt:raise
        raise ValueError('Pi-hole-sessie kon niet worden vernieuwd.')
    def lists(self,server):
        data=self.call(server,'lists').get('lists',[])
        return {'enabled':self.call(server,'dns/blocking').get('blocking')=='enabled','interval':24,
          'filters':[self.list_item(x) for x in data if x.get('type','block')=='block'],
          'whitelist_filters':[self.list_item(x) for x in data if x.get('type')=='allow'],'user_rules':[]}
    @staticmethod
    def list_item(x):return {**x,'url':x['address'],'name':x.get('comment') or x['address'],'rules_count':(x.get('number') or 0)+(x.get('abp_entries') or 0),'last_updated':x.get('date_updated')}
    def refresh(self,server,verify_urls=None):
        before=self.call(server,'lists').get('lists',[])
        if verify_urls is not None and set(verify_urls)-{r['address'] for r in before if r.get('enabled')}:raise ValueError('Pi-hole bevestigt niet alle VenGuard-abonnementen; probeer de koppeling opnieuw.')
        expected={(r['address'],r.get('type','block')) for r in before if r.get('enabled') and (verify_urls is None or r['address'] in verify_urls)}
        started=time.monotonic();result=self.call(server,'action/gravity',{},stream=True)
        # Downloads can finish before a slow Gravity round ends. Anchor freshness
        # to the start of this request in Pi-hole's own clock, not its finish.
        requested_at=result['server_time']-(time.monotonic()-started)
        after={(r['address'],r.get('type','block')):r for r in self.call(server,'lists').get('lists',[])}
        for key in expected:
            item=after.get(key,{})
            if not item.get('enabled') or item.get('status') not in (1,2) or item.get('date_updated',0)<requested_at-2:
                raise ValueError('Pi-hole bevestigt nog geen actuele succesvolle download voor alle gekozen lijsten. Mogelijk loopt Gravity nog of is een bron niet bereikbaar; de volgende ronde probeert opnieuw.')
        return {'ok':True,'verified':len(expected)}
    def adapter(self,server,path,body=None,query=None,method=None):
        if path=='status':
            status=self.call(server,'dns/blocking');version=self.call(server,'info/version').get('version',{}).get('ftl',{}).get('local',{}).get('version','v6')
            blocking=status.get('blocking');return {'version':version,'protection_enabled':True if blocking=='enabled' else False if blocking=='disabled' else None}
        if path=='filtering/status':return self.lists(server)
        if path=='protection':return self.call(server,'dns/blocking',{'blocking':body['enabled'],'timer':None})
        if path=='filtering/config':raise ValueError('Pi-hole heeft één blokkeringsschakelaar. Gebruik Bescherming aan/uit.')
        if path=='filtering/add_url':return self.call(server,'lists?type='+('allow' if body.get('whitelist') else 'block'),{'address':body['url'],'comment':body.get('name','VenGuard'),'enabled':True,'groups':[0]})
        if path in ('filtering/set_url','filtering/remove_url'):
            listtype='allow' if body.get('whitelist') else 'block';current=next((x for x in self.call(server,'lists').get('lists',[]) if x['address']==body['url'] and x.get('type','block')==listtype),None)
            if not current:raise ValueError('Pi-hole-lijst niet gevonden; laad opnieuw.')
            target='lists/'+urllib.parse.quote(body['url'],safe='')+'?type='+listtype
            if path.endswith('remove_url'):return self.call(server,target,method='DELETE')
            value=body['data'];return self.call(server,target,{'comment':current.get('comment') or '', 'groups':current.get('groups',[0]),'enabled':value['enabled']},method='PUT')
        if path=='filtering/refresh':return self.refresh(server,(body or {}).get('verify_urls'))
        if path=='querylog':
            rows=self.call(server,'queries?length=1000').get('queries',[]);out=[]
            blocked={'GRAVITY','REGEX','DENYLIST','GRAVITY_CNAME','REGEX_CNAME','DENYLIST_CNAME','EXTERNAL_BLOCKED_IP','EXTERNAL_BLOCKED_NULL','EXTERNAL_BLOCKED_NXRA','DBBUSY','SPECIAL_DOMAIN'}
            for row in rows:
                status=row.get('status') or 'UNKNOWN';reply=row.get('reply',{}).get('type');is_blocked=status in blocked
                reason='FilteredBlackList' if is_blocked else 'NotFilteredError' if status in ('UNKNOWN','RETRIED_DNSSEC') or reply in ('SERVFAIL','REFUSED') else 'NotFilteredNotFound'
                out.append({'time':datetime.fromtimestamp(row['time'],timezone.utc).isoformat(),'question':{'name':row.get('cname') if is_blocked and row.get('cname') else row['domain'],'type':row['type']},'client':row.get('client',{}).get('ip',''),'client_info':{'name':row.get('client',{}).get('name') or ''},'reason':reason,'status':'SERVFAIL' if reason=='NotFilteredError' else 'NXDOMAIN' if reply=='NXDOMAIN' else 'NOERROR','rules':[{'text':f"Pi-hole: {status}",'filter_list_id':row.get('list_id')}],'provider_status':status})
            return {'data':out}
        if path=='filtering/check_host':
            data=self.call(server,'search/'+urllib.parse.quote(query['name'],safe='')+'?partial=false&N=100')
            return {'reason':'PiHoleMatches','rules':[{'text':json.dumps(x,ensure_ascii=False)} for x in (data.get('search',{}).get('domains',[])+data.get('search',{}).get('gravity',[]))], 'note':'Pi-hole toont lijsttreffers; geen definitieve resolveruitkomst voor een apparaat of groep.'}
        raise ValueError('Dit geavanceerde AdGuard-onderdeel is niet beschikbaar voor Pi-hole. Gebruik gedeelde filterbronnen en eigen domeinregels, of open Eigen beheer.')
