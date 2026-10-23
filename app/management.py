"""VenGuard-owned desired AdGuard configuration, independent of a live origin."""
import copy
import json
import threading
import time
from hub import SECTIONS,digest,error_text,now_iso,write_private
from operations import native_rules
from providers import kind

def profile_matches(wanted,actual):
    """AdGuard fills optional defaults; compare the fields VenGuard actually owns."""
    if isinstance(wanted,dict):return isinstance(actual,dict) and all(k in actual and profile_matches(v,actual[k]) for k,v in wanted.items())
    if isinstance(wanted,list):
        if not isinstance(actual,list) or len(wanted)!=len(actual):return False
        remaining=list(actual)
        for item in wanted:
            index=next((i for i,value in enumerate(remaining) if profile_matches(item,value)),None)
            if index is None:return False
            remaining.pop(index)
        return True
    return wanted==actual

class ManagementMixin:
    def init_management(self):
        self.desired={'captured':False,'sections':{},'controls':{'protection':True,'filtering':True},'native_filters':[],'revision':0,'updated_at':None}
        path=self.dir/'desired-settings.json'
        if path.exists():self.desired.update(json.loads(path.read_text()))
        self.management_results={};self.management_event=threading.Event();self.management_lock=threading.Lock();self.management_last=0
        self.management_error='';self.management_running=False;self.management_refresh=False
    def save_desired(self):
        self.desired['revision']+=1;self.desired['updated_at']=now_iso()
        write_private(self.dir/'desired-settings.json',self.desired);self.management_event.set()
    def management_snapshot(self):
        with self.lock:return {'captured':self.desired['captured'],'revision':self.desired['revision'],'updated_at':self.desired['updated_at'],'sections':list(self.desired['sections']),'controls':copy.deepcopy(self.desired['controls']),'results':copy.deepcopy(self.management_results),'running':self.management_running,'error':self.management_error}
    def adopt_server(self,sid=''):
        if not self.management_lock.acquire(blocking=False):return {'ok':False,'message':'Profiel wordt al overgenomen.'}
        try:return self._adopt_server(sid)
        finally:self.management_lock.release()
    def _adopt_server(self,sid=''):
        revision=self.desired['revision']
        server=self.selected(sid)
        if kind(server)!='adguard':raise ValueError('Een AdGuard-profiel kan alleen uit AdGuard Home worden overgenomen.')
        status=self.agh('status',settings=server);filtering=self.agh('filtering/status',settings=server)
        sections={};errors=[]
        for section in SECTIONS:
            try:sections[section]=self.central_read(section,server['id'])['value']
            except Exception as error:errors.append(section+': '+error_text(error))
        if 'dns' not in sections:raise ValueError('DNS-instellingen konden niet worden gelezen. Profiel nog niet overgenomen.')
        if sections['dns'].get('upstream_dns_file') and not sections['dns'].get('upstream_dns'):raise ValueError('De bron gebruikt een lokaal upstreambestand. Vul de gedeelde upstream-adressen eerst in VenGuard in.')
        sections['dns'].pop('upstream_dns_file',None)
        # Managed live rules remain owned by the ordinary VenGuard rule editor.
        if 'rules' in sections:sections['rules']=native_rules(sections['rules'],[])
        filters=[{k:f.get(k) for k in ('name','url','enabled')}|{'whitelist':white} for white,key in ((False,'filters'),(True,'whitelist_filters')) for f in filtering.get(key,[]) if '/lists/'+self.feed_token+'/' not in f.get('url','')]
        with self.lock:
            if self.desired['revision']!=revision:raise ValueError('Het profiel is intussen gewijzigd; nieuwe keuzes blijven behouden.')
            self.desired.update(captured=True,sections=sections,controls={'protection':bool(status.get('protection_enabled',True)),'filtering':bool(filtering.get('enabled',True))},native_filters=filters)
            self.management_error='; '.join(errors);self.save_desired()
        return {'ok':True,'message':'Instellingen opgeslagen in VenGuard. Bereikbare servers ontvangen dit profiel op de achtergrond.'}
    def desired_read(self,section):
        if section not in SECTIONS:raise ValueError('Onbekend onderdeel.')
        defaults={'rules':[],'dns':{'upstream_dns':[],'bootstrap_dns':[]},'rewrites':[],'clients':[],'services':{'ids':[],'schedule':{'time_zone':'Local'}},'querylog':{'enabled':True},'statistics':{'enabled':True},'safebrowsing':{'enabled':False},'parental':{'enabled':False},'safesearch':{'enabled':False},'access':{'allowed_clients':[],'disallowed_clients':[],'blocked_hosts':[]}}
        value=copy.deepcopy(self.desired['sections'].get(section,defaults[section]))
        return {'section':section,'name':SECTIONS[section]['name'],'value':value,'etag':digest(value),'server_id':'venguard','local':True}
    def desired_write(self,section,value,etag):
        before=self.desired_read(section)
        if not etag or etag!=before['etag']:raise ValueError('Instellingen zijn intussen gewijzigd. Laad opnieuw.')
        if section in ('rules','rewrites','clients'):
            if not isinstance(value,list):raise ValueError('Dit onderdeel verwacht een lijst.')
            if section=='rules' and not all(isinstance(v,str) for v in value):raise ValueError('Regels moeten tekst zijn.')
        elif not isinstance(value,dict):raise ValueError('Dit onderdeel verwacht een object.')
        if section in ('safebrowsing','parental') and (set(value)!={'enabled'} or not isinstance(value['enabled'],bool)):raise ValueError('Gebruik alleen enabled: true of false.')
        if section=='dns':
            if set(value)-set(SECTIONS['dns']['keys']):raise ValueError('Serverspecifieke DNS-velden zijn niet toegestaan.')
            if value.get('upstream_dns_file'):raise ValueError('Een lokaal upstreambestand wordt niet naar andere hosts gekopieerd. Gebruik gedeelde upstream-adressen.')
            if not value.get('upstream_dns') and not value.get('upstream_dns_file'):raise ValueError('Vul minimaal één upstream in.')
        with self.lock:
            folder=self.dir/'profile-backups';folder.mkdir(exist_ok=True)
            write_private(folder/(str(time.time_ns())+'.json'),self.desired)
            for file in sorted(folder.glob('*.json'))[:-20]:file.unlink()
            self.desired['sections'][section]=copy.deepcopy(value);self.desired['captured']=True;self.save_desired()
        return {'ok':True,'message':'Opgeslagen in VenGuard. Alle ingeschakelde servers worden op de achtergrond bijgewerkt.'}
    def desired_controls(self,field,enabled):
        if not isinstance(enabled,bool):raise ValueError('Kies aan of uit.')
        with self.lock:self.desired['controls'][field]=enabled;self.desired['captured']=True;self.save_desired()
        if not self.servers():return {'ok':True,'message':'Stand opgeslagen in VenGuard; nieuwe servers nemen deze over.'}
        return self.set_controls(field,enabled)
    def desired_collection(self,section,data):
        current=self.desired_read(section);values=current['value'];action=data.get('action')
        if action not in ('add','update','delete'):raise ValueError('Ongeldige actie.')
        if section=='rewrites':
            item={k:str(data.get(k,'')).strip() for k in ('domain','answer')}
            if not all(item.values()) or any(len(v)>253 for v in item.values()):raise ValueError('Vul domein en antwoord in.')
            if action=='delete':values=[v for v in values if any(v.get(k)!=item[k] for k in item)]
            elif item not in values:values.append(item)
        else:
            item=data.get('value');name=data.get('original_name') or (item or {}).get('name')
            if not isinstance(item,dict) or not item.get('name'):raise ValueError('Vul een apparaatnaam in.')
            if action=='update' and data.get('etag')!=current['etag']:raise ValueError('Apparaten zijn gewijzigd; laad opnieuw.')
            values=[v for v in values if v.get('name')!=name]
            if action!='delete':values.append(item)
        return self.desired_write(section,values,current['etag'])
    def desired_filter_action(self,data):
        action=data.get('action')
        if action=='refresh':
            with self.lock:self.management_refresh=True;self.management_event.set()
            self.request_build(fetch=True);return {'ok':True}
        with self.lock:
            item=next((f for f in self.desired['native_filters'] if f['url']==data.get('url') and f['whitelist']==bool(data.get('whitelist'))),None)
            if not item:raise ValueError('Deze centrale serverlijst is niet gevonden.')
            if action=='delete':self.desired['native_filters'].remove(item)
            elif action=='toggle':item['enabled']=bool(data.get('enabled'))
            else:raise ValueError('Ongeldige lijstactie.')
            self.save_desired()
        return {'ok':True}
    def desired_filters(self):
        return {key:[copy.deepcopy(f) for f in self.desired['native_filters'] if f['whitelist']==white] for key,white in (('filters',False),('whitelist_filters',True))}
    def apply_management(self):
        if not self.desired['captured']:return {'ok':False,'message':'Stel eerst het centrale profiel in of neem bestaande instellingen over.'}
        if not self.management_lock.acquire(blocking=False):return {'ok':False,'queued':True}
        if not self.cluster_lock.acquire(blocking=False):self.management_lock.release();return {'ok':False,'queued':True}
        self.management_running=True
        try:
            with self.lock:desired=copy.deepcopy(self.desired);servers=[s for s in self.servers() if s.get('enabled',True)];refresh=self.management_refresh;self.management_refresh=False;feed_revision=self.revision
            def apply(server):
                sid=server['id'];changed=[]
                try:
                    if kind(server)!='adguard':return sid,{'ok':True,'revision':desired['revision'],'at':now_iso(),'message':'Pi-hole: gedeelde lijst en domeinregels; AdGuard-profiel niet van toepassing.'}
                    self.agh('status',settings=server)
                    if self.management_results.get(sid,{}).get('revision')!=desired['revision']:self.backup_central(server,'Vóór centraal VenGuard-profiel')
                    for section,value in desired['sections'].items():
                        current=self.central_read(section,sid)['value'];wanted=copy.deepcopy(value)
                        if section=='rules':
                            # Preserve the current live-managed block while replacing native rules.
                            from operations import BEGIN,END
                            managed=[];inside=False
                            for line in current:
                                if line==BEGIN:inside=True;continue
                                if line==END:inside=False;continue
                                if inside:managed.append(line)
                            wanted=native_rules(wanted,managed)
                        comparison={k:current.get(k) for k in wanted} if isinstance(wanted,dict) else current
                        if (profile_matches(wanted,current) if section in ('clients','rewrites') else digest(comparison)==digest(wanted)):continue
                        if section in ('clients','rewrites'):
                            key='name' if section=='clients' else 'domain';endpoint='clients' if section=='clients' else 'rewrite'
                            for old in current:
                                target=next((v for v in wanted if v.get(key)==old.get(key) and (section!='rewrites' or v.get('answer')==old.get('answer'))),None)
                                if target is not None and profile_matches(target,old):continue
                                self.agh(endpoint+'/delete',{'name':old['name']} if section=='clients' else {'domain':old['domain'],'answer':old['answer']},settings=server)
                            for item in wanted:
                                if not any(profile_matches(item,old) for old in current):self.agh(endpoint+'/add',item,settings=server)
                        else:
                            spec=SECTIONS[section]
                            if spec.get('toggle'):self.agh(spec['toggle']+('/enable' if wanted['enabled'] else '/disable'),{},settings=server)
                            else:self.agh(spec['set'],{'rules':wanted} if section=='rules' else wanted,settings=server,method=spec.get('method','POST'))
                        # Read back before considering a saved profile confirmed.
                        actual=self.central_read(section,sid)['value']
                        if isinstance(wanted,dict):
                            if any(actual.get(k)!=v for k,v in wanted.items()):raise ValueError(section+': instellingen nog niet bevestigd.')
                        elif not (profile_matches(wanted,actual) if section in ('clients','rewrites') else digest(actual)==digest(wanted)):raise ValueError(section+': instellingen nog niet bevestigd.')
                        changed.append(section)
                    filtering=self.agh('filtering/status',settings=server)
                    for white,key in ((False,'filters'),(True,'whitelist_filters')):
                        actual=filtering.get(key,[]);wanted=[f for f in desired['native_filters'] if f['whitelist']==white]
                        for item in actual:
                            if '/lists/'+self.feed_token+'/' in item.get('url',''):continue
                            if not any(f['url']==item['url'] for f in wanted):self.agh('filtering/remove_url',{'url':item['url'],'whitelist':white},settings=server)
                        for item in wanted:
                            found=next((f for f in actual if f.get('url')==item['url']),None)
                            if not found:
                                self.agh('filtering/add_url',{k:item[k] for k in ('name','url','whitelist')},settings=server)
                            if not found or any(found.get(k)!=item.get(k) for k in ('name','enabled')):self.agh('filtering/set_url',{'url':item['url'],'whitelist':white,'data':{k:item[k] for k in ('name','url','enabled')}},settings=server)
                    confirmed=self.agh('filtering/status',settings=server)
                    for white,key in ((False,'filters'),(True,'whitelist_filters')):
                        actual=[{k:f.get(k) for k in ('url','name','enabled')} for f in confirmed.get(key,[]) if '/lists/'+self.feed_token+'/' not in f.get('url','')]
                        wanted=[{k:f.get(k) for k in ('url','name','enabled')} for f in desired['native_filters'] if f['whitelist']==white]
                        if sorted(actual,key=lambda f:f['url'])!=sorted(wanted,key=lambda f:f['url']):raise ValueError('Centrale filterlijsten nog niet bevestigd.')
                    for field,enabled in desired['controls'].items():
                        endpoint='status' if field=='protection' else 'filtering/status';key='protection_enabled' if field=='protection' else 'enabled'
                        before=self.agh(endpoint,settings=server)
                        if before.get(key) is not enabled:self.agh('protection' if field=='protection' else 'filtering/config',{'enabled':enabled,'duration':0} if field=='protection' else {'enabled':enabled,'interval':before.get('interval',24)},settings=server)
                        if self.agh(endpoint,settings=server).get(key) is not enabled:raise ValueError('Beschermingsstand nog niet bevestigd.')
                    if self.config.get('public_url'):
                        self.ensure_feed(server,self.feed_url(),False)
                        feed=self.feed_results.get(sid,{})
                        if refresh or self.management_results.get(sid,{}).get('revision')!=desired['revision'] or (self.config.get('auto_sync') and (not feed.get('ok') or feed.get('revision')!=feed_revision)):
                            self.agh('filtering/refresh',{'whitelist':False},settings=server)
                            self.agh('filtering/refresh',{'whitelist':True},settings=server)
                            with self.lock:self.feed_results[sid]={'ok':True,'at':now_iso(),'revision':feed_revision,'error':''}
                    self.record_event('Centraal profiel',sid,'success','Profiel bevestigd; gewijzigd: '+(', '.join(changed) or 'geen instellingen')+'.')
                    return sid,{'ok':True,'revision':desired['revision'],'at':now_iso(),'message':'Centraal profiel bevestigd.' if self.config.get('public_url') else 'Instellingen bevestigd; stel het VenGuard LAN-adres in om ook de lijst aan te bieden.'}
                except Exception as error:
                    message=error_text(error);self.record_event('Centraal profiel',sid,'pending',message)
                    return sid,{'ok':False,'revision':desired['revision'],'at':now_iso(),'message':message}
            # Apply serially: DNS reconfiguration on both replicas at once is avoided.
            results={}
            for server in servers:
                sid,result=apply(server);results[sid]=result
            with self.lock:self.management_results=results;self.management_last=time.time()
            return {'ok':bool(results) and all(r['ok'] for r in results.values()),'results':results}
        finally:self.management_running=False;self.cluster_lock.release();self.management_lock.release()
    def management_worker(self):
        while not self.stop.is_set():
            self.management_event.wait(2)
            try:
                if not self.desired['captured'] and self.servers():
                    self.adopt_server();self.management_event.set()
                if self.desired['captured'] and (self.management_event.is_set() or time.time()-self.management_last>120):
                    self.management_event.clear();self.apply_management()
            except Exception as error:self.management_error=error_text(error);self.stop.wait(30)
