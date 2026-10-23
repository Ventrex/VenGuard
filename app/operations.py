"""Small live mutations, with per-server results and safe retries of desired state."""
import copy
import json
import re
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from hub import now_iso,write_private,error_text
from providers import kind
from rules import rule_text

BEGIN='! VenGuard managed rules begin'
END='! VenGuard managed rules end'

def native_rules(current,wanted):
    output=[];inside=False
    # Never erase ambiguous user content if a marker was accidentally edited.
    if current.count(BEGIN)!=current.count(END) or current.count(BEGIN)>1:raise ValueError('Het beheerde regelblok is gewijzigd. Herstel de VenGuard-markeringen in de eigen serverregels.')
    for line in current:
        if line==BEGIN:inside=True;continue
        if line==END:inside=False;continue
        if not inside:output.append(line)
    if wanted:output += [BEGIN,*wanted,END]
    return output

class OperationsMixin:
    def init_operations(self):
        self.control_intents={};self.live_results={};self.live_lock=threading.Lock()
        path=self.dir/'control-intents.json'
        if path.exists():self.control_intents=json.loads(path.read_text())
        self.rules_pending=bool(self.servers());self.events=[]
        path=self.dir/'events.json'
        if path.exists():self.events=json.loads(path.read_text())[-100:]
    def record_event(self,operation,sid,state,message):
        with self.lock:
            self.events.append({'at':now_iso(),'operation':operation,'server_id':sid,'state':state,'message':message});self.events=self.events[-100:];write_private(self.dir/'events.json',self.events)
    def set_controls(self,field,enabled):
        if field not in ('protection','filtering') or not isinstance(enabled,bool):raise ValueError('Ongeldige beschermingsopdracht.')
        origin=self.primary();feature='general' if field=='protection' else 'filters'
        targets=[origin]
        if self.config['cluster_sync']['enabled'] and self.config['cluster_sync']['features'].get(feature):targets=[s for s in self.servers() if s.get('enabled',True)]
        if field=='filtering' and kind(origin)=='pihole':raise ValueError('Pi-hole heeft één blokkeringsschakelaar; gebruik Bescherming aan/uit.')
        targets=[s for s in targets if field!='filtering' or kind(s)=='adguard']
        with self.lock:
            for s in targets:self.control_intents.setdefault(s['id'],{})[field]=enabled
            write_private(self.dir/'control-intents.json',self.control_intents)
        results=self.reconcile_controls({s['id'] for s in targets})
        return {'ok':all(x['ok'] for x in results.values()),'partial':any(not x['ok'] for x in results.values()),'results':results,'hub':self.hub_snapshot(),'message':f"Stand bevestigd op {sum(x['ok'] for x in results.values())} van {len(results)} servers. Niet bevestigde opdrachten worden opnieuw gecontroleerd."}
    def reconcile_controls(self,ids=None):
        with self.lock:intents=copy.deepcopy(self.control_intents)
        targets=[s for s in self.servers() if s.get('enabled',True) and s['id'] in intents and (ids is None or s['id'] in ids)]
        def apply(server):
            sid=server['id'];outcome={'ok':True,'at':now_iso(),'message':'Stand bevestigd.'}
            for field,enabled in intents[sid].items():
                try:
                    endpoint='status' if field=='protection' else 'filtering/status';key='protection_enabled' if field=='protection' else 'enabled'
                    before=self.agh(endpoint,settings=server)
                    if before.get(key) is not enabled:
                        body={'enabled':enabled,'duration':0} if field=='protection' else {'enabled':enabled,'interval':before.get('interval',24)}
                        # Do not repeat a write after a lost response: first read back its result.
                        try:self.agh('protection' if field=='protection' else 'filtering/config',body,settings=server)
                        except Exception:
                            confirmed=self.agh(endpoint,settings=server)
                            if confirmed.get(key) is not enabled:raise
                        after=self.agh(endpoint,settings=server)
                        if after.get(key) is not enabled:raise ValueError('De server bevestigt de gevraagde stand nog niet.')
                    with self.lock:
                        h=self.health.setdefault(sid,{});h['protection_enabled' if field=='protection' else 'filtering_enabled']=enabled;h['controls_checked_at']=now_iso();h['controls_epoch']=time.time()
                        if self.control_intents.get(sid,{}).get(field) is enabled:self.control_intents[sid].pop(field,None)
                    self.record_event('Bescherming' if field=='protection' else 'Lijstfiltering',sid,'success','Stand bevestigd; overige DNS-instellingen niet gewijzigd.')
                except Exception as e:
                    outcome={'ok':False,'at':now_iso(),'message':error_text(e)};self.record_event('Beschermingsopdracht',sid,'pending',outcome['message'])
            return sid,outcome
        with ThreadPoolExecutor(max_workers=4) as pool:results=dict(pool.map(apply,targets))
        with self.lock:
            self.control_intents={sid:value for sid,value in self.control_intents.items() if value};write_private(self.dir/'control-intents.json',self.control_intents)
        return results
    def apply_live_rules(self):
        if not self.live_lock.acquire(blocking=False):return {'ok':False,'queued':True,'message':'Regels worden al toegepast; de nieuwste keuze volgt automatisch.','results':copy.deepcopy(self.live_results)}
        if not self.cluster_lock.acquire(blocking=False):
            self.live_lock.release();return {'ok':False,'queued':True,'message':'Een synchronisatie loopt. De regel staat klaar en wordt daarna direct toegepast.','results':copy.deepcopy(self.live_results)}
        try:
            with self.lock:rules=copy.deepcopy(self.config['rules']);revision=self.revision
            active=[r for r in rules if r.get('enabled',True) and (not r.get('expires_at') or r['expires_at']>time.time())]
            def apply(server):
                try:
                    if kind(server)=='pihole':self.apply_pihole_rules(server,active)
                    else:
                        status=self.agh('filtering/status',settings=server);before=status.get('user_rules',[]);after=native_rules(before,[rule_text(r) for r in active])
                        if after!=before:self.agh('filtering/set_rules',{'rules':after},settings=server)
                        # Read actual server state; a timeout alone is not evidence that no change happened.
                        check=self.agh('filtering/status',settings=server).get('user_rules',[])
                        if check!=after:raise ValueError('De server bevestigt het beheerde regelblok nog niet.')
                    self.record_event('Eigen domeinregels',server['id'],'success','Actieve regels rechtstreeks toegepast.')
                    return server['id'],{'ok':True,'at':now_iso(),'message':'Actieve regels rechtstreeks toegepast.'}
                except Exception as e:
                    msg=error_text(e);self.record_event('Eigen domeinregels',server['id'],'pending',msg)
                    return server['id'],{'ok':False,'at':now_iso(),'message':msg}
            targets=[s for s in self.servers() if s.get('enabled',True)]
            with ThreadPoolExecutor(max_workers=4) as pool:results=dict(pool.map(apply,targets))
            with self.lock:
                self.live_results=results;self.rules_pending=revision!=self.revision or any(not r['ok'] for r in results.values())
            return {'ok':bool(results) and all(r['ok'] for r in results.values()),'results':results,'queued':self.rules_pending,'message':f"Regels bevestigd op {sum(r['ok'] for r in results.values())} van {len(results)} servers. Geldt bij de volgende DNS-aanvraag; een lopende pagina of app moet zelf opnieuw proberen."}
        finally:self.cluster_lock.release();self.live_lock.release()
    def apply_pihole_rules(self,server,rules):
        if any(r.get('client') for r in rules):raise ValueError('Apparaatregels kunnen niet naar Pi-hole worden vertaald. Gebruik daar groepen, of maak een globale regel.')
        current=self.pihole.call(server,'domains').get('domains',[])
        wanted={}
        for r in rules:
            match=r.get('match','suffix');host=r['domain'];pattern=host if match=='exact' else '(^|\\.)'+re.escape(host)+'$'
            wanted[(r['action']=='allow' and 'allow' or 'deny','exact' if match=='exact' else 'regex',pattern)]={'domain':pattern,'comment':'VenGuard managed rule','groups':[0],'enabled':True}
        owned={(r['type'],r['kind'],r['domain']):r for r in current if r.get('comment')=='VenGuard managed rule'}
        all_items={(r['type'],r['kind'],r['domain']):r for r in current}
        for key,item in owned.items():
            if key not in wanted:self.pihole.call(server,'domains/'+key[0]+'/'+key[1]+'/'+urllib.parse.quote(key[2],safe=''),method='DELETE')
        for key,value in wanted.items():
            existing=all_items.get(key)
            if existing and key not in owned:
                if not existing.get('enabled') or 0 not in existing.get('groups',[0]):raise ValueError('Er bestaat een eigen Pi-hole-regel met andere status/groepen; pas die aan via Eigen beheer.')
                continue
            if existing and existing.get('enabled') and existing.get('groups')==[0]:continue
            target='domains/'+key[0]+'/'+key[1]
            if existing:self.pihole.call(server,target+'/'+urllib.parse.quote(key[2],safe=''),{k:v for k,v in value.items() if k!='domain'},method='PUT')
            else:self.pihole.call(server,target,value)
        verified=self.pihole.call(server,'domains').get('domains',[])
        keys={(r['type'],r['kind'],r['domain']) for r in verified if r.get('enabled') and 0 in r.get('groups',[0])}
        if set(wanted)-keys:raise ValueError('Pi-hole bevestigt niet alle regels in de standaardgroep.')
    def expire_rules(self):
        with self.lock:
            changed=False
            for rule in self.config['rules']:
                if rule.get('enabled') and rule.get('expires_at') and rule['expires_at']<=time.time():rule['enabled']=False;changed=True
            if changed:self.changed();self.rules_pending=True
        return changed

    def operations_worker(self):
        # Independent of source downloads and Gravity; expiry/retry must keep running.
        while not self.stop.is_set():
            try:
                self.expire_rules()
                if time.time()-self.last_live_attempt>15:
                    self.last_live_attempt=time.time()
                    if self.control_intents and self.cluster_lock.acquire(blocking=False):
                        try:self.reconcile_controls()
                        finally:self.cluster_lock.release()
                    if self.rules_pending:self.apply_live_rules()
            except Exception as e:self.record_event('Achtergrondcontrole','','pending',error_text(e))
            self.stop.wait(1)
