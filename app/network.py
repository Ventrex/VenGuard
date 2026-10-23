"""Persistent device inventory and a narrowly authenticated LAN scanner agent."""
import copy
import hmac
import ipaddress
import json
import os
import re
import secrets
import time
from pathlib import Path
from hub import now_iso,write_private
from rules import domain

class NetworkMixin:
    def init_network(self):
        self.network_dir=Path(os.getenv('VENGUARD_NETWORK_DIR',str(self.dir/'network-agent')));self.network_dir.mkdir(parents=True,exist_ok=True)
        self.network={'enabled':False,'subnets':[],'devices':{},'last_scan':None,'agent_seen':0,'error':'','audit':{},'audit_job':None}
        path=self.dir/'network.json'
        if path.exists():self.network.update(json.loads(path.read_text()))
        token_path=self.network_dir/'agent-token'
        if not token_path.exists():write_private(token_path,{'token':secrets.token_urlsafe(32)})
        os.chmod(token_path,0o640)  # Scanner's supplementary group reads this narrow volume only.
        self.network_token=json.loads(token_path.read_text())['token'];self.write_scanner_config()
    def write_scanner_config(self):
        write_private(self.network_dir/'scanner.json',{'enabled':self.network['enabled'],'subnets':self.network['subnets'],'interval':120,'scan_request':self.network.get('scan_request',0),'url':self.config.get('public_url',''),'audit_job':self.network.get('audit_job')})
        os.chmod(self.network_dir/'scanner.json',0o640)
    def save_network(self):
        write_private(self.dir/'network.json',self.network);self.write_scanner_config()
    def network_snapshot(self):
        with self.lock:
            devices=copy.deepcopy(list(self.network['devices'].values()));fresh=self.network['enabled'] and time.time()-self.network['agent_seen']<180 and time.time()-self.network.get('last_scan_epoch',0)<400
            # Stale evidence cannot establish that a device is currently offline.
            for d in devices:
                if not fresh:d['state']='unknown'
            return {'enabled':self.network['enabled'],'subnets':self.network['subnets'],'devices':devices,'last_scan':self.network['last_scan'],'agent_online':time.time()-self.network['agent_seen']<180,'error':self.network['error'],'audit':copy.deepcopy(self.network['audit']),'audit_job':copy.deepcopy(self.network.get('audit_job')),'internet_control':{'available':False,'reason':'Je Deco XE75 Pro heeft geen hier ondersteunde beheer-API voor internetblokkades. Blokkeer apparaten in de Deco-app. DNS blokkeren is geen internetblokkade.'}}
    def network_settings(self,data):
        subnets=[]
        for value in data.get('subnets',[]):
            net=ipaddress.ip_network(str(value).strip(),strict=False)
            if net.version!=4 or net.num_addresses>256 or not all(any(ip in ipaddress.ip_network(r) for r in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')) for ip in (net.network_address,net.broadcast_address)):raise ValueError('Gebruik een privé IPv4-subnet van maximaal 256 adressen (bijvoorbeeld /24).')
            subnets.append(str(net))
        if not subnets or len(subnets)>4:raise ValueError('Vul één tot vier lokale subnetten in.')
        with self.lock:self.network.update(enabled=bool(data.get('enabled',True)),subnets=list(dict.fromkeys(subnets)),scan_request=time.time());self.save_network()
        return {'ok':True,'message':'Scanner ingesteld. De agent ontdekt apparaten iedere twee minuten.'}
    def network_device(self,data):
        with self.lock:
            item=self.network['devices'].get(data.get('id'))
            if not item:raise ValueError('Apparaat niet gevonden.')
            for key in ('name','type','notes'):
                if key in data:item[key]=str(data[key]).strip()[:500 if key=='notes' else 100]
            self.save_network()
        return {'ok':True}
    def scanner_report(self,data,token):
        if not token or not hmac.compare_digest(token,self.network_token):raise PermissionError('Ongeldige scanneragent.')
        rows=data.get('devices',[])
        if not isinstance(rows,list) or len(rows)>1024:raise ValueError('Te veel apparaten.')
        with self.lock:
            now=time.time();self.network['agent_seen']=now
            if data.get('error') or data.get('complete'):self.network['error']=str(data.get('error',''))[:500]
            # Only a complete, successful configured scan can mark a missed device offline.
            complete=bool(data.get('complete')) and not data.get('error') and self.network['enabled']
            scanned=set(data.get('subnets',[]))
            complete=complete and scanned==set(self.network['subnets'])
            seen=set()
            for row in rows:
                ip=ipaddress.ip_address(str(row.get('ip','')))
                if not any(ip in ipaddress.ip_network(n) for n in self.network['subnets']):continue
                mac=str(row.get('mac','')).lower()
                if mac and not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',mac):continue
                key=mac or str(ip);seen.add(key)
                # When a MAC becomes known, retain manual metadata from a prior IP-only observation.
                if key not in self.network['devices'] and str(ip) in self.network['devices']:self.network['devices'][key]=self.network['devices'].pop(str(ip))
                item=self.network['devices'].setdefault(key,{'id':key,'first_seen':now_iso(),'name':'','type':'','notes':''})
                item.update(id=key,ip=str(ip),mac=mac,hostname=str(row.get('hostname',''))[:253],vendor=str(row.get('vendor',''))[:150],last_seen=now_iso(),last_seen_epoch=now,state='online',missed=0,method=str(row.get('method','nmap'))[:60])
            if complete:
                for key,item in self.network['devices'].items():
                    if key not in seen:
                        item['missed']=item.get('missed',0)+1;item['state']='offline' if item['missed']>=3 else 'unknown'
                self.network['last_scan']=now_iso();self.network['last_scan_epoch']=now
            job=self.network.get('audit_job')
            if job and data.get('audit_id')==job['id']:
                results=data.get('audit',{})
                for host in job['domains']:
                    if host in results:self.network['audit'][host]={k:results[host].get(k) for k in ('dns','ping','address','ms','message')}|{'at':now_iso()}
                self.network['audit_job']=None
                self.network['audit']=dict(list(self.network['audit'].items())[-500:])
            self.save_network()
        return {'ok':True}
    def request_audit(self,data):
        hosts=[]
        if data.get('domain'):hosts=[domain(data['domain'])]
        else:
            with self.lock:lines=(self.dir/'filter.txt').read_text().splitlines()
            offset=max(0,min(int(data.get('offset',0)),1000000))
            for line in lines[offset:]:
                if line.startswith('||') and line.endswith('^'):
                    hosts.append(line[2:-1])
                    if len(hosts)>=25:break
        if not hosts:raise ValueError('Geen domeinregels gevonden voor deze controle.')
        if time.time()-self.network['agent_seen']>180:raise ValueError('De scanneragent is nog niet bereikbaar. Start de bijgewerkte Docker Compose-installatie.')
        with self.lock:
            if self.network.get('audit_job'):raise ValueError('Er loopt al een domeincontrole.')
            self.network['audit_job']={'id':secrets.token_hex(8),'domains':hosts,'at':now_iso()};self.save_network()
        return {'ok':True,'message':'Controle gestart. Een timeout of ontbrekend DNS-antwoord verwijdert nooit automatisch een regel.'}
