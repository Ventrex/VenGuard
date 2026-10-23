"""Read-only, bounded network checks and persistent outage evidence.

All checks originate in the VenGuard container. They cannot prove that Wi-Fi,
client DNS settings, recursive upstreams or every Internet destination works.
"""
import copy
import errno
import ipaddress
import json
import secrets
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from hub import now_iso, write_private

EXTERNAL_TARGETS=(('Cloudflare','1.1.1.1',443),('Google','8.8.8.8',443))
RCODES={0:'NOERROR',1:'FORMERR',2:'SERVFAIL',3:'NXDOMAIN',4:'NOTIMP',5:'REFUSED'}

def network_error(error):
    if isinstance(error,(TimeoutError,socket.timeout)):return 'timeout','Geen antwoord binnen 2 seconden.'
    if isinstance(error,ConnectionRefusedError):return 'refused','Verbinding geweigerd; de poort is dicht of de dienst luistert niet.'
    if isinstance(error,ConnectionResetError):return 'reset','De andere kant heeft de verbinding verbroken.'
    if getattr(error,'errno',None) in (errno.EHOSTUNREACH,errno.ENETUNREACH):return 'no_route','Geen netwerkroute vanaf VenGuard naar dit adres.'
    if isinstance(error,ValueError):return 'invalid_response','Het antwoord is geen geldig antwoord op de testvraag.'
    return 'network_error','Netwerkverbinding mislukt vanaf VenGuard.'

def tcp_probe(host,port):
    start=time.monotonic()
    try:
        # IP literals only: this test must not depend on the DNS being diagnosed.
        ipaddress.ip_address(host)
        with socket.create_connection((host,port),timeout=2):pass
        return {'ok':True,'code':'connected','error':'','ms':round((time.monotonic()-start)*1000,1)}
    except (OSError,ValueError) as error:
        code,message=network_error(error)
        return {'ok':False,'code':code,'error':message,'ms':None}

def _name(data,offset):
    labels=[];end=None;seen=set()
    for _ in range(128):
        if offset>=len(data) or offset in seen:raise ValueError('DNS name')
        seen.add(offset);size=data[offset];offset+=1
        if size&0xc0==0xc0:
            if offset>=len(data):raise ValueError('DNS pointer')
            pointer=((size&0x3f)<<8)|data[offset]
            if end is None:end=offset+1
            offset=pointer;continue
        if size&0xc0 or size>63 or offset+size>len(data):raise ValueError('DNS label')
        if not size:return b'.'.join(labels).lower(),end if end is not None else offset
        labels.append(data[offset:offset+size]);offset+=size
    raise ValueError('DNS name length')

def _recv(sock,size):
    data=b''
    while len(data)<size:
        part=sock.recv(size-len(data))
        if not part:raise ConnectionResetError()
        data+=part
    return data

def dns_probe(host,port=53,timeout=2,transport='udp'):
    if not host:return {'ok':None,'reachable':None,'resolved':None,'error':'Geen DNS-IP ingesteld.','code':'not_configured','ms':None}
    start=time.monotonic()
    try:
        address=ipaddress.ip_address(host);transaction=secrets.randbelow(65536)
        question=b'\x07example\x03org\x00'+struct.pack('!HH',1,1)
        packet=struct.pack('!HHHHHH',transaction,0x100,1,0,0,0)+question
        with socket.socket(socket.AF_INET6 if address.version==6 else socket.AF_INET,socket.SOCK_STREAM if transport=='tcp' else socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout);sock.connect((host,int(port)))
            if transport=='tcp':
                sock.sendall(struct.pack('!H',len(packet))+packet)
                size=struct.unpack('!H',_recv(sock,2))[0]
                if size<12:raise ValueError('DNS length')
                response=_recv(sock,size)
            else:sock.send(packet);response=sock.recv(4096)
        if len(response)<12:raise ValueError('DNS header')
        tid,flags,qd,an,ns,ar=struct.unpack('!HHHHHH',response[:12])
        if tid!=transaction or not flags&0x8000 or flags&0x7800 or qd!=1:raise ValueError('DNS transaction')
        name,offset=_name(response,12)
        if name!=b'example.org' or response[offset:offset+4]!=struct.pack('!HH',1,1):raise ValueError('DNS question')
        offset+=4;answers=[]
        for _ in range(an):
            _,offset=_name(response,offset)
            if offset+10>len(response):raise ValueError('DNS record')
            record_type,record_class,ttl,size=struct.unpack('!HHIH',response[offset:offset+10]);offset+=10
            if offset+size>len(response):raise ValueError('DNS data')
            if record_type==1 and record_class==1 and size==4:answers.append(str(ipaddress.ip_address(response[offset:offset+4])))
            offset+=size
        rcode=flags&15;truncated=bool(flags&0x200)
        blocked=bool(answers) and all(ipaddress.ip_address(ip).is_unspecified or ipaddress.ip_address(ip).is_loopback for ip in answers)
        resolved=rcode==0 and bool(answers) and not blocked and not truncated
        code='truncated' if truncated else 'blocked_answer' if blocked else RCODES.get(rcode,'RCODE_'+str(rcode))
        error='' if resolved else ('DNS-antwoord afgekapt; controleer TCP.' if truncated else 'De testnaam example.org krijgt een blokkeeradres.' if blocked else 'De DNS-server antwoordt met '+code+'.' if rcode else 'De DNS-server antwoordt zonder IPv4-adres voor example.org.')
        return {'ok':rcode in (0,3) and not truncated,'reachable':True,'resolved':resolved,'rcode':rcode,'code':code,'answers':answers,'error':error,'ms':round((time.monotonic()-start)*1000,1),'transport':transport}
    except (OSError,ValueError,struct.error) as error:
        code,message=network_error(error)
        return {'ok':False,'reachable':False,'resolved':False,'code':code,'error':message,'ms':None,'transport':transport}

def dns_check(host,port):
    udp=dns_probe(host,port)
    if udp['ok'] is False:udp=dns_probe(host,port)
    tcp=dns_probe(host,port,transport='tcp') if udp['ok'] is False else None
    return {**udp,'tcp':tcp,'checked_at':now_iso(),'checked_epoch':time.time()}

def assessment(health):
    """Observations and qualified next steps, never a claimed root cause."""
    dns=health.get('dns',{});api=health.get('api_ok');fresh=health.get('checked_epoch',0)>time.time()-90
    if dns.get('ok') is None:return {'code':'unknown','title':'DNS nog niet getest','detail':'Stel het DNS-IP in om naamomzetting afzonderlijk te controleren.'}
    if dns.get('ok') and dns.get('resolved') is False:return {'code':'resolution','title':'DNS antwoordt, testnaam werkt niet','detail':dns.get('error','')+' Controleer filters en upstreams; de server is niet volledig onbereikbaar.'}
    if dns.get('ok') is False:
        if (dns.get('tcp') or {}).get('ok'):return {'code':'udp','title':'DNS via UDP faalt, TCP antwoordt','detail':'Controleer UDP-poort 53, Docker-poortpublicatie, firewall en belasting. Dit kan vertraging op apparaten veroorzaken.'}
        if dns.get('reachable'):return {'code':'resolution','title':'DNS geeft een foutantwoord','detail':dns.get('error','')+' Controleer de AdGuard/Pi-hole-log en upstream-DNS.'}
        if fresh and api is False:return {'code':'host_path','title':'Beheer en DNS reageren niet','detail':'De host, container of netwerkroute kan haperen. Een verkeerde binding of firewall kan hetzelfde beeld geven. De oorzaak is nog niet vastgesteld.'}
        return {'code':'dns','title':'DNS reageert niet','detail':'Controleer de DNS-dienst, poort 53 en de route vanaf VenGuard. Een werkende beheerpagina bewijst niet dat DNS werkt.'}
    if fresh and api is False:return {'code':'admin','title':'DNS werkt, beheerverbinding faalt','detail':'Deze meting toont geen DNS-uitval. Controleer het beheeradres en de gemelde HTTP-, TLS- of netwerkfout.'}
    if fresh and (health.get('protection_enabled') is False or health.get('filtering_enabled') is False):return {'code':'filtering_off','title':'DNS werkt, filtering staat uit','detail':'Naamomzetting werkt, maar bescherming of lijstfiltering is uitgeschakeld. Bekijk de actuele schakelaars.'}
    return {'code':'healthy','title':'DNS-test geslaagd','detail':'example.org antwoordt vanaf VenGuard. Het antwoord kan uit de DNS-cache komen; deze test bewijst niet dat alle upstreams of apparaten werken.'}

class ConnectivityMixin:
    def init_connectivity(self):
        self.connectivity_lock=threading.Lock();self.connectivity_running=False
        self.connectivity={'external':{},'checked_at':None,'checked_epoch':0,'incidents':[],'samples':[],'previous':{},'last_sample':0}
        path=self.dir/'connectivity.json'
        if path.exists():
            try:self.connectivity.update(json.loads(path.read_text()))
            except (ValueError,OSError):pass
        self.connectivity['incidents']=self.connectivity['incidents'][-200:]
        self.connectivity['samples']=self.connectivity['samples'][-1440:]
        # An unobserved restart gap is never counted as measured downtime.
        for incident in self.connectivity['incidents']:
            if not incident.get('ended_at'):
                incident.update(ended_at=now_iso(),end_reason='monitor_restarted',duration_seconds=None)
        self.connectivity['previous']={}

    def track_connection(self,key,ok,message,at,epoch):
        if ok is None:return
        previous=self.connectivity['previous'].get(key)
        if not ok and previous is not False:
            related=[{k:e.get(k) for k in ('at','operation','server_id','state')} for e in getattr(self,'events',[]) if epoch-datetime.fromisoformat(e['at']).timestamp()<120][-8:]
            self.connectivity['incidents'].append({'key':key,'started_at':at,'started_epoch':epoch,'ended_at':None,'duration_seconds':None,'last_seen_at':at,'message':message,'nearby_actions':related})
        elif ok and previous is False:
            for incident in reversed(self.connectivity['incidents']):
                if incident['key']==key and not incident.get('ended_at'):
                    incident.update(ended_at=at,duration_seconds=max(0,round(epoch-incident['started_epoch'])),end_reason='recovered');break
        elif not ok:
            for incident in reversed(self.connectivity['incidents']):
                if incident['key']==key and not incident.get('ended_at'):incident.update(last_seen_at=at,message=message);break
        self.connectivity['previous'][key]=ok
        self.connectivity['incidents']=self.connectivity['incidents'][-200:]

    def check_connectivity(self):
        if not self.connectivity_lock.acquire(blocking=False):return False
        self.connectivity_running=True
        try:
            servers=[s for s in self.servers() if s.get('enabled',True)]
            def probe_server(s):return s['id'],dns_check(s.get('dns_host',''),s.get('dns_port',53))
            def probe_external(target):
                name,host,port=target;return {'name':name,'host':host,'port':port,**tcp_probe(host,port)}
            with ThreadPoolExecutor(max_workers=12) as pool:
                dns_futures=[pool.submit(probe_server,s) for s in servers]
                external_futures=[pool.submit(probe_external,t) for t in EXTERNAL_TARGETS]
                results=[f.result() for f in dns_futures];external=[f.result() for f in external_futures]
            at=now_iso();epoch=time.time()
            with self.lock:
                ids={s['id'] for s in self.servers() if s.get('enabled',True)}
                active_keys={'external'}|{s['id']+':'+part for s in servers for part in ('dns','api')}
                for incident in self.connectivity['incidents']:
                    if incident['key'] not in active_keys and not incident.get('ended_at'):incident.update(ended_at=at,end_reason='server_removed_or_disabled',duration_seconds=None)
                for sid,result in results:
                    if sid not in ids:continue
                    self.health.setdefault(sid,{})['dns']=result
                    ok=result.get('ok')
                    if ok and result.get('resolved') is False:ok=False
                    self.track_connection(sid+':dns',ok,result.get('error',''),at,epoch)
                external_ok=any(r['ok'] for r in external)
                self.connectivity.update(external={'ok':external_ok,'targets':external},checked_at=at,checked_epoch=epoch)
                self.track_connection('external',external_ok,'Beide externe TCP-tests mislukten. Dit bewijst geen storing bij de provider.',at,epoch)
                if epoch-self.connectivity.get('last_sample',0)>=60:
                    self.connectivity['samples'].append({'at':at,'external':external_ok,'servers':{sid:{'dns':d.get('ok'),'resolved':d.get('resolved'),'code':d.get('code'),'ms':d.get('ms'),'api':self.health.get(sid,{}).get('api_ok')} for sid,d in results if sid in ids}})
                    self.connectivity['last_sample']=epoch
                self.connectivity['samples']=[s for s in self.connectivity['samples'] if datetime.fromisoformat(s['at']).timestamp()>epoch-86400][-1440:]
                write_private(self.dir/'connectivity.json',self.connectivity)
            return True
        finally:self.connectivity_running=False;self.connectivity_lock.release()

    def request_connectivity(self):
        # A UI request returns immediately, also behind a short reverse-proxy timeout.
        if not self.connectivity_running:threading.Thread(target=self.check_connectivity,daemon=True).start()
        return {'ok':True,'message':'DNS- en verbindingstests worden uitgevoerd. Het overzicht wordt automatisch bijgewerkt.'}

    def connectivity_worker(self):
        while not self.stop.is_set():
            try:self.check_connectivity()
            except Exception:
                # Preserve the last evidence; fresh/stale is exposed separately.
                pass
            self.stop.wait(15)

    def connectivity_snapshot(self,report=False):
        with self.lock:
            result={k:copy.deepcopy(v) for k,v in self.connectivity.items() if k in ('external','checked_at','checked_epoch','incidents')}
            result['stale']=time.time()-result['checked_epoch']>60
            result['running']=self.connectivity_running
            result['incidents']=list(reversed(result['incidents']))[:50]
            if report:
                result['incidents']=list(reversed(copy.deepcopy(self.connectivity['incidents'])))
                result['samples']=copy.deepcopy(self.connectivity['samples'])
                result['servers']=[{**{k:s.get(k) for k in ('id','name','dns_host','dns_port','type')},'health':copy.deepcopy(self.health.get(s['id'],{}))} for s in self.servers()]
                result['actions']=copy.deepcopy(getattr(self,'events',[]))[-100:]
                result['limits']='Gemeten vanaf de VenGuard-container; geen bewijs van client-DNS, wifi, alle upstreams, providerstoring of oorzaak. Extern: alleen TCP naar twee IPv4-adressen. Geen metingen tijdens uitgeschakelde VenGuard.'
            return result
