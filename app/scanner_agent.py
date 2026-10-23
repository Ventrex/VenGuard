"""Linux LAN discovery helper. No listening server, routing or Docker socket.

Host networking and NET_RAW are used only for Nmap host discovery/ICMP.
"""
import concurrent.futures
import ipaddress
import json
import os
import subprocess
import time
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT=Path(os.getenv('VENGUARD_NETWORK_DIR','/network'))

def parse_nmap(raw):
    devices=[]
    for host in ET.fromstring(raw).findall('host'):
        if host.find('status') is None or host.find('status').get('state')!='up':continue
        ip=host.find("address[@addrtype='ipv4']");mac=host.find("address[@addrtype='mac']");name=host.find('hostnames/hostname')
        if ip is None:continue
        devices.append({'ip':ip.get('addr'),'mac':mac.get('addr','').lower() if mac is not None else '', 'vendor':mac.get('vendor','') if mac is not None else '', 'hostname':name.get('name','') if name is not None else '', 'method':host.find('status').get('reason','nmap')})
    return devices

def scan(subnets):
    if not subnets or len(subnets)>4:raise ValueError('Geen geldige lokale subnetten ingesteld.')
    for subnet in subnets:
        net=ipaddress.ip_network(subnet)
        if net.version!=4 or net.num_addresses>256 or not all(any(ip in ipaddress.ip_network(r) for r in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')) for ip in (net.network_address,net.broadcast_address)):raise ValueError('Alleen kleine lokale IPv4-subnetten zijn toegestaan.')
    # No service/OS/vulnerability scan; at most 20 discovery probes per second.
    result=subprocess.run(['nmap','-sn','--max-rate','20','--max-retries','1','--host-timeout','5s','-oX','-',*subnets],capture_output=True,timeout=90)
    if result.returncode:raise ValueError('Nmap-scan mislukt; controleer subnet, hostnetwerk en NET_RAW.')
    if len(result.stdout)>2*1024*1024:raise ValueError('Scanresultaat te groot.')
    return parse_nmap(result.stdout)

def audit_domain(host):
    # Resolve through the host's configured resolver. A blocklist may deliberately prevent this.
    try:
        result=subprocess.run(['getent','ahostsv4',host],capture_output=True,text=True,timeout=4)
        if result.returncode or not result.stdout:return {'dns':False,'ping':None,'message':'Geen DNS-antwoord. Dit kan juist een actieve DNS-blokkade zijn; niet automatisch verwijderen.'}
        address=result.stdout.split()[0];ip=ipaddress.ip_address(address)
        if not ip.is_global:return {'dns':True,'ping':None,'address':address,'message':'DNS geeft een lokaal of blokkeeradres. Geen ping uitgevoerd.'}
        started=time.monotonic();ping=subprocess.run(['ping','-n','-c','1','-W','1','--',address],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3)
        return {'dns':True,'ping':ping.returncode==0,'address':address,'ms':round((time.monotonic()-started)*1000,1) if ping.returncode==0 else None,'message':'Ping ontvangen; dit bewijst niet dat een filterregel nodig of overbodig is.' if ping.returncode==0 else 'Geen pingantwoord. ICMP kan geblokkeerd zijn; dit bewijst niet dat het domein vervallen is.'}
    except (ValueError,OSError,subprocess.TimeoutExpired):return {'dns':None,'ping':None,'message':'Controle niet bevestigd; regel blijft behouden.'}

def cycle(config,last_scan,last_audit):
    report={'devices':[],'complete':False,'subnets':config.get('subnets',[])}
    now=time.time()
    if config.get('enabled') and now-last_scan>config.get('interval',120):
        try:report.update(devices=scan(report['subnets']),complete=True)
        except Exception as error:report['error']=str(error)
        last_scan=now
    job=config.get('audit_job')
    if job and job['id']!=last_audit:
        hosts=job.get('domains',[])[:25]
        if any(not isinstance(h,str) or len(h)>253 or not all(c.isalnum() or c in '.-' for c in h) for h in hosts):raise ValueError('Ongeldige controlevraag.')
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(audit_domain,hosts))
        report.update(audit_id=job['id'],audit=dict(zip(hosts,results)))
        last_audit=job['id']
    return report,last_scan,last_audit

def main():
    last_scan=0;last_audit='';last_request=None
    while True:
        try:
            config=json.loads((ROOT/'scanner.json').read_text());token=json.loads((ROOT/'agent-token').read_text())['token']
            if config.get('scan_request')!=last_request:last_scan=0;last_request=config.get('scan_request')
            report,new_scan,new_audit=cycle(config,last_scan,last_audit)
            url=(config.get('url') or os.getenv('VENGUARD_AGENT_URL','http://127.0.0.1:8098')).rstrip('/')+'/api/network/report'
            req=urllib.request.Request(url,data=json.dumps(report).encode(),headers={'Content-Type':'application/json','X-VenGuard':'1','X-VenGuard-Agent':token})
            # No redirects: the agent token must never be forwarded elsewhere.
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self,*args,**kwargs):return None
            with urllib.request.build_opener(NoRedirect()).open(req,timeout=10) as response:
                if response.status==200:last_scan=new_scan;last_audit=new_audit
        except Exception:
            # No URLs, tokens or inventory in stdout. Stale heartbeat is visible in VenGuard.
            pass
        time.sleep(15)
if __name__=='__main__':main()
