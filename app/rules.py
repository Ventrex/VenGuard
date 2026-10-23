"""Conservative DNS-only import and a small, explicit Dutch domain catalogue."""
import ipaddress
import re
from collections import Counter
from catalog import COMPATIBILITY

# Descriptions are local annotations, not live reputation or malware verdicts.
CATALOGUE = [
    ('advertising-module.api.dpgmedia.cloud', 'DPG-advertenties', 'Advertentiemodule bij DPG Media, onder meer op Nederlandse nieuwssites.', 'dpg_ads', 'Functie afgeleid uit domeinnaam en aangeleverde NU.nl-log; geen live verificatie.'),
    ('creative.dpgdsp-adv-prod.dpgmedia.cloud', 'DPG-advertenties', 'Waarschijnlijk advertentiemateriaal van het DPG-advertentieplatform.', 'dpg_ads', 'Waarschijnlijke functie op basis van naam en context.'),
    ('prebid-server.dpgmedia.net', 'DPG-advertenties', 'Waarschijnlijk advertentieveilingen via Prebid bij DPG Media.', 'dpg_ads', 'Waarschijnlijke functie op basis van naam en context.'),
    ('prebid.optinadserving.com', 'Advertenties', 'Waarschijnlijk een Prebid-advertentieveiling.', 'dpg_ads', 'Waarschijnlijke functie op basis van naam en context.'),
    ('tracking-module.api.dpgmedia.cloud', 'DPG-metingen', 'Waarschijnlijk een module voor bezoekers- of gebruiksmetingen bij DPG Media.', 'dpg_tracking', 'Waarschijnlijke functie op basis van naam en context.'),
    ('tracking-module.tracking.dpgmedia.cloud', 'DPG-metingen', 'Waarschijnlijk bezoekers- of gebruiksmetingen bij DPG Media.', 'dpg_tracking', 'Waarschijnlijke functie op basis van naam en context.'),
    ('collector.brandmetrics.com', 'Publieksmeting', 'Waarschijnlijk meting van het effect van advertenties via Brand Metrics.', 'measurement', 'Lokale beschrijving; geen live onderzoek.'),
    ('end.nmo-ep.nl', 'Nederlandse publieksmeting', 'Waarschijnlijk een endpoint voor het Nationaal Media Onderzoek.', 'measurement', 'Waarschijnlijke functie op basis van naam en context.'),
    ('nmodpgendpoint.2cnt.net', 'Nederlandse publieksmeting', 'Waarschijnlijk publieksmeting voor DPG Media / NMO.', 'measurement', 'Waarschijnlijke functie op basis van naam en context.'),
    ('nmoendpoint.northeurope.cloudapp.azure.com', 'Nederlandse publieksmeting', 'Waarschijnlijk NMO-publieksmeting op Microsoft Azure.', 'measurement', 'Waarschijnlijke functie op basis van naam en context.'),
    ('region1.app-analytics-services-att.com', 'App-metingen', 'Waarschijnlijk app-analyses; de precieze eigenaar is hier niet vastgesteld.', 'measurement', 'Lage zekerheid; gebaseerd op domeinnaam.'),
    ('mask.icloud.com', 'Apple Privédoorgifte', 'Onderdeel van iCloud Privédoorgifte. Een DNS-verzoek bewijst niet dat de functie actief is.', 'relay', 'Apple documenteert mask.icloud.com en mask-h2.icloud.com voor Privédoorgifte.'),
    ('mask-h2.icloud.com', 'Apple Privédoorgifte', 'Onderdeel van iCloud Privédoorgifte. Blokkeren schakelt privacybescherming op dit netwerk mogelijk uit.', 'relay', 'Apple-documentatie.'),
    ('mask.apple-dns.net', 'Apple-netwerkdienst', 'Apple-domein in deze log. De precieze rol is hier niet geverifieerd; niet automatisch blokkeren.', None, 'Onvoldoende zekerheid.'),
    ('gateway.icloud.com', 'Apple iCloud', 'Apple iCloud-dienst; dit verzoek alleen is geen aanwijzing voor reclame.', None, 'Algemene domeinkennis; precieze functie niet vastgesteld.'),
    ('login.dpgmedia.net', 'DPG-inloggen', 'Inlogdienst van DPG Media. Blokkeren kan aanmelden verstoren.', None, 'Functie afgeleid uit naam en context.'),
    ('myprivacy-static.dpgmedia.net', 'DPG-privacykeuze', 'Waarschijnlijk bestanden voor privacy- of toestemmingskeuzes. Niet standaard blokkeren.', None, 'Waarschijnlijke functie op basis van naam en context.'),
    ('graph.nu.nl', 'NU.nl-inhoud', 'Waarschijnlijk een inhouds-API voor NU.nl. Blokkeren kan artikelen of de site verstoren.', None, 'Waarschijnlijke functie op basis van naam en context.'),
]
PACKS = [
    {'id':'dpg_ads','name':'DPG-advertenties','description':'Gerichte advertentie-endpoints uit je NU.nl-log. Kan videoreclame of onderdelen van een pagina verstoren.','enabled':True},
    {'id':'dpg_tracking','name':'DPG-metingen','description':'Gerichte trackingmodules bij Nederlandse DPG-sites.','enabled':True},
    {'id':'measurement','name':'Nederlandse publieksmetingen','description':'NMO en enkele meetdiensten. Optioneel; kan statistieken of spelers beïnvloeden.','enabled':False},
    {'id':'relay','name':'Apple Privédoorgifte blokkeren','description':'Optioneel: blokkeert de twee door Apple gedocumenteerde relay-hosts. Vermindert privacybescherming en kan een Apple-melding geven.','enabled':False},
]

def domain(value):
    if not isinstance(value, str):
        raise ValueError('Vul een domeinnaam in.')
    value = value.strip().lower().rstrip('.')
    if not value or len(value) > 253 or any(c in value for c in '/:@*^$|?#\\'):
        raise ValueError('Gebruik alleen een domeinnaam, zonder https://, pad of wildcards.')
    try:
        ipaddress.ip_address(value)
        raise ValueError('Gebruik een domeinnaam, geen IP-adres.')
    except ValueError as e:
        if str(e).startswith('Gebruik '):
            raise
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError:
        raise ValueError('Ongeldige domeinnaam.')
    labels = value.split('.')
    if len(labels) < 2 or len(labels[-1]) < 2 or labels[-1].isdigit():
        raise ValueError('Gebruik een volledige domeinnaam, bijvoorbeeld reclame.example.nl.')
    if not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p) for p in labels):
        raise ValueError('Ongeldige domeinnaam.')
    return value

def suffixes(d):
    labels=d.split('.')
    return ['.'.join(labels[i:]) for i in range(len(labels)-1)]

def scope(value):
    if not value:
        return ''
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False)) if '/' in value else str(ipaddress.ip_address(value.strip()))
    except ValueError:
        raise ValueError('Gebruik als apparaat een IPv4/IPv6-adres of CIDR-bereik; laat leeg voor iedereen.')

def parse_list(text):
    """Only complete DNS domains, hosts entries and unmodified ||domain^ rules.

    Browser URL paths, cosmetic rules, regexes, modifiers and rewrites are
    deliberately skipped instead of broadening their blocking scope.
    """
    rules=set(); counts=Counter(); examples=[]
    for raw in text.splitlines():
        line=raw.strip().lstrip('\ufeff')
        if not line or line.startswith(('!','#','[')):
            counts['comments']+=1; continue
        candidates=[]; allow=False
        if re.fullmatch(r'(?:@@)?\|\|[^\s^]+\^',line):
            allow=line.startswith('@@'); candidates=[line[4:-1] if allow else line[2:-1]]
        else:
            parts=re.split(r'\s+#',line,maxsplit=1)[0].split()
            if len(parts)>1 and parts[0] in ('0.0.0.0','127.0.0.1','::','::1'):
                candidates=parts[1:]
            elif len(parts)==1:
                candidates=parts
        accepted=False
        for candidate in candidates:
            try:
                d=domain(candidate)
                if d in ('localhost.localdomain','broadcasthost.localdomain'):
                    continue
                rules.add(('@@' if allow else '')+'||'+d+'^'); accepted=True
            except ValueError:
                pass
        if accepted:
            counts['accepted_lines']+=1
        else:
            counts['skipped']+=1
            if len(examples)<5: examples.append(line[:150])
    return sorted(rules),dict(counts),examples

def explain(d):
    for host,category,description,pack,evidence in CATALOGUE:
        if d==host or d.endswith('.'+host):
            return {'category':category,'description':description,'evidence':evidence,'pack':pack,'known':True}
    for host,label in [('akamaiedge.net','Akamai'),('akamai.net','Akamai'),('edgekey.net','Akamai'),('amazonaws.com','Amazon AWS'),('awsglobalaccelerator.com','Amazon AWS'),('cloudapp.azure.com','Microsoft Azure')]:
        if d==host or d.endswith('.'+host):
            return {'category':'Gedeelde infrastructuur','description':f'{label} levert infrastructuur voor veel diensten. De naam vertelt niet of dit reclame of noodzakelijke inhoud is.','evidence':'Bekende infrastructuur; individuele dienst onbekend.','pack':None,'known':True}
    return {'category':'Onbekend','description':'Geen betrouwbare lokale uitleg beschikbaar. Bekijk de aanleiding en controleer het domein voordat je blokkeert.','evidence':'Geen classificatie; dit is geen veiligheidsbeoordeling.','pack':None,'known':False}

def rule_text(item):
    return ('@@' if item['action']=='allow' else '')+'||'+item['domain']+'^'+('$client='+item['client'] if item.get('client') else '')

def compose(config,caches,observed):
    merged=set(); origins={}; stats=[]
    # Match an observed subdomain against parent-domain rules too.
    used=set()
    for d in observed:
        used.update(suffixes(d))
    for source in config['sources']:
        cached=caches.get(source['id'],{})
        chosen=[];duplicates=0
        if source['enabled'] and config.get('categories',{}).get(source.get('category','custom'),True):
            for r in cached.get('rules',[]):
                d=r[4:-1] if r.startswith('@@') else r[2:-1]
                # Keep exceptions even in observed mode to preserve upstream intent.
                if config['mode']=='all' or r.startswith('@@') or d in used:
                    chosen.append(r)

            duplicates=len(set(chosen)&merged)
            merged.update(chosen)
        stats.append({**source,'rules':len(cached.get('rules',[])),'selected':len(chosen),'duplicates':duplicates,'skipped':cached.get('counts',{}).get('skipped',0),'examples':cached.get('examples',[]),'fetched':cached.get('fetched'),'error':cached.get('error',''),'cached_fallback':bool(cached.get('error') and cached.get('rules'))})
    for host,_,_,pack,_ in CATALOGUE:
        if pack and config['packs'].get(pack,False):
            merged.add('||'+host+'^'); origins.setdefault(host,[]).append('Nederlands keuzepakket')
    for item in config['rules']:
        if item.get('enabled',True):
            merged.add(rule_text(item)); origins.setdefault(item['domain'],[]).append('Eigen '+item['action'])
    for preset in COMPATIBILITY:
        if config.get('compatibility',{}).get(preset['id'],False):
            for host in preset['domains']:
                merged.add('@@||'+host+'^');origins.setdefault(host,[]).append('Bereikbaarheid: '+preset['name'])
    # Ordinary allow rules are emitted unchanged. Advanced AdGuard rules outside
    # this generated list may affect their priority; use check_host to verify.
    lines=sorted(merged)
    return lines,stats,origins
