"""Conservative DNS-only import and a small, explicit Dutch domain catalogue."""
import ipaddress
import re
from collections import Counter
import time

CATALOGUE=[]
PACKS=[]

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
    # Transparent hints, never a brand-specific whitelist or a reputation verdict.
    labels=d.lower().replace('-','.').split('.')
    hints=[(('ads','ad','advertising','advertisement','prebid','adserver'),'Mogelijke advertenties','De naam kan op een advertentiedienst wijzen. Controleer het gebruik voordat je blokkeert.'),
           (('tracking','tracker','analytics','metrics','telemetry','measurement'),'Mogelijke metingen','De naam kan op tracking of gebruiksmeting wijzen. Dit is niet geverifieerd.'),
           (('payment','payments','checkout','pay','auth','login','identity'),'Mogelijke sitefunctie','De naam kan op aanmelden, afrekenen of een andere sitefunctie wijzen. Maak zo nodig een gerichte uitzondering.'),
           (('cdn','static','assets','images'),'Gedeelde bestanden','Dit kan inhoud, afbeeldingen of andere bestanden leveren. Blokkeren kan zichtbare functies verstoren.')]
    for words,category,description in hints:
        if set(labels)&set(words):return {'category':category,'description':description,'evidence':'Indicatie op basis van domeinnaam; geen inhoudsanalyse of veiligheidsbeoordeling.','pack':None,'known':False}
    return {'category':'Niet geclassificeerd','description':'Geen geverifieerde functie bekend. Bekijk het moment, het apparaat en de toegepaste filterregel voordat je beslist.','evidence':'Geen automatische reputatie- of inhoudsbeoordeling.','pack':None,'known':False}

def rule_text(item):
    prefix='@@' if item['action']=='allow' else ''
    # An anchored regex makes an exact DNS hostname explicit and cannot widen to a parent.
    pattern='/^'+re.escape(item['domain'])+'[.]?$/' if item.get('match','suffix')=='exact' else '||'+item['domain']+'^'
    return prefix+pattern+('$client='+item['client'] if item.get('client') else '')

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
        if not config.get('direct_rules',False) and item.get('enabled',True) and (not item.get('expires_at') or item['expires_at']>time.time()):
            merged.add(rule_text(item)); origins.setdefault(item['domain'],[]).append('Eigen '+item['action'])
    # Ordinary allow rules are emitted unchanged. Advanced AdGuard rules outside
    # this generated list may affect their priority; use check_host to verify.
    lines=sorted(merged)
    return lines,stats,origins
