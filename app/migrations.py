"""Preserve earlier user choices without shipping site-specific UI presets."""
import secrets

LEGACY_RULES=[('advertising-module.api.dpgmedia.cloud', 'dpg_ads'),
 ('creative.dpgdsp-adv-prod.dpgmedia.cloud', 'dpg_ads'),
 ('prebid-server.dpgmedia.net', 'dpg_ads'),
 ('prebid.optinadserving.com', 'dpg_ads'),
 ('tracking-module.api.dpgmedia.cloud', 'dpg_tracking'),
 ('tracking-module.tracking.dpgmedia.cloud', 'dpg_tracking'),
 ('collector.brandmetrics.com', 'measurement'),
 ('end.nmo-ep.nl', 'measurement'),
 ('nmodpgendpoint.2cnt.net', 'measurement'),
 ('nmoendpoint.northeurope.cloudapp.azure.com', 'measurement'),
 ('region1.app-analytics-services-att.com', 'measurement'),
 ('mask.icloud.com', 'relay'),
 ('mask-h2.icloud.com', 'relay')]

def migrate(config):
    done=config.setdefault("migrations",[])
    if 'stable-lists-v2' not in done:
        if config.get('mode')=='observed':config['mode']='all';config['mode_migration']='Compacte modus vervangen door volledige bronnen. Gezien verkeer verkleint de lijst niet meer automatisch.'
        done.append('stable-lists-v2')
    if "general-filtering-v13" in done:return
    existing={r["domain"] for r in config["rules"]}
    for host,pack in LEGACY_RULES:
        if config.get("packs",{}).get(pack,False) and host not in existing:
            config["rules"].append({"id":secrets.token_hex(6),"domain":host,"action":"block","match":"suffix","client":"","enabled":True,"note":"Overgenomen domeinregel uit eerder keuzepakket"});existing.add(host)
    for host,key in [("marktplaats.nl","marktplaats"),("ing.nl","ing")]:
        if config.get("compatibility",{}).get(key) and host not in existing:
            config["rules"].append({"id":secrets.token_hex(6),"domain":host,"action":"allow","match":"suffix","client":"","enabled":False,"note":"Eerdere brede uitzondering; uitgeschakeld. Sta zo nodig alleen het noodzakelijke subdomein toe."})
    config["packs"]={};config.pop("compatibility",None);done.append("general-filtering-v13")
