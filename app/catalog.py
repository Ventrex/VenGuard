"""Explicit source categories; optional presets never activate on upgrade."""
CATEGORIES={'ads':'Advertenties & tracking','security':'Malware & phishing','adult':'Volwassen inhoud','gambling':'Gokken','social':'Sociale media','custom':'Eigen / overige lijsten'}
BASE='https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/'
PRESETS=[
 {'id':'light','name':'HaGeZi Light','category':'ads','url':BASE+'light.txt','description':'Algemene, terughoudende basis voor advertenties en tracking; ook Nederlandse websites. Bevat eveneens beveiligingsregels.'},
 {'id':'tif','name':'HaGeZi Threat Intelligence Mini','category':'security','url':BASE+'tif.mini.txt','description':'Aanvullende lijst tegen malware, phishing en andere bedreigingen. Geen garantie dat iedere onveilige site wordt herkend.'},
 {'id':'adult','name':'HaGeZi NSFW','category':'adult','url':BASE+'nsfw.txt','description':'Blokkeert domeinen voor volwassen inhoud. Kan geen afzonderlijke video’s, afbeeldingen of pagina’s beoordelen.'},
 {'id':'gambling','name':'HaGeZi Gambling Mini','category':'gambling','url':BASE+'gambling.mini.txt','description':'Blokkeert gokdomeinen, ook buiten Nederland. Categorieën zijn afhankelijk van de bronbeheerder.'},
]
COMPATIBILITY=[
 {'id':'marktplaats','name':'Marktplaats bereikbaar houden','domains':['marktplaats.nl'],'description':'Staat marktplaats.nl en subdomeinen toe. Als afbeeldingen of betalingen nog falen, controleer de extra domeinen in Netwerkactiviteit.'},
 {'id':'ing','name':'ING bereikbaar houden','domains':['ing.nl'],'description':'Staat ing.nl en subdomeinen toe. Andere betaalproviders worden niet automatisch toegestaan; controleer die gericht via het log.'},
]
