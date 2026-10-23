# VenGuard

**VenGuard 2.0** is een centrale beheerschil voor **AdGuard Home en Pi-hole v6**. Combineer DNS-filterbronnen zonder dubbele regels, bekijk verzoeken van meerdere servers en pas gerichte uitzonderingen rechtstreeks toe. Dark mode is standaard; light mode wordt per browser onthouden.

## Installeren en bijwerken

Benodigd: een Linux-host met Docker Engine en Docker Compose v2. Gebruik op Proxmox een Linux-VM of geschikte Docker-LXC.

```bash
git clone https://github.com/Ventrex/VenGuard.git
cd VenGuard
bash start.sh
```

Het script bouwt de container, maakt een installatiewachtwoord in `.env` en toont het adres, doorgaans `http://IP-VAN-JE-NUC:8098`. Docker ontbreekt? Gebruik de [officiële installatiehandleiding](https://docs.docker.com/engine/install/). Bij ontbrekende Docker-rechten kun je `sudo bash start.sh` gebruiken.

Bijwerken vanuit je bestaande VenGuard-map:

```bash
bash update.sh
```

Het datavolume, account, serverkoppelingen en eigen regels blijven behouden. Eerdere keuzepakketten worden eenmalig overgenomen als gewone domeinregels. Eerdere brede bereikbaarheidspresets worden als **uitgeschakelde** regels bewaard: controleer zo nodig het werkelijk benodigde subdomein. Nieuwe installaties bevatten geen voorgedefinieerde website-uitzonderingen of uitgeverspakketten.

## Vier compacte onderdelen

- **Centraal beheer:** klikbaar dashboard met de gepubliceerde VenGuard-regels, bereikbare DNS-servers, actieve AdGuard-lijsten, regels op de servers en online/offline apparaten. Klik door naar het bijbehorende beheer. Serverdetails blijven ingeklapt onder de naam en status.
- **Adblocker voor AdGuard:** bronnen samenvoegen, categorieën en lijsten schakelen, DNS-verzoeken bekijken en eigen tijdelijke of blijvende uitzonderingen beheren.
- **Netwerk:** apparaten ontdekken, namen/type/notities invullen, online/offline/onbekend en laatst online bekijken.
- **Instellingen:** het centrale AdGuard-profiel, servers, lijstpublicatie, account/2FA en beveiliging. Dark mode is standaard; light mode wordt onthouden.

## VenGuard is de bron voor de instellingen

Bij de eerste start na de update neemt VenGuard de gedeelde instellingen van de bestaande geselecteerde AdGuard-server over. Die staan daarna zelfstandig in `/data/desired-settings.json`. Je kunt dit ook expliciet doen bij **Instellingen → Instellingen overnemen**. Dit is een eenmalige import; de oorspronkelijke server hoeft vervolgens niet online te zijn om een andere server in te richten.

1. Installeer AdGuard Home en rond alleen de eerste installatiewizard af: web/DNS-binding en gebruikersnaam/wachtwoord. De DNS-poort moet beschikbaar zijn. Geen filterlijsten handmatig toevoegen.
2. Voeg de server in VenGuard toe via **Instellingen → AdGuard-servers**. Gebruik de werkelijke beheer-URL/webpoort en het aparte DNS-IP/poort (meestal 53).
3. Vul het bereikbare **LAN-adres van VenGuard** in, bijvoorbeeld `http://192.168.0.10:8098`. Gebruik geen `localhost` als een andere host de lijst moet ophalen.
4. VenGuard stuurt het opgeslagen profiel naar alle ingeschakelde AdGuard-servers en koppelt de eigen samengestelde filterlijst. Per server zie je welke profielversie is bevestigd of welke fout nog openstaat.
5. Bewerk gedeelde instellingen voortaan in VenGuard. Wijzigingen rechtstreeks in AdGuard worden bij de volgende vergelijking teruggezet naar het VenGuard-profiel. Voeg extra bronnen bij voorkeur toe als VenGuard-bron, zodat ze in dezelfde deduplicatie vallen.

Het profiel beheert upstreams/cache, toegangsregels, eigen native AdGuard-regels, DNS-herschrijvingen, apparaatinstellingen, geblokkeerde diensten, Safe Browsing/Safe Search/ouderlijk toezicht, verzoekenlog/statistiekconfiguratie, native filterabonnementen en bescherming/filterstand. De API past alleen afwijkende waarden aan en leest ze terug ter bevestiging. Servers worden achtereenvolgens ingericht. Luisteradressen/poorten, DHCP, TLS-bestanden en loginaccounts blijven per server ingesteld; die kun je niet veilig blind klonen. Het is dus geen volledige kopie van `AdGuardHome.yaml`.

De achtergrondvergelijking loopt iedere twee minuten en direct na een wijziging. Een onbereikbare server blijft niet bevestigd en krijgt later een nieuwe poging. De oude Go Sync-engine blijft voor compatibiliteit in de image aanwezig, maar voert geen automatische bron-naar-replica-rondes meer uit zodra het centrale profiel actief is. Stop een los draaiende AdGuard Sync om twee concurrerende beheerders te voorkomen.

DNS-aanvragen gaan rechtstreeks naar je AdGuard/Pi-hole-servers. Een VenGuard-uitval onderbreekt hun opgeslagen DNS-configuratie niet. Je router/DHCP moet beide DNS-IP's uitdelen; VenGuard kan dat niet via je Deco instellen. Twee servers op dezelfde fysieke host beschermen niet tegen een hoststoring. Dit is een verschil tussen centraal **beheer** en de route van het DNS-verkeer, geen ontbrekende synchronisatie.

Pi-hole v6 gebruikt de gedeelde VenGuard-filterfeeds, eigen domeinregels, verzoekenlog en blokkeringsstand. Het AdGuard-profiel wordt niet naar Pi-hole vertaald. Gebruik bij Pi-hole-2FA een app-wachtwoord. URLs met `/control` (AdGuard) of `/admin`/`/api` (Pi-hole) worden herkend; certificaatvalidatie blijft aan.

## Waarom 600.000 regels opeens 53 konden worden

De vroegere modus **Alleen gezien** selecteerde alleen bronregels voor recent waargenomen domeinen. Die selectie kon veel kleiner zijn dan de gedownloade bronnen. Versie 2.0 migreert bestaande installaties één keer naar **Volledige bronnen**. Je kunt daarna bewust opnieuw een compacte selectie kiezen, maar dat is niet de standaard.

Het dashboard onderscheidt de unieke gepubliceerde VenGuard-bronregels van de aantallen die AdGuard rapporteert. De AdGuard-telling is een som over servers en kan dezelfde regels dus meerdere keren bevatten. Eigen live-regels staan apart van de bronlijst. Een gedownloade bron die meer dan 80% krimpt na minimaal 1.000 bestaande regels wordt niet blind gepubliceerd: de laatste goede cache blijft actief met een foutmelding. Ook een ontbrekende actieve bron mag een grote bestaande publicatie niet vervangen. Bewust uitschakelen/verwijderen van bronnen blijft mogelijk. Deze controles bewijzen niet achteraf wat de oorzaak van jouw eerdere telling was.

## Filterbronnen samenvoegen

Begin met de algemene basis **HaGeZi Light** en voeg naar behoefte eigen publieke HTTPS-bronnen of optionele beveiligings-/inhoudslijsten toe. Nederlandse en internationale domeinlijsten worden op dezelfde manier verwerkt. Er zijn geen ingebouwde website-uitzonderingen of uitgeverspakketten. Categorieën zijn beheerlabels; je kunt een bron of categorie uitschakelen zonder verwijderen. Bekijk per bron aantallen, overlap, laatste download en fouten.

Standaard wordt elke 24 uur bijgewerkt; kies 6, 12, 24 of 48 uur bij Instellingen. Mislukte downloads behouden de laatste goede cache. Complete domeinregels, hostsregels en eenvoudige `||domein^`/`@@||domein^` worden overgenomen. Browserregels, URL-paden, regexen en geavanceerde modifiers uit externe bronnen worden overgeslagen, niet verbreed. Limieten: 30 bronnen, 24 MiB per download, 1 miljoen opgeslagen bronregels. Losse native AdGuard-abonnementen onder de geavanceerde lijstopties vallen niet in de VenGuard-deduplicatie; importeer ze als bron en schakel het oude abonnement uit om overlap te vermijden.

## DNS- en pingcontrole van regels

Open **Adblocker → Mijn filterlijst**. Controleer één domein of een steekproef van maximaal 25 domeinen uit de gepubliceerde lijst. De scanneragent doet een DNS-opzoeking en, bij een publiek IPv4-adres, een ICMP-ping. De resultaten blijven zichtbaar met tijdstip. Er is bewust geen automatische verwijdering.

Een ping-timeout betekent niet dat een domein verouderd is: veel servers weigeren ICMP. Een mislukte DNS-opzoeking kan juist door je eigen adblocker komen. Ook een tijdelijke fout of opgeheven hostnaam bewijst niet dat een toekomstige blokkaderegel overbodig is. De scan gebruikt de DNS-resolver van de Docker-host en beoordeelt geen website-inhoud.

## Netwerkscanner

`bash update.sh` bouwt en start ook de afzonderlijke **venguard-scanner**. Schakel scannen bij **Netwerk** in en vul je eigen lokale IPv4-subnet in, bijvoorbeeld `192.168.0.0/24`. Maximaal vier privé-subnetten van ieder 256 adressen; iedere twee minuten een Nmap-hostdetectie, geen poortscan. **Opslaan & scannen** vraagt een nieuwe scan aan.

De scanner vindt waar mogelijk IP, MAC, hostnaam en fabrikant op basis van het MAC-prefix. Een fabrikant is geen zekere apparaatidentificatie. Zelf ingevulde naam, type en notities blijven bewaard. Een reactie betekent online; na drie volledige succesvolle scans zonder reactie wordt een apparaat offline. Bij ontbrekende/oude scannerdata blijft de status onbekend, met de laatst geziene tijd. Slapende apparaten kunnen onterecht offline lijken. MAC-randomisatie en wisselende IP's kunnen dubbele of veranderde herkenning geven.

De aparte Linux Docker-helper gebruikt host-netwerk en uitsluitend `NET_RAW` voor hostdetectie. Geen Docker-socket, `NET_ADMIN`, privileged mode of inkomende scannerpoort. Hij deelt alleen scannerconfiguratie en een eigen beperkt report-token met de webcontainer; niet de AdGuard-loginbestanden. De hoofdcontainer blijft zonder netwerkcapabilities. `venguard-network` is het afzonderlijke gedeelde volume. Bij een aangepaste bind-poort/hostnaam moet de agent het ingestelde VenGuard-adres kunnen bereiken.

Detectie kan alleen apparaten zien die vanaf de NUC bereikbaar zijn. Gastnetwerken, IoT-isolatie, VLANs en mesh kunnen MAC-informatie of alle antwoorden afschermen. Er is geen uitlezing van de Deco-DHCP-tabel. Dit vervangt geen routermonitor of packet capture en ziet niet al het in-/uitgaande verkeer.

**Internet blokkeren:** met de Deco XE75 Pro is hiervoor geen ondersteunde koppeling ingebouwd. Gebruik de Deco-app voor een echte apparaatblokkade. VenGuard toont dit bij het apparaat en doet niet alsof een DNS-blokkade alle internetverkeer stopt.

## Verbindingsproblemen onderzoeken

Bij **Centraal beheer → DNS-servers bereikbaar** zie je afzonderlijk DNS, beheer-API en filtering. Technische gegevens zijn uitklapbaar. Een beheerfout bewijst geen DNS-uitval; een opgeslagen gewenste stand is pas toegepast als de server die bevestigt.

- Iedere 15 seconden een onafhankelijke UDP-DNS-test naar elk ingesteld DNS-IP voor `example.org`, met één herhaling en TCP-test bij problemen. SERVFAIL, REFUSED, NXDOMAIN, lege antwoorden en blokkeeradressen worden onderscheiden van een ontbrekend antwoord.
- TCP-bereikbaarheid naar `1.1.1.1:443` en `8.8.8.8:443`, zonder DNS. Mislukking van beide bewijst geen providerstoring.
- API-, TLS-, route- en poortfouten blijven apart zichtbaar. **Nu controleren** start op de achtergrond; een trage beheeractie houdt DNS-metingen niet tegen.
- Storingshistorie: maximaal 200 incidenten en 24 uur meetpunten. Download een rapport met tijden, fouten en recente beheeracties, zonder servercredentials/lijsttokens/verzoekenlog. Een tijdsovereenkomst is geen bewezen oorzaak. De rapportage blijft in `/data/connectivity.json` bewaard.
- Browserverbindingsfouten staan apart van servermetingen. Filterdiagnose leest de globale schakelaars en eventuele apparaatuitzonderingen.

**Waar komt `example.org` vandaan?** Dat is VenGuards eigen DNS-testnaam. De VenGuard-verzoekenpagina verbergt deze standaard; vink **Toon testnaam example.org** aan om die weer te zien. De originele AdGuard-log wordt niet verwijderd en blijft de controles tonen. De testnaam wordt niet als gebruikersactiviteit meegenomen in compacte lijstselectie. De DNS-check uitschakelen is niet nodig om de weergave op te ruimen.

Alle verbindingsmetingen komen vanuit de VenGuard-container. Ze bewijzen niet dat je telefoon dezelfde DNS gebruikt of dat wifi goed werkt. Een test kan uit DNS-cache komen en controleert niet alle upstreams. VenGuard leest geen historische host-, Docker-, kabel-, switch- of routerstoringen terug. De oorzaak van jouw bestaande uitval is zonder meetrapport/hostlogs nog niet vastgesteld. Bewaar een rapport na de volgende storing.

## Een vastlopende functie direct vrijgeven

1. Open **Netwerkactiviteit** en filter op het apparaat en **Geblokkeerd**.
2. Bekijk het tijdstip en de toegepaste filterregel. Een domeinnaam alleen bewijst niet wat de dienst doet.
3. Kies **Nu toestaan · 15 min** naast het benodigde verzoek. Dit maakt een exacte uitzondering; geen complete hoofdwebsite wordt automatisch toegestaan.
4. VenGuard past de regel rechtstreeks toe en toont hoeveel servers die bevestigen. De logpagina blijft open, inclusief je zoekfilters.
5. Beheer eindtijd, aan/uit en verwijderen bij **Eigen regels**. Met de gewone toestaan-/blokkeeractie kies je zelf het domeinbereik en de duur.

Bij alleen AdGuard geldt de snelle uitzondering voor het apparaat-IP uit het log. Bij Pi-hole of een gemengde groep gebruikt VenGuard globale regels in Pi-hole-standaardgroep **0**. Andere Pi-hole-groepen moet je daar zelf beheren; apparaat-IP-regels worden niet onveilig vertaald naar globale uitzonderingen.

**Direct toepassen betekent:** de volgende DNS-aanvraag gebruikt de nieuwe regel zodra de server die bevestigt. VenGuard kan een vastgelopen betaling, verbinding of app niet zelf hervatten en kan de DNS-cache van je iPhone niet op afstand wissen. Vaak kan de pagina/app opnieuw proberen; soms is een nieuwe verbindingspoging nodig. Dit is geen automatische herhaling van een betaling.

Eigen regels staan in een herkenbaar VenGuard-blok tussen de overige AdGuard-regels, of als herkenbaar beheerde Pi-hole-domeinen. Overige regels worden behouden. Dubbele, afwijkende bestaande Pi-hole-regels worden niet blind overschreven. De downloadbare bronlijst bevat de samengevoegde **bronnen**; eigen live-regels staan apart zodat een verouderde lijst een verwijderde uitzondering niet opnieuw kan activeren.

DNS kan advertenties van aparte advertentiedomeinen blokkeren. Het kan een gesponsord onderdeel en gewenste inhoud op **dezelfde hostnaam** niet inhoudelijk onderscheiden. Daarvoor is aanvullend een browserfilter nodig. De lokale uitleg bij een domein is een transparante naamindicatie, geen reputatiedienst of inhoudsanalyse.

## Back-ups vóór wijzigingen

Vóór een nieuwe profielversie bewaart VenGuard waar bereikbaar een AdGuard-snapshot in `/data/settings-backups` (maximaal 20). Vorige centrale profielen staan in `/data/profile-backups` (maximaal 20). Er is geen automatische rollback. Gedeeltelijke fouten blijven per server zichtbaar; een mislukking wordt niet als bevestigde synchronisatie weergegeven.

## Beveiliging en Wazuh

**VenGuard is geen router, firewall of DDoS-filter.** De hoofdcontainer heeft geen host-netwerkrechten, packet capture of firewallbevoegdheden. De aparte scanner gebruikt host-netwerk en NET_RAW uitsluitend voor hostdetectie en aangevraagde domeinchecks. De DNS-dienst blijft los van VenGuard werken.

De pagina **Beveiliging** toont:

- Mislukte en geslaagde aanmeldingen op VenGuard zelf, met bron-IP en tijd. Er worden maximaal 500 gebeurtenissen lokaal bewaard; het dashboard toont een selectie. Wachtwoorden, codes en sessietokens worden niet gelogd.
- Een tijdelijke aanmeldbeperking na 10 mislukte pogingen in 5 minuten per IP. Dit beperkt uitsluitend toegang tot VenGuard, niet tot andere servers of het netwerk.
- Een API-limiet van 120 verzoeken per minuut per IP, maximaal 32 gelijktijdige HTTP-verbindingen en een leestimeout voor onvolledige aanvragen. Dit begrenst de eigen app; het biedt geen garantie tegen DDoS.
- Een optionele **alleen-lezen Wazuh-indexerkoppeling**: maximaal 100 alerts met niveau 5 of hoger uit de laatste 30 minuten, iedere minuut opgehaald. Alleen de geselecteerde alertvelden worden opgehaald en getoond. Een lege selectie bewijst niet dat je hele netwerk veilig is.
- Expliciete dekkingsstatus: volledig netwerkverkeer en firewall-blokkering zijn **niet aangesloten**.

### Wazuh koppelen

Installeer Wazuh apart of gebruik een bestaande installatie. Richt agents/logbronnen in voor de servers en diensten die je wilt volgen. VenGuard installeert of herconfigureert geen Wazuh-manager, indexer of agents.

1. Maak in Wazuh/OpenSearch een afzonderlijk account met uitsluitend leesrechten op `wazuh-alerts-*`.
2. Open VenGuard **Beveiliging**, vul het indexer-adres in (meestal `https://HOST:9200`), gebruikersnaam en wachtwoord.
3. Schakel ophalen in, sla op en kies **Wazuh nu ophalen**.
4. Gebruik het **indexer**-adres, niet het Wazuh-dashboard of de manager-API op poort 55000.

Certificaatvalidatie blijft aan. Gebruik voor een eigen CA een vertrouwde certificaatketen in de container, bijvoorbeeld via een alleen-lezen CA-bundelmount en `SSL_CERT_FILE` in een Compose-override. Die bundel moet ook de gebruikelijke openbare CA’s bevatten, zodat HTTPS-downloads van filterbronnen blijven werken. Er is geen knop om TLS-validatie uit te zetten. Credentials staan uitsluitend in `/data/security.json` met rechten `0600`, buiten de instellingenexport. Bescherm het datavolume en back-ups.

Achter een reverse proxy: vul uitsluitend de daadwerkelijke proxy-IP’s/CIDR’s in bij **Vertrouwde reverse-proxy-IP’s**. Zonder deze instelling wordt het socket-IP gebruikt, zodat bezoekers niet zelf een ander IP kunnen opgeven via `X-Forwarded-For`. Een gedeeld proxy-IP kan dan ook een gedeelde aanmeldlimiet betekenen. De proxy moet inkomende forwardingheaders correct overschrijven of aanvullen. Vertrouw nooit het gehele internet als proxy.

### Naar een echte netwerkbeschermlaag

Voor volledige verkeersmetadata zijn flow- of sensorbronnen nodig op een plek waar het verkeer langs komt, bijvoorbeeld router/firewall-flowlogs of een geschikte netwerksensor. Wazuh kan meldingen uit die bronnen verzamelen; DNS-logs laten alleen DNS-aanvragen zien. Versleutelde inhoud is daarmee niet automatisch leesbaar.

Wazuh Active Response kan gericht aanvallende IP’s op ondersteunde endpoints laten blokkeren. Dat is een aparte configuratie met expliciete doelhosts, uitsluitingen en een tijdelijke blokkadeduur. VenGuard voert zulke blokkades in deze versie niet uit. Voordat een firewallkoppeling wordt toegevoegd, moeten router/firewall, publieke toegangsroutes, proxy/tunnel en beheer-/VPN-adressen bekend zijn. Zo voorkom je blokkeren van je eigen toegang of een proxy die al je bezoekers vertegenwoordigt.

Een bron-IP lokaal droppen is iets anders dan je internetlijn beschermen. Bij een volumetrische DDoS moet verkeer vóór je aansluiting worden gefilterd door een geschikte provider/upstreamdienst. Zelf een doeladres blackholen kan juist je eigen dienst onbereikbaar maken. Gebruik geen automatische blokkade uitsluitend op basis van een druk DNS-apparaat of een los Wazuh-signaal.

Officiële achtergrond: [Wazuh indexer API](https://documentation.wazuh.com/current/user-manual/indexer-api/index.html), [Wazuh Active Response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/ar-use-cases/blocking-ssh-brute-force.html), [Wazuh systeemeisen](https://documentation.wazuh.com/current/quickstart.html) en [volumetrische DDoS](https://www.cloudflare.com/learning/ddos/what-is-a-ddos-attack/).

## Eigen account en 2FA

1. Log in met het installatiewachtwoord uit `.env`.
2. Open **Account & 2FA** en kies een gebruikersnaam en wachtwoord van minimaal 12 tekens. Bevestig met het installatiewachtwoord.
3. Log opnieuw in. Het installatiewachtwoord geeft nu geen toegang meer tot de website.
4. Kies **2FA instellen**, bevestig je wachtwoord en voeg de getoonde sleutel handmatig aan je authenticator toe: TOTP, 6 cijfers, 30 seconden.
5. Bevestig met een code en bewaar de tien eenmalige herstelcodes. Controleer de systeemtijd van host en telefoon.

Er is één eigen beheerdersaccount; geen openbare registratie. Wachtwoorden worden met scrypt gehasht. Accountwijzigingen beëindigen bestaande sessies. Een TOTP-code wordt één keer geaccepteerd; wacht bij snel opnieuw inloggen op de volgende code. Herstelcodes werken één keer in plaats van een authenticatorcode. Passkeys zijn niet ingebouwd.

Gebruik bij voorkeur HTTPS via een vertrouwde reverse proxy en stel de beheerpoort niet rechtstreeks open op internet. Met `X-Forwarded-Proto: https` gebruikt VenGuard Secure-cookies. De 2FA-sleutel en gehashte herstelcodes staan lokaal in `/data/account.json` met rechten `0600`; bescherm je datavolume en back-ups.

Account/2FA kwijt? Gebruik eerst een herstelcode. Anders kun je met lokale Docker-beheertoegang uitsluitend het VenGuard-account herstellen:

```bash
docker compose exec venguard python3 reset_account.py
# Typ HERSTEL om het eigen account en 2FA te wissen.
docker compose restart venguard
sed -n 's/^VENGUARD_PASSWORD=//p' .env
```

Log daarna in met het installatiewachtwoord en maak opnieuw een eigen account. Filters en serverkoppelingen blijven behouden. Er is geen onbeveiligde web-resetknop.

## Beheer en back-up

```bash
bash update.sh
docker compose stop
docker compose start
docker compose logs --tail=50
```

Wijzig voor een andere webpoort `VENGUARD_PORT` in `.env`, voer `bash start.sh` uit en pas het VenGuard LAN-adres in de website aan. De interne poort blijft 8098.

Volledige back-up vanaf de Docker-host:

```bash
docker compose stop
mkdir -p backup
docker cp venguard:/data ./backup/
cp .env backup/.env
docker compose start
```

Deze back-up bevat de servercredentials en eventuele 2FA-sleutel. Herstel `data` naar `/data` in het Docker-volume en zet `.env` terug vóór starten. De instellingenexport laat credentials en het lijsttoken weg en is geen volledige back-up. Gebruik geen `docker compose down -v` als je het volume wilt bewaren.

## Ontwikkeling en verificatie

Python 3.12-standaardbibliotheek, HTML/CSS/JavaScript, Nmap/iputils in de aparte scanner en de gebundelde Go Sync-engine; geen PHP en geen pip-/npm-afhankelijkheden voor productie. De container draait niet als root, met alleen-lezen image en schrijfbare data in `/data`.

```bash
python3 -m unittest discover -s tests -v
node --check app/static/app.js
node --check app/static/hub.js
node --check app/static/filters.js
node --check app/static/account.js
node --check app/static/security.js
bash -n start.sh update.sh
```

GitHub Actions bouwt en start de productiecontainer, controleert authenticatie, test de echte gebundelde Sync-engine tegen lokale testservers en test Pi-hole tegen een officiële wegwerpcontainer en controleert de scanneragent. Een integratietest richt twee schone officiële AdGuard Home-servers in en past het opgeslagen profiel toe terwijl de oorspronkelijke server onbereikbaar is. `scripts/preview.py` is alleen een geïsoleerde UI-demo zonder echte servers of productie-authenticatie; gebruik die niet voor installatie.

## Bronnen en licenties

- [AdGuard API](https://github.com/AdguardTeam/AdGuardHome/blob/master/openapi/openapi.yaml)
- [AdGuard DNS-filterregels](https://adguard-dns.io/kb/general/dns-filtering-syntax/)
- [Pi-hole v6 API](https://docs.pi-hole.net/api/) en [sessieauthenticatie](https://docs.pi-hole.net/api/auth/)
- [Pi-hole officiële API-schema’s](https://github.com/pi-hole/FTL/tree/master/src/api/docs/content/specs)
- [HaGeZi DNS-lijsten](https://github.com/hagezi/dns-blocklists)
- [TOTP RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.html)

App-code: MIT. AdGuardHome Sync: Apache 2.0, zie `THIRD-PARTY-NOTICES.md` en `licenses/`. Externe filterbronnen behouden hun eigen licenties. VenGuard is een onafhankelijk project.
