# VenGuard

Centraal filterbeheer voor **AdGuard Home en Pi-hole v6**. Combineer DNS-filterbronnen zonder dubbele regels, bekijk verzoeken van meerdere servers en pas gerichte uitzonderingen rechtstreeks toe. Dark mode is standaard; light mode wordt per browser onthouden.

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

Versie **1.4.0** vereenvoudigt het dashboard en voegt onafhankelijke verbindingsmetingen met een storingshistorie toe.

## Eenvoudig overzicht en storingen (1.4)

Het hoofdmenu bevat **Overzicht**, **DNS-verzoeken**, **Filters**, **Eigen keuzes** en **Status & storingen**. Account, beveiliging, lijstpublicatie en geavanceerde DNS-editors staan onder **Instellingen & extra’s**. Bestaande adressen zoals `#central` blijven werken. Dark mode blijft standaard.

Bij **Status & storingen** zie je per server DNS, beheer en filtering. Technische gegevens en synchronisatie-instellingen zijn uitklapbaar. De actuele beschermingsstand wordt bij een mislukte beheerverbinding als onbekend weergegeven, niet als een bevestigde actuele instelling.

- **Iedere 15 seconden, onafhankelijk van het beheer:** een echte UDP-DNS-aanvraag voor `example.org` aan elk ingesteld DNS-IP. Na een mislukking wordt eenmaal opnieuw geprobeerd en aanvullend DNS over TCP getest. SERVFAIL, REFUSED, NXDOMAIN, lege antwoorden en blokkeeradressen worden onderscheiden van een ontbrekend antwoord. Een NXDOMAIN bewijst wel een reagerende server, maar geen geslaagde omzetting van de testnaam.
- **Externe verbinding:** TCP naar `1.1.1.1:443` en `8.8.8.8:443`, zonder DNS te gebruiken. Eén geslaagde verbinding toont bereikbaarheid van die bestemming; mislukking van beide tests bewijst geen providerstoring. Deze tests wijzigen geen upstreams en sturen geen gebruikersverkeer om.
- **Beheer:** de bestaande controle blijft iedere ronde de API en filterstand controleren. Een trage API of het ophalen van verzoekenlogs houdt de aparte DNS-metingen niet op. “Nu controleren” start controles op de achtergrond en antwoordt meteen, zodat een reverse-proxy-timeout niet als DNS-uitval wordt gepresenteerd.
- **Bewijs bewaren:** maximaal 200 incidenten met begin, laatst waargenomen fout en herstel, plus maximaal 24 uur meetpunten (hoogstens één per minuut). Het scherm toont de laatste 12 incidenten. **Download rapport** bevat alle bewaarde incidenten, meetpunten, servernamen/IP’s en recente VenGuard-beheeracties, zonder serverwachtwoorden, gebruikersnamen, lijsttokens of DNS-verzoekenlog.
- **Correlatie:** beheeracties vlak voor een storing zijn zichtbaar. Een overeenkomstig tijdstip is geen bewezen oorzaak. Bij herstart van VenGuard wordt een open incident afgesloten met *meting beëindigd*, zonder een verzonnen hersteltijd of uitvalduur voor de niet-gemeten periode.
- **Filterdiagnose per server:** open de meetdetails en kies **Filterinstellingen controleren** om globale schakelaars, actieve lijsten en apparaten met eigen filtering uit te lezen.
- **Browserverbinding:** fouten tussen je browser en VenGuard/reverse proxy verschijnen apart bovenaan. Een verdwenen dashboardverbinding wordt niet automatisch uitgelegd als een defecte DNS-server.

Alle metingen worden uitgevoerd **vanuit de VenGuard-container**. Ze bewijzen niet dat een telefoon dezelfde DNS gebruikt, dat wifi werkt of dat alle upstreams bereikbaar zijn. `example.org` kan uit de DNS-cache komen. VenGuard kan geen eerdere storing reconstrueren en leest zonder aanvullende koppeling geen Docker-, host-, switch- of routerlogs uit. De oorzaak van een hostherstart, geheugenprobleem, defecte kabel of upstreamstoring vereist nog die logs. Duur en hersteltijden zijn benaderingen op basis van de meetmomenten; korte storingen tussen de controles kunnen worden gemist.

Bewaar een rapport na een storing om DNS-uitval, alleen een beheerfout, een extern verbindingsprobleem en uitgeschakelde filtering te onderscheiden. Verbindingsmetingen staan in `/data/connectivity.json` en blijven bij een gewone update behouden.

## Wat versie 1.3 verandert

- **Bescherming aan/uit is een kleine opdracht:** eerst de werkelijke stand lezen; als die al klopt wordt niets geschreven. Bij ingeschakelde algemene sync wordt dezelfde stand op de gekozen servers bevestigd. Deze knop start geen volledige synchronisatie en downloadt geen lijsten.
- **Geen automatische DNS-herconfiguratie:** periodieke AdGuard Sync-rondes kopiëren geen upstreams/cache/DNS-serverconfiguratie. Die onderdelen worden alleen meegenomen bij **Nu alles synchroniseren** of expliciet opslaan in de DNS-editor. Het opnieuw verzenden van sommige AdGuard DNS-instellingen kan DNS herstarten, zelfs bij dezelfde waarden.
- **Concrete verbindingsfouten:** timeout, geweigerde verbinding, geen route, naamresolutie en echte TLS-fouten krijgen verschillende meldingen. Recente beheeracties en niet bevestigde opdrachten staan apart van historische sync-resultaten.
- **Directe eigen regels:** eigen domeinregels gaan via de API naar alle ingeschakelde servers, onafhankelijk van het downloaden van de samengevoegde bronlijst. Een onbereikbare server houdt de andere niet tegen. VenGuard probeert openstaande wijzigingen later opnieuw.
- **Gerichte, tijdelijke uitzonderingen:** standaard alleen de exacte hostnaam, optioneel inclusief subdomeinen. Kies blijvend, 15 minuten, 1 uur of 1 dag. Uitgeschakelde/verlopen regels worden uit het beheerde serverblok verwijderd. Een offline server kan pas worden bijgewerkt als die terugkomt; de toepassing blijft zichtbaar als niet bevestigd.
- **Pi-hole v6:** status, blokkeringsschakelaar, gecombineerd verzoekenlog, bestaande lijsten, Gravity-updates, eigen globale domeinregels en aparte blokkeer-/toestaanfeeds.

Een tijdelijke beheer-API-fout bewijst niet dat DNS uitligt. De twee controles staan apart. De nieuwe diagnose herstelt geen onjuiste poort, firewall, netwerkroute of onbereikbare host.

## Servers toevoegen

1. Open **Status & storingen → Server toevoegen**.
2. Kies **AdGuard Home** of **Pi-hole v6**.
3. Geef het beheeradres op. Voorbeelden: `http://192.168.0.10:3000` of `http://192.168.0.20`. Gebruik de werkelijke webpoort, niet de DNS-poort.
4. AdGuard: vul gebruikersnaam en wachtwoord in. Pi-hole: vul het wachtwoord of app-wachtwoord in; gebruikersnaam is niet nodig. Bij Pi-hole-2FA gebruik je een **app-wachtwoord**. VenGuard bewaart en hergebruikt één API-sessie per server.
5. Vul het echte **DNS-IP** en de **DNS-poort**, meestal 53, in. De UDP-test staat los van het beheeradres.
6. Kies een bronserver voor het importeren van lijsten en de geavanceerde AdGuard-editor.
7. Vul bij **Instellingen** het bereikbare **LAN-adres van VenGuard** in. Gebruik geen `localhost` voor toegang vanuit een andere container.
8. Open **Mijn filterlijst → Koppel / ververs** om de abonnementen aan te bieden. Een Pi-hole Gravity-update kan langer duren dan een normale beheeractie. De API-gebruiker moet die actie mogen uitvoeren.

URLs die eindigen op `/control` (AdGuard) of `/admin`/`/api` (Pi-hole) worden voor de beheerverbinding herkend. HTTPS-certificaten worden gecontroleerd; certificaatvalidatie wordt niet uitgeschakeld.

**Continuïteit:** laat je router/DHCP beide DNS-IP’s aan apparaten meegeven. VenGuard staat niet in het DNS-verkeerspad. Bij uitval van VenGuard blijven de DNS-servers hun opgeslagen regels gebruiken. Twee DNS-servers op dezelfde host beschermen niet tegen uitval van die host. Clients kunnen beide servers gebruiken; bij uitval kan omschakelen vertraging geven.

## Eén verzameling bronnen

Open **Filters & categorieën**:

- Begin met de rustige algemene basis **HaGeZi Light**.
- Voeg zo nodig Threat Intelligence Mini, volwassen-inhoud- of goklijsten toe. Deze opties worden niet vanzelf ingeschakeld.
- Voeg eigen publieke HTTPS-lijsten toe of importeer de ingeschakelde blokkeerlijsten van je bronserver.
- Deel bronnen in categorieën in. De categorie is een beheerlabel; een bron kan inhoudelijk meerdere soorten regels bevatten.
- Zet een bron of categorie uit zonder die te verwijderen.
- Bekijk per bron regels, geselecteerde regels, overlap, laatste download en eventuele fouten.
- Schakel na controle oude overlap uit bij **Bestaande lijsten op de bronserver**. Zolang andere lijsten actief zijn, kunnen die blijven blokkeren.

Standaard wordt elke 24 uur bijgewerkt; in Instellingen kies je 6, 12, 24 of 48 uur. Een mislukte download behoudt de laatste goede cache. De import neemt complete domeinregels, hostsregels en eenvoudige `||domein^`/`@@||domein^`-regels over. Browserregels, URL-paden, regexen en geavanceerde modifiers uit externe bronnen worden overgeslagen, niet verbreed.

Limieten: 30 bronnen, 24 MiB per download, 1 miljoen opgeslagen bronregels. De volledige modus dekt nieuwe domeinen meteen volgens de bron; **Alleen gezien** selecteert uit log-steekproeven van maximaal 30 dagen en blokkeert nieuwe domeinen pas na waarnemen en verversen. Gebruik de volledige modus voor beveiligingslijsten.

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

## Wat wordt gesynchroniseerd?

| Functie | AdGuard Home | Pi-hole v6 |
| --- | --- | --- |
| Beheerstatus en onafhankelijke DNS-test | Ja | Ja |
| Bescherming aan/uit | Ja | Eén blokkeringsschakelaar |
| Verzoekenlog | Ja | Genormaliseerd in hetzelfde overzicht |
| Samengevoegde bronnen | AdGuard-abonnement | Afzonderlijk blokkeer- en toestaanabonnement |
| Exacte en subdomeinregels | Beheerd regelblok | Exacte/regex-domeinen in standaardgroep 0 |
| Apparaat-IP-regels | Ja | Niet vertaald; gebruik Pi-hole-groepen |
| Geavanceerde instellingen kopiëren | AdGuard → AdGuard | Geen vertaling van AdGuard-instellingen |

De ongewijzigde **AdGuardHome Sync v0.9.4** is in de Docker-container opgenomen. Kies de onderdelen bij Status & storingen. De bron blijft leidend; replica’s worden niet automatisch gepromoveerd. Pi-hole wordt nooit als AdGuard-replica aan deze engine doorgegeven. Met een Pi-hole-bron worden alleen de gedeelde VenGuard-functies gebruikt. Stop een eventueel nog los draaiende AdGuard Sync zodra je deze ingebouwde sync gebruikt.

DHCP, luisterinterfaces/poorten, TLS-certificaten en AdGuard-gebruikers worden niet gekloond. Voor zover bereikbaar worden vóór geavanceerde wijzigingen lokale snapshots bewaard in `/data/settings-backups`, maximaal 20; er is geen automatische rollback. Een gedeeltelijk mislukte actie blijft zichtbaar. Recente acties bevatten geen wachtwoorden of ruwe serverlogs.

## Beveiliging en Wazuh

**VenGuard is geen router, firewall of DDoS-filter.** De container heeft geen host-netwerkrechten, packet capture of firewallbevoegdheden gekregen. De DNS-dienst blijft los van VenGuard werken.

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

Python 3.12-standaardbibliotheek, HTML/CSS/JavaScript en de echte Go Sync-engine; geen PHP en geen pip-/npm-afhankelijkheden voor productie. De container draait niet als root, met alleen-lezen image en schrijfbare data in `/data`.

```bash
python3 -m unittest discover -s tests -v
node --check app/static/app.js
node --check app/static/hub.js
node --check app/static/filters.js
node --check app/static/account.js
node --check app/static/security.js
bash -n start.sh update.sh
```

GitHub Actions bouwt en start de productiecontainer, controleert authenticatie, test de echte gebundelde Sync-engine tegen lokale testservers en test Pi-hole tegen een afzonderlijke officiële wegwerpcontainer. `scripts/preview.py` is alleen een geïsoleerde UI-demo zonder echte servers of productie-authenticatie; gebruik die niet voor installatie.

## Bronnen en licenties

- [AdGuard API](https://github.com/AdguardTeam/AdGuardHome/blob/master/openapi/openapi.yaml)
- [AdGuard DNS-filterregels](https://adguard-dns.io/kb/general/dns-filtering-syntax/)
- [Pi-hole v6 API](https://docs.pi-hole.net/api/) en [sessieauthenticatie](https://docs.pi-hole.net/api/auth/)
- [Pi-hole officiële API-schema’s](https://github.com/pi-hole/FTL/tree/master/src/api/docs/content/specs)
- [HaGeZi DNS-lijsten](https://github.com/hagezi/dns-blocklists)
- [TOTP RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.html)

App-code: MIT. AdGuardHome Sync: Apache 2.0, zie `THIRD-PARTY-NOTICES.md` en `licenses/`. Externe filterbronnen behouden hun eigen licenties. VenGuard is een onafhankelijk project.
