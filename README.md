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

## Wat versie 1.3 verandert

- **Bescherming aan/uit is een kleine opdracht:** eerst de werkelijke stand lezen; als die al klopt wordt niets geschreven. Bij ingeschakelde algemene sync wordt dezelfde stand op de gekozen servers bevestigd. Deze knop start geen volledige synchronisatie en downloadt geen lijsten.
- **Geen automatische DNS-herconfiguratie:** periodieke AdGuard Sync-rondes kopiëren geen upstreams/cache/DNS-serverconfiguratie. Die onderdelen worden alleen meegenomen bij **Nu alles synchroniseren** of expliciet opslaan in de DNS-editor. Het opnieuw verzenden van sommige AdGuard DNS-instellingen kan DNS herstarten, zelfs bij dezelfde waarden.
- **Concrete verbindingsfouten:** timeout, geweigerde verbinding, geen route, naamresolutie en echte TLS-fouten krijgen verschillende meldingen. Recente beheeracties en niet bevestigde opdrachten staan apart van historische sync-resultaten.
- **Directe eigen regels:** eigen domeinregels gaan via de API naar alle ingeschakelde servers, onafhankelijk van het downloaden van de samengevoegde bronlijst. Een onbereikbare server houdt de andere niet tegen. VenGuard probeert openstaande wijzigingen later opnieuw.
- **Gerichte, tijdelijke uitzonderingen:** standaard alleen de exacte hostnaam, optioneel inclusief subdomeinen. Kies blijvend, 15 minuten, 1 uur of 1 dag. Uitgeschakelde/verlopen regels worden uit het beheerde serverblok verwijderd. Een offline server kan pas worden bijgewerkt als die terugkomt; de toepassing blijft zichtbaar als niet bevestigd.
- **Pi-hole v6:** status, blokkeringsschakelaar, gecombineerd verzoekenlog, bestaande lijsten, Gravity-updates, eigen globale domeinregels en aparte blokkeer-/toestaanfeeds.

Een tijdelijke beheer-API-fout bewijst niet dat DNS uitligt. De twee controles staan apart. De nieuwe diagnose herstelt geen onjuiste poort, firewall, netwerkroute of onbereikbare host.

## Servers toevoegen

1. Open **Servers & Sync → Server toevoegen**.
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

De ongewijzigde **AdGuardHome Sync v0.9.4** is in de Docker-container opgenomen. Kies de onderdelen bij Servers & Sync. De bron blijft leidend; replica’s worden niet automatisch gepromoveerd. Pi-hole wordt nooit als AdGuard-replica aan deze engine doorgegeven. Met een Pi-hole-bron worden alleen de gedeelde VenGuard-functies gebruikt. Stop een eventueel nog los draaiende AdGuard Sync zodra je deze ingebouwde sync gebruikt.

DHCP, luisterinterfaces/poorten, TLS-certificaten en AdGuard-gebruikers worden niet gekloond. Voor zover bereikbaar worden vóór geavanceerde wijzigingen lokale snapshots bewaard in `/data/settings-backups`, maximaal 20; er is geen automatische rollback. Een gedeeltelijk mislukte actie blijft zichtbaar. Recente acties bevatten geen wachtwoorden of ruwe serverlogs.

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
