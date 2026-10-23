# VenGuard

**Jouw netwerk, jouw regels.** Een lokale Docker-webapp voor centraal beheer van meerdere AdGuard Home-servers: één filterlijst, één verzoekenoverzicht, echte AdGuardHome Sync en status per server. Dark mode is standaard; light mode is beschikbaar en wordt per browser onthouden.

## Installeren op je NUC

Gebruik een **Linux-machine met Docker Engine en Docker Compose v2**. Bij Proxmox: draai dit in een Linux-VM of een geschikte Docker-LXC, niet rechtstreeks op de Proxmox-host.

Open de terminal/SSH van die machine en voer uit:

```bash
git clone https://github.com/Ventrex/VenGuard.git
cd VenGuard
bash start.sh
```

Het script bouwt en start de container en toont:

- het webadres: **`http://IP-VAN-JE-NUC:8098`**;
- je automatisch aangemaakte installatiewachtwoord (totdat je een eigen account instelt).

Krijg je **geen toegang tot Docker**? Voer in dezelfde map `sudo bash start.sh` uit. Het script installeert Docker niet. Als Docker nog ontbreekt, gebruik de [officiële Docker-installatiehandleiding](https://docs.docker.com/engine/install/) voor jouw Linux-versie, inclusief de Compose-plugin.

## Upgraden naar VenGuard 1.2

In de bestaande VenGuard-map:

```bash
bash update.sh
```

Je datavolume, beheerwachtwoord, filterbronnen en eigen regels blijven behouden. De oude enkele AdGuard-koppeling wordt automatisch je eerste bronserver. Het bijgewerkte Docker-image bevat **AdGuardHome Sync v0.9.4**; je hoeft geen extra container, poort of YAML-bestand voor Sync in te richten.

## Nieuw in 1.2

- **Bescherming aan/uit:** succesvolle AdGuard-acties met een lege reactie of tekst `OK` worden correct verwerkt. HTML-inlogpagina’s worden niet als succes geaccepteerd. Na wijzigen leest VenGuard de bescherming en DNS-filtering terug; beide toestanden staan bij Centraal beheer en per server.
- **Rustigere status:** bij een mislukte netwerkcontrole volgt één herpoging. Een probleem wordt meteen zichtbaar als “Controle mislukt”; na drie opeenvolgende mislukte rondes krijgt het de gewone storingsstatus. Laatste API-bereikbaarheid en vorige sync-ronde staan apart. Dit herstelt geen onbereikbare host, onjuiste poort, firewall of Docker-netwerk.
- **Algemene filters:** HaGeZi Light als rustige basis, optionele Threat Intelligence Mini, NSFW en Gambling Mini. De oude Nederlandse pakketten blijven aanvullende keuzes. Er wordt bij een upgrade geen nieuwe inhoudsblokkade of uitzondering aangezet.
- **Categorieën:** advertenties/tracking, beveiliging, volwassen inhoud, gokken, sociale media en eigen lijsten. Iedere bron krijgt één beheercategorie; sommige bronnen bevatten meerdere soorten regels. Een categorie uitschakelen schakelt alleen de daarin ingedeelde VenGuard-bronnen uit, geen losstaande oude AdGuard-lijst of eigen regel. Je kunt de categorie per bron veranderen.
- **Uitzonderingen:** optionele schakelaars staan `marktplaats.nl` of `ing.nl` inclusief subdomeinen toe. Dit dekt niet automatisch andere betaal-, afbeelding- of identiteitsproviders. Gebruik Netwerkactiviteit en Domein testen voor een gerichte extra uitzondering. Bestaande `$important`-regels of andere AdGuard-instellingen kunnen de uitkomst beïnvloeden.

## Eigen account en authenticator-2FA

1. Log na de update in met je bestaande installatiewachtwoord.
2. Open **Account & 2FA**, kies een gebruikersnaam en een nieuw wachtwoord van minimaal 12 tekens. Vul ter bevestiging je installatiewachtwoord in.
3. Log opnieuw in met je eigen account. Het installatiewachtwoord uit `.env` werkt nu niet meer op de website.
4. Open **Account & 2FA → 2FA instellen** en bevestig met je huidige wachtwoord.
5. Voeg in je authenticator een account **handmatig** toe met de getoonde geheime sleutel: TOTP, 6 cijfers, 30 seconden. Bevestig in VenGuard met de code uit je app. Controleer dat NUC en telefoon een juiste systeemtijd hebben.
6. Bewaar de tien getoonde herstelcodes op een veilige plek. Ze worden één keer getoond. Iedere herstelcode werkt één keer in plaats van een authenticatorcode. Log daarna opnieuw in.

Deze versie heeft één eigen beheerdersaccount, geen openbare registratie of meerdere gebruikersrollen. Wachtwoorden worden met scrypt gehasht; 2FA-sleutel en gehashte herstelcodes worden lokaal in `/data/account.json` met rechten `0600` bewaard. Accountwijzigingen beëindigen bestaande sessies. Een al gebruikte TOTP-code wordt niet opnieuw geaccepteerd; wacht bij snel opnieuw inloggen op de volgende code. De authenticator is geen externe dienst van VenGuard.

**Passkeys zijn niet ingebouwd in deze versie.** De gevraagde alternatieve optie is hier authenticator-2FA. WebAuthn vraagt voor gebruik vanaf andere apparaten een beveiligd HTTPS-adres. Gebruik ook voor wachtwoorden en 2FA bij voorkeur HTTPS via je eigen vertrouwde reverse proxy; stel de beheerpoort niet rechtstreeks open op internet. Cookies worden `Secure` als de proxy `X-Forwarded-Proto: https` doorgeeft.

### Account of 2FA kwijt

Gebruik eerst een herstelcode. Zonder werkende accounttoegang kun je met lokale Docker-beheertoegang uitsluitend het VenGuard-account wissen:

```bash
docker compose exec venguard python3 reset_account.py
# Typ HERSTEL als je het eigen account en 2FA wilt wissen.
docker compose restart venguard
sed -n 's/^VENGUARD_PASSWORD=//p' .env
```

Log daarna in met dit installatiewachtwoord en stel je eigen account opnieuw in. Filters, serverkoppelingen en AdGuard-inloggegevens blijven behouden. Dit herstel kan alleen met toegang tot de Docker-host; er is geen onbeveiligde resetknop in de website. Een back-up van het datavolume bevat ook je 2FA-sleutel: bescherm die back-up.

### Je twee AdGuard-servers instellen

1. Open **Servers & Sync**. Je oude koppeling staat hier al na een upgrade. Klik op **AdGuard toevoegen** voor je tweede server.
2. Vul per server een naam, **beheeradres**, gebruikersnaam, wachtwoord en **DNS-IP/poort** in. Bijvoorbeeld beheer `http://192.168.0.10:3000` en DNS `192.168.0.10`, poort `53`. Gebruik de echte adressen en poorten van jouw installaties; beheer kan ook poort 80 of iets anders gebruiken.
3. Kies welke server de **bronserver** is. Kies de server met de instellingen die je wilt behouden. Alle andere ingeschakelde servers zijn replica’s.
4. Vul bij **Instellingen → LAN-adres van VenGuard** het bereikbare adres van VenGuard in, bijvoorbeeld `http://192.168.0.20:8098`. Sla op. Bij **Mijn filterlijst** kun je de lijst aan alle servers aanbieden.
5. Ga terug naar **Servers & Sync**, kies de te synchroniseren onderdelen, vink **Centrale synchronisatie inschakelen** aan en sla op. Hiermee geef je opdracht om de gekozen instellingen op replica’s te vervangen door die van de bronserver. Klik eventueel op **Nu alles synchroniseren**.
6. Pas voortaan gedeelde instellingen aan via **Centraal beheer**. De bestaande AdGuard-websites blijven bereikbaar voor lokaal of serverspecifiek beheer.

**Belangrijk voor je internetverbinding:** geef via je router/DHCP **beide AdGuard DNS-IP’s** aan je apparaten mee. Twee gesynchroniseerde servers zorgen op zichzelf nog niet voor uitwijkgedrag bij clients. Apparaten kunnen beide DNS-servers gebruiken; het omschakelen bij uitval kan even duren. Een openbare DNS-server als tweede adres kan je filtering omzeilen. Voor uitval van een complete host moeten de twee DNS-servers op verschillende hosts draaien.

VenGuard is geen DNS-proxy en zit niet tussen je apparaten en AdGuard. Valt VenGuard uit, dan gebruiken beide AdGuard-installaties hun laatst opgeslagen instellingen en filterregels verder. Er worden dan tijdelijk geen nieuwe lijsten of instellingen uit VenGuard opgehaald.

**De adressen verschillen:** het AdGuard-beheeradres hoort bij het bestaande AdGuard-portaal. Het VenGuard LAN-adres hoort bij deze app op poort 8098. Gebruik geen `localhost` voor een andere container: dat verwijst vanuit VenGuard naar VenGuard zelf.

## Wat krijg je?

| Onderdeel | Wat je ermee kunt |
| --- | --- |
| Overzicht | Aantal regels, bronnen, eigen keuzes en geziene domeinen bekijken. |
| Servers & Sync | Maximaal 10 servers toevoegen, bron kiezen, beheer-API en echte DNS-aanvragen controleren en synchronisatie per replica volgen. |
| Centraal beheer | Eigen AdGuard-regels, DNS/upstreams, herschrijvingen, apparaten, geblokkeerde diensten en instellingen van logs/statistieken beheren op de bronserver. Geavanceerde onderdelen hebben een JSON-editor. |
| Netwerkactiviteit | Eén gecombineerd overzicht van al je servers; filter op server, domein, apparaat en uitkomst. Offline servers verbergen de overige activiteit niet. |
| Eigen regels | Domeinen blokkeren of toestaan, voor iedereen of alleen een apparaat-IP/CIDR. Regels aan- en uitzetten of verwijderen. |
| Filters & categorieën | Algemene broncatalogus, categorieën, eigen HTTPS-lijsten, samenvoegen zonder dubbele regels, gerichte uitzonderingen en bestaande AdGuard-lijsten aan/uitzetten, verwijderen en verversen. |
| Account & 2FA | Eigen beheerdersaccount met gebruikersnaam, wachtwoord, authenticator en eenmalige herstelcodes. |
| Mijn filterlijst | De samengevoegde lijst doorzoeken en downloaden; de actuele AdGuard-uitkomst per domein en apparaat testen. |
| Diagnose | Controleren of bescherming en lijstfiltering aanstaan en of clients eigen filtering hebben uitgeschakeld. |

Er is geen API-sleutel, ChatGPT-account, abonnement of externe AI-dienst nodig. Alleen Docker is nodig op de host; Python wordt in het image meegeleverd. De Python-webapp heeft geen pip- of npm-pakketten nodig voor productie. De ongewijzigde Sync-engine wordt bij de Docker-build uit het officiële bakito-image gekopieerd.

## Nederlandse keuzepakketten

- **DPG-advertenties — standaard aan:** enkele specifieke advertentie-endpoints uit een NU.nl/DPG-sessie, waaronder de advertentiemodule en Prebid.
- **DPG-metingen — standaard aan:** enkele gerichte trackingmodules van DPG.
- **Nederlandse publieksmetingen — standaard uit:** NMO en een kleine selectie meetdiensten.
- **Apple Privédoorgifte blokkeren — standaard uit:** een bewuste optionele keuze die privacybescherming kan verminderen en Apple-meldingen kan veroorzaken.

Dit is een kleine lokale catalogus, **geen uitputtende Nederlandse reclamedatabase**. De catalogus blokkeert geen complete uitgever, cloudprovider of CDN. Beschrijvingen vermelden hun zekerheid; functies die alleen uit naam of context zijn afgeleid worden als waarschijnlijk beschreven. Onbekende domeinen blijven **Onbekend**. Een uitleg is geen veiligheids- of malwarebeoordeling.

Als rustige internationale basis is **HaGeZi Light** ingesteld. Ook Nederlandse sites gebruiken internationale advertentie- en meetplatforms. Je kunt die bron uitschakelen en uitsluitend eigen regels en pakketten gebruiken.

## Je bestaande lijsten samenvoegen

1. Voeg je AdGuard-servers toe bij Servers & Sync en kies een bronserver.
2. Open **Filters & categorieën → Importeer uit AdGuard**.
3. VenGuard kopieert van de bronserver de URLs van **ingeschakelde DNS-blokkeerlijsten**. Uitgeschakelde lijsten en toestaanlijsten worden niet in deze bronimport meegenomen. Bestaande eigen AdGuard-regels beheer je apart bij Centraal beheer.
4. Bekijk per bron het aantal bruikbare DNS-regels, overgeslagen regels en eventuele downloadfouten.
5. Test jouw VenGuard-lijst in AdGuard. Open daarna **Filters & categorieën → Bestaande lijsten in AdGuard** en schakel oude overlap uit met de aan/uit-schakelaars. Laat de VenGuard-lijst aan. Met filter-sync ingeschakeld volgen de replica’s.

Zolang andere AdGuard-lijsten actief blijven op de bronserver, kunnen ze domeinen blijven blokkeren die jij niet in de VenGuard-lijst hebt geselecteerd. AdGuard Sync kan ook die bestaande lijsten naar de replica’s kopiëren; kies daarom bewust welke lijsten je op de bronserver actief laat. Bestaande AdGuard-uitzonderingen kunnen eveneens voorrang hebben. **Domein testen** toont de actuele AdGuard-uitkomst.

### Wat wordt samengevoegd?

VenGuard ondersteunt:

```text
reclame.example.nl
0.0.0.0 reclame.example.nl
||reclame.example.nl^
@@||inloggen.example.nl^
```

Dubbele regels worden verwijderd. Geïmporteerde uitzonderingen blijven behouden. Eigen regels kunnen een apparaatscope krijgen, bijvoorbeeld:

```text
||reclame.example.nl^$client=192.168.0.83
```

Browserregels voor onderdelen van een pagina, URL-paden, reguliere expressies en bronregels met modifiers worden **overgeslagen**, niet vertaald naar ruimere blokkades. Daarom zijn **DNS-bronnen** de beste invoer. Browserlijsten zoals EasyList Cookie kunnen veel onbruikbare regels bevatten. De importstatus laat dit zien.

Limieten: maximaal 30 bronnen, 24 MiB per download en 1 miljoen opgeslagen bronregels samen. Gebruik bij voorkeur één goede basis in plaats van meerdere grote overlappende lijsten. Bij een mislukte download blijft de laatst opgehaalde goede broncache actief. Zonder eerdere cache wordt die bron nog niet meegenomen; dit is zichtbaar in het dashboard.

## Alleen blokkeren wat je netwerk gebruikt

Onderaan **Filters & categorieën** kies je de lijstmodus:

- **Volledige gekozen bronnen (standaard):** alle ondersteunde bronregels meenemen. Nieuwe domeinen worden meteen door de gekozen bronlijsten gedekt.
- **Alleen geziene domeinen:** alleen bronblokkades meenemen die overeenkomen met eerder waargenomen domeinen. Ook een ouderdomeinregel wordt meegenomen als een subdomein is gezien. Bronuitzonderingen, eigen regels en gekozen pakketten blijven actief.

**De compacte modus is een afweging:** nieuwe reclame kan bij het eerste bezoek doorlaten, totdat het domein is gezien, de lijst is opgebouwd en AdGuard is ververst. Gebruik deze modus niet als complete beveiligingslijst. VenGuard haalt maximaal **1.000 recente logregels per server per ronde** op, ongeveer iedere 30 seconden plus de tijd voor de netwerkcontroles. Het gezamenlijke overzicht toont maximaal 5.000 regels. Bij druk verkeer worden dus niet alle verzoeken waargenomen. Gezien-domeinen worden maximaal 30 dagen onthouden, tot maximaal 50.000 domeinen. Een IP-adres wordt daarbij niet opgeslagen.

Deze modus filtert op **gebruik**, niet op land. Alleen `.nl` blokkeren zou veel advertenties op Nederlandse sites missen.

## Automatisch bijwerken

- Externe bronnen worden standaard elke **24 uur** bijgewerkt. Kies eventueel 6, 12 of 48 uur.
- Eigen regel- en pakketwijzigingen starten automatisch een nieuwe opbouw.
- AdGuard-logregels en de bereikbaarheid van elke ingeschakelde server worden in een eigen achtergrondtaak opgehaald: iedere 30 seconden plus netwerktijd. De webinterface ververst de weergave ongeveer elke 7 seconden. Een status ouder dan 90 seconden wordt als verouderd getoond, niet als betrouwbaar online.
- Met automatisch synchroniseren aan vraagt VenGuard na een gewijzigde lijst of gewijzigde instellingen aan alle ingeschakelde AdGuard-servers om filters te verversen. Ongewijzigde lijstinhoud veroorzaakt geen herhaald verversverzoek. AdGuard kan dit verzoek begrenzen of eerder gedownloade data blijven gebruiken; de knop is geen garantie voor onmiddellijke toepassing. Controleer met **Domein testen** en wacht zo nodig op het AdGuard-update-interval.
- Zonder automatisch synchroniseren blijft de lokale lijst wel automatisch opgebouwd. AdGuard haalt die op volgens zijn eigen ingestelde interval, of via **Koppel / ververs in AdGuard**.

Het lijstadres bevat een willekeurig toegangstoken. AdGuard kan die URL ophalen zonder je beheerwachtwoord. Behandel de URL als privé en maak VenGuard niet via een openbare tunnel toegankelijk zonder passende toegangsbescherming; de lijst moet voor AdGuard bereikbaar blijven.

## Synchronisatie en storingen

VenGuard gebruikt de **echte AdGuardHome Sync v0.9.4-engine van bakito**, gebundeld in dezelfde container. De engine draait per ronde als een apart proces met een gegenereerde privéconfiguratie. Na de ronde verwijdert VenGuard die tijdelijke configuratie. Je beheert alle gegevens in de webinterface; geen Docker-socket of losse Sync-website nodig.

Standaard is de extra centrale instellingen-sync **uit** totdat je minimaal twee servers hebt toegevoegd en hem inschakelt. Daarna is het interval standaard 5 minuten; kies eventueel 1, 15, 30 of 60 minuten. Wijzigingen via Centraal beheer vragen meteen een ronde aan. De reeds bestaande automatische verspreiding van de VenGuard-filterlijst staat hier los van.

Gedeelde onderdelen die je kunt kiezen:

- externe blokkeer- en toestaanlijsten, eigen AdGuard-regels;
- algemene bescherming, Safe Browsing en Safe Search;
- DNS-serverinstellingen, upstreams en toegangsregels;
- DNS-herschrijvingen en apparaatinstellingen;
- geblokkeerde diensten, log- en statistiekinstellingen.

**Serverspecifiek blijft lokaal:** DHCP-server en leases, TLS-certificaten, webthema van AdGuard, gebruikerswachtwoorden en luisterinterfaces/poorten. Vooral DHCP mag niet blind dubbel actief worden. De dark/light-keuze in VenGuard is een eigen lokale browservoorkeur.

VenGuard toont drie verschillende signalen:

1. **Beheer-API:** kan VenGuard aanmelden en de status lezen?
2. **DNS UDP:** krijgt VenGuard een geldig DNS-antwoord van het ingestelde IP en de poort? Het testdomein is `example.org`. Dit is een controle vanaf VenGuard, geen bewijs dat elk clientapparaat of elke internetdienst werkt. Een geldig NXDOMAIN-antwoord telt ook als DNS-reactie.
3. **Sync-resultaat:** rapporteert de echte engine een geslaagde afronding voor de gekozen replica? Alleen een bereikbaar beheerscherm of exitcode 0 wordt niet als geslaagde sync beschouwd. De per-server badge is de laatst gemelde ronde; de tijdstippen staan erbij.

Bij een offline replica gaat een bereikbare replica gewoon door. Een mislukte server wordt bij de volgende ronde opnieuw geprobeerd. Een bronserver die offline is wordt **niet** automatisch vervangen door een replica: zo voorkom je dat een oude configuratie ineens de andere servers overschrijft. Bestaande DNS-resolvers blijven hun laatste configuratie gebruiken. Wijzigingen in de bestaande AdGuard-instellingen vereisen een bereikbare bron; eigen VenGuard-lijstkeuzes kun je wel lokaal blijven aanpassen en aan bereikbare servers aanbieden.

Vóór synchronisatie en centrale wijzigingen bewaart VenGuard voor zover bereikbaar lokale momentopnamen van ondersteunde instellingen in `/data/settings-backups` (maximaal 20 bestanden). Dit zijn herstelgegevens, geen automatische rollback. De bestanden kunnen interne adressen of gevoelige upstream-URLs bevatten; bescherm het datavolume. Een mislukte API-aanroep kan tot gedeeltelijk gewijzigde instellingen leiden; bekijk dan de status en de eigen AdGuard-interface. De gezamenlijke export laat de wachtwoorden van **alle** servers weg.

**Stop je oude losse AdGuard Sync** zodra je de nieuwe ingebouwde sync gebruikt. Laat niet twee sync-processen met verschillende broninstellingen tegelijk dezelfde servers beheren.

## Bijwerken, stoppen en wachtwoord

In de VenGuard-map:

```bash
# Nieuwe versie downloaden en container opnieuw bouwen; instellingen blijven behouden.
bash update.sh

# Alleen stoppen.
docker compose stop

# Weer starten.
docker compose start

# Log bekijken.
docker compose logs --tail=50

# Installatiewachtwoord bekijken (werkt alleen als er geen eigen account is).
sed -n 's/^VENGUARD_PASSWORD=//p' .env
```

Een andere webpoort? Pas `VENGUARD_PORT=8098` aan in `.env`, start opnieuw met `bash start.sh` en wijzig daarna ook het VenGuard LAN-adres in de webinterface. De interne containerpoort blijft 8098.

De container gebruikt een blijvend Docker-volume. Gebruik **niet** `docker compose down -v` als je de data wilt bewaren: `-v` verwijdert het volume. Voor een volledige back-up: bewaar `.env` en het datavolume. In de webinterface kun je daarnaast instellingen exporteren; die export laat wachtwoorden en het lijsttoken weg en is geen volledige herstelback-up.

Volledige datakopie, vanaf de Docker-host:

```bash
docker compose stop
mkdir -p backup
docker cp venguard:/data ./backup/
cp .env backup/.env
docker compose start
```

Bewaar deze map veilig: hij bevat de AdGuard-inloggegevens. Voor herstel zet je de map `data` terug in `/data` van het VenGuard-volume en herstel je `.env` vóór het starten. De 10 vorige gegenereerde lijstversies staan in `/data/backups`; oude instellingen worden niet automatisch geversioneerd.

## Wat dit wel en niet oplost

VenGuard beheert de DNS-lijst. Het vervangt AdGuard Home niet en verandert geen iPhone-, iPad- of routerinstellingen. Als een apparaat DNS-filtering omzeilt of eigen clientinstellingen gebruikt, moet dat apart worden opgelost. De aanwezigheid van `mask.icloud.com` in een log bewijst op zichzelf niet dat Privédoorgifte actief is.

Een DNS-filter kan geen afzonderlijke reclame blokkeren als die hetzelfde domein gebruikt als de gewenste inhoud. Denk aan bepaalde YouTube-advertenties of gesponsorde berichten. Het kan ook geen lege vakken of alle cookievensters uit een pagina verwijderen. Daarvoor is aanvullend een geschikte Safari-/browserfilter nodig.

## Techniek en testen

- Python 3.12, standaardbibliotheek, HTML/CSS/JavaScript en de gebundelde Go Sync-engine; **geen PHP**.
- Niet-root container, alleen-lezen image, schrijfbare data in `/data`, alle Linux-capabilities uit.
- Beheer achter wachtwoord en sessiecookie; schrijfverzoeken met herkomstcontrole en een verplichte custom header.
- AdGuard-wachtwoord lokaal opgeslagen met bestandsrechten `0600`; geen credentials in de frontend of in de instellingenexport.
- Lokale adressen voor AdGuard zijn toegestaan; externe filterbronnen moeten publieke HTTPS-URLs zijn. TLS-certificaten worden gecontroleerd.
- Lijsten en configuratie worden atomair vervangen. Een downloadfout verwijdert de vorige goede broncache niet.

Tests uitvoeren zonder Docker:

```bash
python3 -m unittest discover -s tests -v
node --check app/static/app.js
node --check app/static/hub.js
node --check app/static/account.js
node --check app/static/filters.js
bash -n start.sh update.sh
```

GitHub Actions voert tests uit, bouwt het Docker-image, controleert dat de productiecontainer met alleen-lezen bestandssysteem gezond opstart en test de echte gebundelde Sync-binary tegen lokale test-API’s, inclusief een offline replica. `scripts/preview.py` is uitsluitend een wegwerp-UI-demo met testgegevens, zonder echte AdGuard-toegang en zonder inlogscherm. Gebruik die **niet** voor installatie; Docker start altijd `app/server.py` met echte authenticatie.

## Bronnen en licenties

- [AdGuard Home API-schema](https://github.com/AdguardTeam/AdGuardHome/blob/master/openapi/openapi.yaml)
- [AdGuard DNS-filterregels](https://adguard-dns.io/kb/general/dns-filtering-syntax/)
- [Beperkingen van DNS-filtering](https://github.com/AdguardTeam/AdGuardHome/wiki/FAQ#are-there-any-known-limitations)
- [TOTP-standaard (RFC 6238)](https://www.rfc-editor.org/rfc/rfc6238.html)
- [HaGeZi DNS-blocklists](https://github.com/hagezi/dns-blocklists)
- [Apple: Private Relay op netwerken](https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay/)

De app-code valt onder MIT. De gebundelde AdGuardHome Sync-engine valt onder Apache 2.0; bron, versie en volledige licentie staan in `THIRD-PARTY-NOTICES.md` en `licenses/`. Externe lijsten worden tijdens gebruik opgehaald en behouden hun eigen licenties en bronvoorwaarden. VenGuard is een onafhankelijk project, niet van AdGuard of Apple. De lokale domeincatalogus is een aanpasbare hulpmiddelset, geen automatisch bijgehouden reputatiedienst.
