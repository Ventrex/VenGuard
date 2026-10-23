# VenGuard

**Jouw netwerk, jouw regels.** Een lokale Docker-webapp die DNS-filterlijsten samenvoegt tot één persoonlijke lijst voor AdGuard Home, met Nederlandse uitleg en gerichte keuzepakketten.

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
- je automatisch aangemaakte beheerwachtwoord.

Krijg je **geen toegang tot Docker**? Voer in dezelfde map `sudo bash start.sh` uit. Het script installeert Docker niet. Als Docker nog ontbreekt, gebruik de [officiële Docker-installatiehandleiding](https://docs.docker.com/engine/install/) voor jouw Linux-versie, inclusief de Compose-plugin.

### Eenmalig invullen in de webinterface

1. Open VenGuard, log in en ga naar **Instellingen**.
2. Vul bij **AdGuard Home beheeradres** het adres in dat je normaal gebruikt om AdGuard te beheren, inclusief de poort. Bijvoorbeeld `http://192.168.0.10:3000`. Je installatie kan ook poort 80 of een andere poort gebruiken.
3. Vul je **AdGuard-gebruikersnaam en wachtwoord** in. Klik op **Sla op & test verbinding**.
4. Vul bij **LAN-adres van VenGuard** bijvoorbeeld `http://192.168.0.10:8098` in, met het echte IP van jouw NUC. Klik op **Instellingen opslaan**.
5. Ga naar **Mijn filterlijst → Koppel / ververs in AdGuard**. Vanaf dat moment haalt AdGuard jouw lijst op. Automatisch synchroniseren staat standaard aan zodra beide adressen ingevuld zijn.

**Let op het verschil:** het AdGuard-adres is van het bestaande beheerportaal; het VenGuard-adres is van deze nieuwe app. Gebruik geen `localhost`: vanuit een container verwijst dat naar de container zelf. Beide diensten moeten elkaar via het LAN kunnen bereiken.

VenGuard gebruikt poort **8098**, zodat de gebruikelijke AdGuard-poorten vrij blijven. Je DNS-server of router hoeft hiervoor niet vervangen of aangepast te worden.

## Wat krijg je?

| Onderdeel | Wat je ermee kunt |
| --- | --- |
| Overzicht | Aantal regels, bronnen, eigen keuzes en geziene domeinen bekijken. |
| Netwerkactiviteit | Recente AdGuard-verzoeken bekijken, zoeken op domein of apparaat, toegelaten en geblokkeerde verzoeken onderscheiden. |
| Eigen regels | Domeinen blokkeren of toestaan, voor iedereen of alleen een apparaat-IP/CIDR. Regels aan- en uitzetten of verwijderen. |
| Bronnen & pakketten | Bronlijsten importeren uit AdGuard, eigen publieke HTTPS-bronnen toevoegen, Nederlandse pakketten kiezen en downloads bijwerken. |
| Mijn filterlijst | De samengevoegde lijst doorzoeken en downloaden; de actuele AdGuard-uitkomst per domein en apparaat testen. |
| Diagnose | Controleren of bescherming en lijstfiltering aanstaan en of clients eigen filtering hebben uitgeschakeld. |

Er is geen API-sleutel, ChatGPT-account, abonnement of externe AI-dienst nodig. Alleen Docker is nodig op de host; Python wordt in het image meegeleverd. De app heeft geen pip- of npm-pakketten nodig voor productie.

## Nederlandse keuzepakketten

- **DPG-advertenties — standaard aan:** enkele specifieke advertentie-endpoints uit een NU.nl/DPG-sessie, waaronder de advertentiemodule en Prebid.
- **DPG-metingen — standaard aan:** enkele gerichte trackingmodules van DPG.
- **Nederlandse publieksmetingen — standaard uit:** NMO en een kleine selectie meetdiensten.
- **Apple Privédoorgifte blokkeren — standaard uit:** een bewuste optionele keuze die privacybescherming kan verminderen en Apple-meldingen kan veroorzaken.

Dit is een kleine lokale catalogus, **geen uitputtende Nederlandse reclamedatabase**. De catalogus blokkeert geen complete uitgever, cloudprovider of CDN. Beschrijvingen vermelden hun zekerheid; functies die alleen uit naam of context zijn afgeleid worden als waarschijnlijk beschreven. Onbekende domeinen blijven **Onbekend**. Een uitleg is geen veiligheids- of malwarebeoordeling.

Als rustige internationale basis is **HaGeZi Light** ingesteld. Ook Nederlandse sites gebruiken internationale advertentie- en meetplatforms. Je kunt die bron uitschakelen en uitsluitend eigen regels en pakketten gebruiken.

## Je bestaande lijsten samenvoegen

1. Koppel AdGuard bij Instellingen.
2. Open **Bronnen & pakketten → Importeer uit AdGuard**.
3. VenGuard kopieert de URLs van **ingeschakelde DNS-blokkeerlijsten**. Uitgeschakelde lijsten, toestaanlijsten en bestaande eigen AdGuard-regels worden niet geïmporteerd of gewijzigd.
4. Bekijk per bron het aantal bruikbare DNS-regels, overgeslagen regels en eventuele downloadfouten.
5. Test jouw VenGuard-lijst in AdGuard. Schakel daarna desgewenst de oude, overlappende blokkeerlijsten **zelf** uit in AdGuard. Laat de VenGuard-lijst aan.

Zolang andere AdGuard-lijsten actief blijven, kunnen ze domeinen blijven blokkeren die jij niet in VenGuard hebt geselecteerd. Bestaande AdGuard-uitzonderingen kunnen eveneens voorrang hebben. **Domein testen** toont de actuele AdGuard-uitkomst.

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

Bij **Bronnen & pakketten → Hoe groot wil je jouw lijst?** kies je:

- **Volledige gekozen bronnen (standaard):** alle ondersteunde bronregels meenemen. Nieuwe domeinen worden meteen door de gekozen bronlijsten gedekt.
- **Alleen geziene domeinen:** alleen bronblokkades meenemen die overeenkomen met eerder waargenomen domeinen. Ook een ouderdomeinregel wordt meegenomen als een subdomein is gezien. Bronuitzonderingen, eigen regels en gekozen pakketten blijven actief.

**De compacte modus is een afweging:** nieuwe reclame kan bij het eerste bezoek doorlaten, totdat het domein is gezien, de lijst is opgebouwd en AdGuard is ververst. Gebruik deze modus niet als complete beveiligingslijst. VenGuard haalt maximaal **1.000 recente logregels per minuut** op. Bij druk verkeer worden dus niet alle verzoeken waargenomen. Gezien-domeinen worden maximaal 30 dagen onthouden, tot maximaal 50.000 domeinen. Een IP-adres wordt daarbij niet opgeslagen.

Deze modus filtert op **gebruik**, niet op land. Alleen `.nl` blokkeren zou veel advertenties op Nederlandse sites missen.

## Automatisch bijwerken

- Externe bronnen worden standaard elke **24 uur** bijgewerkt. Kies eventueel 6, 12 of 48 uur.
- Eigen regel- en pakketwijzigingen starten automatisch een nieuwe opbouw.
- AdGuard-logregels worden bij een ingestelde koppeling elke **60 seconden** opgehaald. De webinterface ververst de weergave ongeveer elke 7 seconden.
- Met automatisch synchroniseren aan vraagt VenGuard na een gewijzigde lijst of gewijzigde instellingen aan AdGuard om filters te verversen. Ongewijzigde lijstinhoud veroorzaakt geen herhaald verversverzoek. AdGuard kan dit verzoek begrenzen of eerder gedownloade data blijven gebruiken; de knop is geen garantie voor onmiddellijke toepassing. Controleer met **Domein testen** en wacht zo nodig op het AdGuard-update-interval.
- Zonder automatisch synchroniseren blijft de lokale lijst wel automatisch opgebouwd. AdGuard haalt die op volgens zijn eigen ingestelde interval, of via **Koppel / ververs in AdGuard**.

Het lijstadres bevat een willekeurig toegangstoken. AdGuard kan die URL ophalen zonder je beheerwachtwoord. Behandel de URL als privé en maak VenGuard niet via een openbare tunnel toegankelijk zonder passende toegangsbescherming; de lijst moet voor AdGuard bereikbaar blijven.

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

# Beheerwachtwoord opnieuw bekijken.
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

- Python 3.12, standaardbibliotheek, HTML/CSS/JavaScript; **geen PHP**.
- Niet-root container, alleen-lezen image, schrijfbare data in `/data`, alle Linux-capabilities uit.
- Beheer achter wachtwoord en sessiecookie; schrijfverzoeken met herkomstcontrole en een verplichte custom header.
- AdGuard-wachtwoord lokaal opgeslagen met bestandsrechten `0600`; geen credentials in de frontend of in de instellingenexport.
- Lokale adressen voor AdGuard zijn toegestaan; externe filterbronnen moeten publieke HTTPS-URLs zijn. TLS-certificaten worden gecontroleerd.
- Lijsten en configuratie worden atomair vervangen. Een downloadfout verwijdert de vorige goede broncache niet.

Tests uitvoeren zonder Docker:

```bash
python3 -m unittest discover -s tests -v
node --check app/static/app.js
bash -n start.sh update.sh
```

GitHub Actions voert tests uit, bouwt het Docker-image en controleert dat de productiecontainer met alleen-lezen bestandssysteem gezond opstart. `scripts/preview.py` is uitsluitend een wegwerp-UI-demo met testgegevens, zonder echte AdGuard-toegang en zonder inlogscherm. Gebruik die **niet** voor installatie; Docker start altijd `app/server.py` met echte authenticatie.

## Bronnen en licenties

- [AdGuard Home API-schema](https://github.com/AdguardTeam/AdGuardHome/blob/master/openapi/openapi.yaml)
- [AdGuard DNS-filterregels](https://adguard-dns.io/kb/general/dns-filtering-syntax/)
- [Beperkingen van DNS-filtering](https://github.com/AdguardTeam/AdGuardHome/wiki/FAQ#are-there-any-known-limitations)
- [HaGeZi DNS-blocklists](https://github.com/hagezi/dns-blocklists)
- [Apple: Private Relay op netwerken](https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay/)

De app-code valt onder MIT. Externe lijsten worden tijdens gebruik opgehaald en behouden hun eigen licenties en bronvoorwaarden. VenGuard is een onafhankelijk project, niet van AdGuard of Apple. De lokale domeincatalogus is een aanpasbare hulpmiddelset, geen automatisch bijgehouden reputatiedienst.
