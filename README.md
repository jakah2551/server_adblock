# WiFi Anti-AdBlock

Un'applicazione Python che crea una rete WiFi in grado di bloccare il funzionamento degli AdBlock sui dispositivi client connessi.

## Descrizione

Questo progetto implementa un server backend che:

1. Genera un access point WiFi utilizzando hostapd
2. Configura il servizio DHCP tramite dnsmasq
3. Implementa un meccanismo per bloccare gli AdBlock sui dispositivi connessi tramite:
   - Intercettazione delle richieste DNS verso domini noti degli AdBlock
   - Blocco delle connessioni agli URL utilizzati per aggiornare le liste di filtri
   - Reindirizzamento delle richieste relative agli AdBlock

## Requisiti

### Requisiti di sistema
- Sistema operativo Linux (testato su Debian/Ubuntu)
- Privilegi di amministratore (root)
- Una scheda di rete WiFi che supporta la modalità AP

### Pacchetti di sistema richiesti
- hostapd
- dnsmasq
- iptables
- Python 3.6+

### Moduli Python richiesti
- scapy
- netifaces

## Installazione

1. Clona il repository:
```bash
git clone https://github.com/username/wifi-anti-adblock.git
cd wifi-anti-adblock
```

2. Installa i pacchetti di sistema necessari:
```bash
sudo apt-get update
sudo apt-get install hostapd dnsmasq iptables python3-pip
```

3. Installa i moduli Python richiesti:
```bash
pip install -r requirements.txt
```

## Utilizzo

### Opzioni del comando

```bash
sudo python3 wifi_anti_adblock.py --interface <interfaccia_wifi> [opzioni]
```

Parametri:
- `--interface`, `-i`: (Obbligatorio) Nome dell'interfaccia WiFi da utilizzare (es. wlan0)
- `--ssid`, `-s`: (Opzionale) Nome della rete WiFi (default: "Free_WiFi")
- `--channel`, `-c`: (Opzionale) Canale WiFi (default: 1)
- `--password`, `-p`: (Opzionale) Password per la rete WiFi (se omesso, la rete sarà aperta)

### Esempio

```bash
sudo python3 wifi_anti_adblock.py --interface wlan0 --ssid "MyNetwork" --password "securepassword" --channel 6
```

## Come funziona

1. **Configurazione dell'Access Point**:
   - Crea una rete WiFi utilizzando l'interfaccia specificata
   - Assegna indirizzi IP nella rete 10.0.0.0/24
   - Configura il NAT per consentire l'accesso a Internet

2. **Blocco degli AdBlock**:
   - Intercetta le richieste DNS dirette ai domini degli AdBlock
   - Risponde con indirizzi IP locali (127.0.0.1) per bloccare il download delle liste di filtri
   - Monitora e blocca l'accesso ai domini noti utilizzati dagli AdBlock

3. **Server Web**:
   - Implementa un server web minimo per gestire le richieste HTTP reindirizzate

## Elenco dei domini bloccati

Il sistema blocca diversi domini associati ai servizi AdBlock, tra cui:
- easylist.to
- adblockplus.org
- getadblock.com
- ublock.org
- disconnect.me
- ghostery.com
- adguard.com
- E molti altri...

## Risoluzione dei problemi

### La rete WiFi non si avvia
- Verifica che l'interfaccia WiFi supporti la modalità AP
- Assicurati che NetworkManager non stia gestendo l'interfaccia
- Controlla i log per errori specifici

### I client non riescono a connettersi
- Verifica che la password WiFi soddisfi i requisiti minimi (se configurata)
- Assicurati che il canale selezionato sia disponibile nella tua area

### Gli AdBlock continuano a funzionare
- Il sistema potrebbe non bloccare tutte le varianti di AdBlock
- Alcuni AdBlock potrebbero utilizzare metodi alternativi di aggiornamento
- Controlla i log per vedere se le richieste DNS vengono intercettate correttamente

## Avvertenze

- Questo software è progettato per scopi dimostrativi ed educativi
- L'utilizzo di questo software potrebbe essere soggetto a restrizioni legali in alcune giurisdizioni
- L'uso improprio di questo software può violare i termini di servizio dei provider di rete

## Contribuire

Le pull request sono benvenute. Per modifiche importanti, apri prima un issue per discutere cosa vorresti cambiare.

## Licenza

[MIT](https://choosealicense.com/licenses/mit/)