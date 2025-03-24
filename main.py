#!/usr/bin/env python3
"""
Backend per generare una rete WiFi e bloccare AdBlock
Questo script crea un access point WiFi e modifica le richieste DNS per bloccare 
il funzionamento degli AdBlock comuni.
"""

import os
import sys
import time
import subprocess
import threading
import logging
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send, sniff
import netifaces
import argparse

# Configurazione del logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Lista di domini comuni di AdBlock da bloccare
ADBLOCK_DOMAINS = [
    "easylist.to", 
    "adblockplus.org",
    "getadblock.com",
    "ublock.org",
    "disconnect.me",
    "ghostery.com",
    "adguard.com",
    "blockadblock.com",
    "adblock-listefr.com",
    "fanboy.co.nz",
    "adblockcdn.com",
    "easy-privacy.com",
    "malwaredomains.com",
    "ublock-origin.dev",
    "abpvn.com",
    "filterlists.com"
]

# Lista di URL comuni utilizzati da AdBlock per aggiornare le liste
ADBLOCK_URLS = [
    "easylist-downloads.adblockplus.org",
    "cdn.adblockcdn.com",
    "filters.adtidy.org",
    "cdn.ublock.org",
    "subscribe.adblockplus.org",
    "raw.githubusercontent.com/easylist",
    "cdn.disconnect.me",
    "lists.disconnect.me",
    "pgl.yoyo.org/adservers",
    "filter.adtidy.org",
    "adaway.org/hosts.txt",
    "hosts-file.net",
    "filterlists.com"
]

class WifiAP:
    """Classe per la gestione dell'access point WiFi"""
    def __init__(self, interface, ssid, channel=1, password=None):
        self.interface = interface
        self.ssid = ssid
        self.channel = channel
        self.password = password
        self.original_interface_status = None
        self.hostapd_conf_path = "/tmp/hostapd.conf"
        self.dnsmasq_conf_path = "/tmp/dnsmasq.conf"
        self.hostapd_process = None
        self.dnsmasq_process = None

    def _check_prerequisites(self):
        """Verifica che i prerequisiti siano installati"""
        required_packages = ["hostapd", "dnsmasq", "iptables"]
        missing_packages = []
        
        for package in required_packages:
            result = subprocess.run(["which", package], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:
                missing_packages.append(package)
        
        if missing_packages:
            logger.error(f"Pacchetti mancanti: {', '.join(missing_packages)}")
            logger.error("Installa i pacchetti mancanti con: sudo apt-get install " + " ".join(missing_packages))
            return False
        
        return True

    def _create_hostapd_config(self):
        """Crea il file di configurazione per hostapd"""
        config = [
            f"interface={self.interface}",
            f"ssid={self.ssid}",
            f"channel={self.channel}",
            "driver=nl80211",
            "hw_mode=g",
            "wmm_enabled=1",
            "auth_algs=1",
            "macaddr_acl=0",
            "ignore_broadcast_ssid=0"
        ]
        
        if self.password:
            config.extend([
                "wpa=2",
                "wpa_key_mgmt=WPA-PSK",
                "wpa_pairwise=TKIP CCMP",
                "rsn_pairwise=CCMP",
                f"wpa_passphrase={self.password}"
            ])
        
        with open(self.hostapd_conf_path, "w") as f:
            f.write("\n".join(config))
        
        logger.info(f"File di configurazione hostapd creato in {self.hostapd_conf_path}")

    def _create_dnsmasq_config(self):
        """Crea il file di configurazione per dnsmasq"""
        config = [
            f"interface={self.interface}",
            "dhcp-range=10.0.0.2,10.0.0.20,255.255.255.0,24h",
            "dhcp-option=option:router,10.0.0.1",
            "dhcp-option=option:dns-server,10.0.0.1",
            "address=/#/10.0.0.1",
            "log-queries",
            "log-dhcp",
            "listen-address=127.0.0.1",
            "listen-address=10.0.0.1",
            "bind-interfaces"
        ]
        
        # Aggiungi redirezioni per domini AdBlock
        for domain in ADBLOCK_DOMAINS + ADBLOCK_URLS:
            config.append(f"address=/{domain}/10.0.0.1")
        
        with open(self.dnsmasq_conf_path, "w") as f:
            f.write("\n".join(config))
        
        logger.info(f"File di configurazione dnsmasq creato in {self.dnsmasq_conf_path}")

    def _configure_interface(self):
        """Configura l'interfaccia di rete"""
        try:
            # Salva lo stato originale dell'interfaccia
            result = subprocess.run(["ip", "addr", "show", self.interface], 
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                   text=True, check=True)
            self.original_interface_status = result.stdout
            
            # Disattiva NetworkManager per questa interfaccia
            subprocess.run(["nmcli", "device", "set", self.interface, "managed", "no"], 
                          check=True)
            
            # Configura l'indirizzo IP
            subprocess.run(["ip", "addr", "flush", "dev", self.interface], check=True)
            subprocess.run(["ip", "addr", "add", "10.0.0.1/24", "dev", self.interface], 
                          check=True)
            subprocess.run(["ip", "link", "set", self.interface, "up"], check=True)
            
            logger.info(f"Interfaccia {self.interface} configurata con IP 10.0.0.1/24")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Errore nella configurazione dell'interfaccia: {e}")
            return False

    def _setup_nat(self):
        """Configura il NAT per condividere la connessione internet"""
        try:
            # Ottieni l'interfaccia con internet
            gw_iface = None
            gateways = netifaces.gateways()
            default_gw = gateways.get('default', {}).get(netifaces.AF_INET)
            
            if default_gw:
                gw_iface = default_gw[1]
                logger.info(f"Interfaccia internet rilevata: {gw_iface}")
            else:
                logger.warning("Nessun gateway predefinito trovato. Il NAT potrebbe non funzionare.")
                return False
            
            # Abilita IP forwarding
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
            
            # Configura iptables per il NAT
            subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", 
                           gw_iface, "-j", "MASQUERADE"], check=True)
            subprocess.run(["iptables", "-A", "FORWARD", "-i", self.interface, "-o", 
                           gw_iface, "-j", "ACCEPT"], check=True)
            subprocess.run(["iptables", "-A", "FORWARD", "-i", gw_iface, "-o", 
                           self.interface, "-m", "state", "--state", 
                           "RELATED,ESTABLISHED", "-j", "ACCEPT"], check=True)
            
            # Redirect DNS queries to our server
            subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", 
                           self.interface, "-p", "tcp", "--dport", "53", 
                           "-j", "REDIRECT", "--to-port", "53"], check=True)
            subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", 
                           self.interface, "-p", "udp", "--dport", "53", 
                           "-j", "REDIRECT", "--to-port", "53"], check=True)
            
            logger.info("NAT configurato con successo")
            return True
        except Exception as e:
            logger.error(f"Errore nella configurazione del NAT: {e}")
            return False

    def start(self):
        """Avvia l'access point WiFi"""
        if not self._check_prerequisites():
            return False
        
        if not self._configure_interface():
            return False
        
        self._create_hostapd_config()
        self._create_dnsmasq_config()
        
        if not self._setup_nat():
            logger.warning("Configurazione NAT fallita, ma continuiamo comunque")
        
        try:
            # Avvia hostapd
            logger.info("Avvio hostapd...")
            self.hostapd_process = subprocess.Popen(
                ["hostapd", self.hostapd_conf_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Attendi che hostapd sia pronto
            time.sleep(2)
            
            if self.hostapd_process.poll() is not None:
                stdout, stderr = self.hostapd_process.communicate()
                logger.error(f"hostapd fallito: {stderr.decode()}")
                return False
            
            # Avvia dnsmasq
            logger.info("Avvio dnsmasq...")
            self.dnsmasq_process = subprocess.Popen(
                ["dnsmasq", "-C", self.dnsmasq_conf_path, "--no-daemon"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Attendi che dnsmasq sia pronto
            time.sleep(2)
            
            if self.dnsmasq_process.poll() is not None:
                stdout, stderr = self.dnsmasq_process.communicate()
                logger.error(f"dnsmasq fallito: {stderr.decode()}")
                self.stop()
                return False
            
            logger.info(f"Access Point WiFi '{self.ssid}' avviato con successo su {self.interface}")
            return True
        
        except Exception as e:
            logger.error(f"Errore nell'avvio dell'access point: {e}")
            self.stop()
            return False

    def stop(self):
        """Ferma l'access point WiFi e ripristina la configurazione"""
        try:
            # Termina i processi
            if self.hostapd_process:
                self.hostapd_process.terminate()
                self.hostapd_process.wait()
                logger.info("hostapd terminato")
            
            if self.dnsmasq_process:
                self.dnsmasq_process.terminate()
                self.dnsmasq_process.wait()
                logger.info("dnsmasq terminato")
            
            # Ripristina iptables
            subprocess.run(["iptables", "-F"], check=True)
            subprocess.run(["iptables", "-t", "nat", "-F"], check=True)
            
            # Disabilita IP forwarding
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0")
            
            # Riattiva NetworkManager per questa interfaccia
            subprocess.run(["nmcli", "device", "set", self.interface, "managed", "yes"], 
                          check=True)
            
            # Rimuovi i file di configurazione
            if os.path.exists(self.hostapd_conf_path):
                os.remove(self.hostapd_conf_path)
            
            if os.path.exists(self.dnsmasq_conf_path):
                os.remove(self.dnsmasq_conf_path)
            
            logger.info(f"Access Point WiFi terminato e configurazione ripristinata")
            return True
        
        except Exception as e:
            logger.error(f"Errore nel fermare l'access point: {e}")
            return False

class DNSBlocker:
    """Classe per il blocco dei DNS legati agli AdBlock"""
    def __init__(self, interface):
        self.interface = interface
        self.running = False
        self.sniffer_thread = None
    
    def _dns_handler(self, packet):
        """Gestisce i pacchetti DNS"""
        if packet.haslayer(DNSQR) and not packet.haslayer(DNSRR):
            try:
                # Estrai il dominio
                qname = packet[DNSQR].qname.decode('utf-8')
                qname = qname.rstrip('.')
                
                # Controlla se è un dominio AdBlock
                is_adblock_domain = False
                for ad_domain in ADBLOCK_DOMAINS + ADBLOCK_URLS:
                    if ad_domain in qname:
                        is_adblock_domain = True
                        break
                
                if is_adblock_domain:
                    logger.info(f"Bloccata richiesta DNS per dominio AdBlock: {qname}")
                    
                    # Crea pacchetti di risposta con IP localhost
                    ip = packet[IP]
                    udp = packet[UDP]
                    dns = packet[DNS]
                    
                    # Crea una risposta DNS che punta a localhost
                    response = IP(dst=ip.src, src=ip.dst) / \
                               UDP(dport=udp.sport, sport=udp.dport) / \
                               DNS(
                                   id=dns.id,
                                   qr=1,  # Questo è una risposta
                                   aa=0,  # Non autoritativo
                                   rd=dns.rd,  # Mantieni il recursive desired
                                   ra=1,  # Recursive disponibile
                                   qdcount=1,
                                   ancount=1,
                                   qd=dns.qd,  # Mantieni la query originale
                                   an=DNSRR(rrname=dns.qd.qname, ttl=60, rdata="127.0.0.1")
                               )
                    
                    # Invia la risposta
                    send(response, verbose=0)
                    
            except Exception as e:
                logger.error(f"Errore nel gestire il pacchetto DNS: {e}")
    
    def start(self):
        """Avvia il blocco DNS"""
        if self.running:
            logger.warning("Il blocco DNS è già in esecuzione")
            return
        
        self.running = True
        self.sniffer_thread = threading.Thread(
            target=self._run_sniffer,
            daemon=True
        )
        self.sniffer_thread.start()
        logger.info(f"Blocco DNS avviato sull'interfaccia {self.interface}")
    
    def _run_sniffer(self):
        """Esegue lo sniffer in un thread separato"""
        try:
            sniff(
                iface=self.interface,
                filter="udp port 53",
                prn=self._dns_handler,
                store=0,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            logger.error(f"Errore nello sniffer DNS: {e}")
            self.running = False
    
    def stop(self):
        """Ferma il blocco DNS"""
        if not self.running:
            logger.warning("Il blocco DNS non è in esecuzione")
            return
        
        self.running = False
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=2)
        logger.info("Blocco DNS fermato")

class WebServer:
    """Server web minimale per intercettare richieste HTTP"""
    def __init__(self, interface, port=80):
        self.interface = interface
        self.port = port
        self.server_process = None
    
    def start(self):
        """Avvia il server web per intercettare richieste da domini AdBlock"""
        try:
            # Implementazione minima con Python http.server
            self.server_process = subprocess.Popen([
                sys.executable, "-m", "http.server", 
                "--bind", "10.0.0.1", str(self.port)
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            logger.info(f"Server web avviato su 10.0.0.1:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Errore nell'avvio del server web: {e}")
            return False
    
    def stop(self):
        """Ferma il server web"""
        if self.server_process:
            self.server_process.terminate()
            self.server_process.wait()
            logger.info("Server web fermato")

def main():
    """Funzione principale"""
    parser = argparse.ArgumentParser(description="Crea una rete WiFi che blocca gli AdBlock")
    parser.add_argument("--interface", "-i", required=True, help="Interfaccia WiFi da utilizzare")
    parser.add_argument("--ssid", "-s", default="Free_WiFi", help="Nome della rete WiFi")
    parser.add_argument("--channel", "-c", type=int, default=1, help="Canale WiFi")
    parser.add_argument("--password", "-p", help="Password per la rete WiFi (opzionale)")
    
    args = parser.parse_args()
    
    logger.info("Avvio del sistema di blocco AdBlock su rete WiFi")
    
    # Verifica i permessi di root
    if os.geteuid() != 0:
        logger.error("Questo script deve essere eseguito come root (sudo)")
        sys.exit(1)
    
    # Crea e avvia l'access point WiFi
    ap = WifiAP(args.interface, args.ssid, args.channel, args.password)
    if not ap.start():
        logger.error("Impossibile avviare l'access point WiFi. Uscita.")
        sys.exit(1)
    
    # Avvia il blocco DNS
    dns_blocker = DNSBlocker(args.interface)
    dns_blocker.start()
    
    # Avvia il server web
    web_server = WebServer(args.interface)
    web_server.start()
    
    try:
        logger.info(f"Sistema in esecuzione. Rete WiFi '{args.ssid}' attiva.")
        logger.info("Premi Ctrl+C per terminare.")
        
        # Mantieni lo script in esecuzione
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        logger.info("Interruzione rilevata. Arresto in corso...")
    
    finally:
        # Ferma tutti i servizi
        web_server.stop()
        dns_blocker.stop()
        ap.stop()
        logger.info("Sistema arrestato con successo.")

if __name__ == "__main__":
    main()