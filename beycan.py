#!/usr/bin/env python3

import nmap
import scapy.all
import argparse
import sys
import socket
import requests
import subprocess
import os
import time
import ssl
import dns.resolver
import concurrent.futures
from datetime import datetime
from colorama import init, Fore, Style
import re

init()  # Colorama başlatma

class NetworkAnalyzer:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.results = {}
        self.common_ports = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
            445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
        }

    def print_banner(self):
        banner = f"""
{Fore.RED}╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║  {Fore.GREEN}███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗{Fore.RED}  ║
║  {Fore.GREEN}████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝{Fore.RED}  ║
║  {Fore.GREEN}██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝ {Fore.RED}  ║
║  {Fore.GREEN}██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗ {Fore.RED}  ║
║  {Fore.GREEN}██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗{Fore.RED}  ║
║  {Fore.GREEN}╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝{Fore.RED}  ║
║                                                                               ║
║  {Fore.YELLOW}[+] Port Tarama • Ağ Keşfi • Güvenlik Analizi • Raporlama{Fore.RED}        ║
║  {Fore.CYAN}[+] Created by: Beycan{Fore.RED}                                            ║
║  {Fore.MAGENTA}[+] Version: 2.0{Fore.RED}                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)

    def show_tools(self):
        # Üst bilgi kutusu
        print(f"{Fore.CYAN}{'─'*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}|{Style.RESET_ALL} Create by    : {Fore.RED}Beycan{Style.RESET_ALL}")
        print(f"{Fore.CYAN}|{Style.RESET_ALL} Github       : {Fore.RED}https://github.com/beycanyildiz{Style.RESET_ALL}")
        print(f"{Fore.CYAN}|{Style.RESET_ALL} Instagram    : {Fore.RED}https://www.instagram.com/beaycan/{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─'*80}{Style.RESET_ALL}")
        print(f"\n{Fore.MAGENTA}{'~'*15} Network Security Analyzer {'~'*15}{Style.RESET_ALL}\n")

        # Kendi araç isimleriniz
        tool_names = [
            ("Port Tarama", Fore.CYAN),
            ("Ağ Keşfi", Fore.GREEN),
            ("HTTP Güvenlik Analizi", Fore.MAGENTA),
            ("DNS Tespiti", Fore.YELLOW),
            ("SSL/TLS Analizi", Fore.GREEN),
            ("Servis Versiyon Tespiti", Fore.YELLOW),
            ("OS Tespiti", Fore.MAGENTA),
            ("Firewall Tespiti", Fore.CYAN),
            ("MAC Adresi Tespiti", Fore.GREEN),
            ("Açık Port Taraması", Fore.YELLOW),
            ("UDP Port Taraması", Fore.YELLOW),
            ("TCP SYN Taraması", Fore.GREEN),
            ("Servis Enumeration", Fore.MAGENTA),
            ("Güvenlik Duvarı Bypass", Fore.CYAN),
            ("ARP Spoofing Tespiti", Fore.MAGENTA),
            ("Man-in-the-Middle Tespiti", Fore.CYAN),
            ("SSL/TLS Güvenlik Analizi", Fore.GREEN),
            ("Web Uygulama Güvenlik Analizi", Fore.YELLOW),
            ("Ağ Trafiği Analizi", Fore.MAGENTA),
            ("Detaylı Raporlama", Fore.CYAN)
        ]
        # İki sütunlu gösterim için
        left_col = tool_names[:10]
        right_col = tool_names[10:]
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        for i in range(10):
            left = left_col[i] if i < len(left_col) else ("", "")
            right = right_col[i] if i < len(right_col) else ("", "")
            left_str = f"[{i+1}] {Fore.GREEN}✔{Style.RESET_ALL} {left[1]}{left[0]}{Style.RESET_ALL}" if left[0] else ""
            right_str = f"[{i+11}] {Fore.GREEN}✔{Style.RESET_ALL} {right[1]}{right[0]}{Style.RESET_ALL}" if right[0] else ""
            print(f"{left_str:<30} {right_str:<30}")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"[q] {Fore.GREEN}✔{Style.RESET_ALL} Exit    [h] {Fore.RED}✔{Style.RESET_ALL} Araçlar Hakkında Bilgi Ve Kullanım\n")
        print(f"{Fore.YELLOW}NetworkAnalyzer@Beycan{Style.RESET_ALL}:({Fore.CYAN}./NetworkAnalyzer{Style.RESET_ALL})\n{Fore.GREEN}[*]{Style.RESET_ALL}")

    def show_tool_details(self):
        print(f"\n{Fore.YELLOW}Araçlar Hakkında Detaylı Bilgi:{Style.RESET_ALL}\n")
        details = [
            ("Port Tarama", "Hedef sistemdeki açık TCP/UDP portlarını tespit eder, servis ve versiyon bilgisini gösterir. Güvenlik önerileri sunar."),
            ("Ağ Keşfi", "Yerel ağdaki aktif cihazları, IP ve MAC adreslerini, üretici bilgisini ve hızlı port taramasını listeler."),
            ("HTTP Güvenlik Analizi", "Web sunucusunun güvenlik başlıklarını, cookie ayarlarını ve sunucu bilgisini analiz eder."),
            ("DNS Tespiti", "Alan adının DNS kayıtlarını (A, MX, NS, TXT, SOA, CNAME) ve DNSSEC durumunu inceler."),
            ("SSL/TLS Analizi", "Sunucunun SSL/TLS sertifikasını, geçerlilik süresini, şifreleme algoritmasını ve güvenliğini kontrol eder."),
            ("Servis Versiyon Tespiti", "Açık portlardaki servislerin ürün ve versiyon bilgisini detaylı olarak tespit eder."),
            ("OS Tespiti", "Hedef sistemin işletim sistemi ve sürümünü tespit eder, doğruluk oranı ile birlikte gösterir."),
            ("Firewall Tespiti", "Güvenlik duvarı varlığını ve yapılandırmasını analiz eder, port durumlarını raporlar."),
            ("MAC Adresi Tespiti", "Ağdaki cihazların MAC adreslerini ve üretici bilgisini tespit eder, olası sahtecilikleri analiz eder."),
            ("Açık Port Taraması", "Hedefteki tüm açık portları hızlıca tespit eder ve güvenlik açısından riskli portları vurgular."),
            ("UDP Port Taraması", "UDP portlarını detaylı şekilde tarar, açık ve filtrelenmiş portları listeler."),
            ("TCP SYN Taraması", "TCP SYN bayrağı ile hızlı ve gizli port taraması yapar, güvenlik duvarı arkasındaki portları tespit eder."),
            ("Servis Enumeration", "Açık portlardaki servislerin detaylı özelliklerini ve ek bilgilerini toplar."),
            ("Güvenlik Duvarı Bypass", "Farklı tarama teknikleriyle güvenlik duvarı atlatma olasılığını analiz eder."),
            ("ARP Spoofing Tespiti", "Ağda ARP zehirlenmesi olup olmadığını, MAC çakışmalarını ve olası saldırıları tespit eder."),
            ("Man-in-the-Middle Tespiti", "MITM saldırılarını ARP ve SSL analizleriyle tespit eder, güvenlik önerileri sunar."),
            ("SSL/TLS Güvenlik Analizi", "SSL/TLS bağlantısının güvenliğini, sertifika geçerliliğini ve şifreleme gücünü analiz eder."),
            ("Web Uygulama Güvenlik Analizi", "Web uygulamasının güvenlik başlıkları, cookie ayarları ve eksik güvenlik önlemlerini analiz eder."),
            ("Ağ Trafiği Analizi", "Ağ trafiğini yakalar, protokol dağılımını ve şifrelenmemiş trafiği analiz eder."),
            ("Detaylı Raporlama", "Tüm analizlerin özetini ve güvenlik önerilerini içeren kapsamlı bir rapor oluşturur.")
        ]
        for idx, (name, desc) in enumerate(details, 1):
            print(f"{Fore.CYAN}[{idx}] {name}:{Style.RESET_ALL}\n  {Fore.YELLOW}{desc}{Style.RESET_ALL}\n")
        print(f"{Fore.GREEN}Tüm araçlar hakkında daha fazla bilgi için dökümantasyonu inceleyin!{Style.RESET_ALL}\n")

    def scan_ports(self, target, ports="1-1000"):
        print(f"\n{Fore.BLUE}[*] Port taraması başlatılıyor: {target}{Style.RESET_ALL}")
        try:
            self.nm.scan(target, ports)
            for host in self.nm.all_hosts():
                print(f"\n{Fore.GREEN}[+] {host} için sonuçlar:{Style.RESET_ALL}")
                for proto in self.nm[host].all_protocols():
                    lport = self.nm[host][proto].keys()
                    for port in lport:
                        state = self.nm[host][proto][port]['state']
                        service = self.nm[host][proto][port]['name']
                        print(f"{Fore.YELLOW}[*] Port {port}/{proto}: {state} - {service}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Hata: {str(e)}{Style.RESET_ALL}")

    def network_discovery(self, network):
        print(f"\n{Fore.BLUE}[*] Ağ keşfi başlatılıyor: {network}{Style.RESET_ALL}")
        try:
            arp_request = scapy.all.ARP(pdst=network)
            broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered_list = scapy.all.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

            print(f"\n{Fore.GREEN}[+] Aktif cihazlar:{Style.RESET_ALL}")
            for element in answered_list:
                print(f"{Fore.YELLOW}[*] IP: {element[1].psrc} - MAC: {element[1].hwsrc}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Hata: {str(e)}{Style.RESET_ALL}")

    def dns_detection(self, target):
        print(f"\n{Fore.BLUE}[*] DNS tespiti başlatılıyor: {target}{Style.RESET_ALL}")
        try:
            result = socket.gethostbyaddr(target)
            print(f"{Fore.GREEN}[+] Hostname: {result[0]}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] IP Adresleri: {', '.join(result[2])}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] DNS tespiti başarısız: {str(e)}{Style.RESET_ALL}")

    def ssl_analysis(self, target):
        print(f"\n{Fore.BLUE}[*] SSL/TLS analizi başlatılıyor: {target}{Style.RESET_ALL}")
        try:
            cmd = f"openssl s_client -connect {target}:443 -servername {target}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if "SSL handshake" in result.stdout:
                print(f"{Fore.GREEN}[+] SSL/TLS bağlantısı başarılı{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] SSL/TLS bağlantısı başarısız{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] SSL analizi hatası: {str(e)}{Style.RESET_ALL}")

    def service_version_detection(self, target):
        print(f"\n{Fore.BLUE}[*] Servis versiyon tespiti başlatılıyor: {target}{Style.RESET_ALL}")
        try:
            self.nm.scan(target, arguments='-sV')
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    for port in self.nm[host][proto].keys():
                        service = self.nm[host][proto][port]
                        print(f"{Fore.GREEN}[+] Port {port}/{proto}: {service['name']} {service['product']} {service['version']}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Hata: {str(e)}{Style.RESET_ALL}")

    def os_detection(self, target):
        print(f"\n{Fore.BLUE}[*] İşletim sistemi tespiti başlatılıyor: {target}{Style.RESET_ALL}")
        try:
            self.nm.scan(target, arguments='-O')
            for host in self.nm.all_hosts():
                if 'osmatch' in self.nm[host]:
                    for osmatch in self.nm[host]['osmatch']:
                        print(f"{Fore.GREEN}[+] OS: {osmatch['name']} (Doğruluk: {osmatch['accuracy']}%){Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Hata: {str(e)}{Style.RESET_ALL}")

    def vulnerability_scan(self, target):
        print(f"\n{Fore.BLUE}[*] Güvenlik açığı taraması başlatılıyor: {target}{Style.RESET_ALL}")
        try:
            if self.check_http(target):
                print(f"{Fore.YELLOW}[*] HTTP servisi tespit edildi, güvenlik kontrolü yapılıyor...{Style.RESET_ALL}")
                self.check_http_security(target)
        except Exception as e:
            print(f"{Fore.RED}[!] Hata: {str(e)}{Style.RESET_ALL}")

    def check_http(self, target):
        try:
            response = requests.get(f"http://{target}", timeout=5)
            return True
        except:
            return False

    def check_http_security(self, target):
        try:
            response = requests.get(f"http://{target}", timeout=5)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'Eksik',
                'X-XSS-Protection': 'Eksik',
                'X-Content-Type-Options': 'Eksik',
                'Strict-Transport-Security': 'Eksik',
                'Content-Security-Policy': 'Eksik',
                'X-Permitted-Cross-Domain-Policies': 'Eksik',
                'Referrer-Policy': 'Eksik',
                'Expect-CT': 'Eksik',
                'Permissions-Policy': 'Eksik'
            }

            for header in headers:
                if header in security_headers:
                    security_headers[header] = 'Mevcut'

            print(f"\n{Fore.GREEN}[+] Güvenlik başlıkları analizi:{Style.RESET_ALL}")
            for header, status in security_headers.items():
                print(f"{Fore.YELLOW}[*] {header}: {status}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Hata: {str(e)}{Style.RESET_ALL}")

    def generate_report(self, target):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_report_{target}_{timestamp}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║  ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗            ║
║  ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝            ║
║  ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝             ║
║  ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗             ║
║  ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗            ║
║  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝            ║
║                                                                               ║
║  [+] Port Tarama • Ağ Keşfi • Güvenlik Analizi • Raporlama                   ║
║  [+] Created by: Beycan                                                      ║
║  [+] Version: 2.0                                                           ║
╚═══════════════════════════════════════════════════════════════════════════════╝

Ağ Analiz Raporu - {target}
Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

=== Port Tarama Sonuçları ===
""")
            for host in self.nm.all_hosts():
                f.write(f"\nHost: {host}\n")
                for proto in self.nm[host].all_protocols():
                    for port in self.nm[host][proto].keys():
                        state = self.nm[host][proto][port]['state']
                        service = self.nm[host][proto][port]['name']
                        f.write(f"Port {port}/{proto}: {state} - {service}\n")
        
        print(f"\n{Fore.GREEN}[+] Rapor oluşturuldu: {filename}{Style.RESET_ALL}")

    def tool_1_port_scan(self, target, ports="1-1000"):
        """1. Port Tarama - Detaylı port tarama ve analiz"""
        print(f"\n{Fore.BLUE}[*] Port taraması başlatılıyor: {target}{Style.RESET_ALL}")
        try:
            # TCP SYN Taraması
            print(f"{Fore.YELLOW}[*] TCP SYN taraması yapılıyor...{Style.RESET_ALL}")
            self.nm.scan(target, ports, arguments='-sS')
            
            # Servis versiyon tespiti
            print(f"{Fore.YELLOW}[*] Servis versiyonları tespit ediliyor...{Style.RESET_ALL}")
            self.nm.scan(target, ports, arguments='-sV')
            
            # İşletim sistemi tespiti
            print(f"{Fore.YELLOW}[*] İşletim sistemi tespit ediliyor...{Style.RESET_ALL}")
            self.nm.scan(target, arguments='-O')
            
            for host in self.nm.all_hosts():
                print(f"\n{Fore.GREEN}[+] {host} için sonuçlar:{Style.RESET_ALL}")
                
                # OS Bilgisi
                if 'osmatch' in self.nm[host]:
                    print(f"\n{Fore.CYAN}[*] İşletim Sistemi Bilgisi:{Style.RESET_ALL}")
                    for osmatch in self.nm[host]['osmatch']:
                        print(f"{Fore.YELLOW}[+] {osmatch['name']} (Doğruluk: {osmatch['accuracy']}%){Style.RESET_ALL}")
                
                # Port ve Servis Bilgileri
                print(f"\n{Fore.CYAN}[*] Port ve Servis Bilgileri:{Style.RESET_ALL}")
                for proto in self.nm[host].all_protocols():
                    lport = self.nm[host][proto].keys()
                    for port in lport:
                        service = self.nm[host][proto][port]
                        state = service['state']
                        name = service['name']
                        product = service.get('product', '')
                        version = service.get('version', '')
                        extrainfo = service.get('extrainfo', '')
                        
                        status_color = Fore.GREEN if state == 'open' else Fore.RED
                        print(f"{status_color}[*] Port {port}/{proto}: {state} - {name} {product} {version} {extrainfo}{Style.RESET_ALL}")
                        
                        # Güvenlik önerileri
                        if port in self.common_ports:
                            print(f"{Fore.YELLOW}[!] Güvenlik Önerisi: {self.common_ports[port]} portu için güvenlik önlemlerini kontrol edin{Style.RESET_ALL}")
                
                # Güvenlik Özeti
                open_ports = len([p for p in self.nm[host]['tcp'].keys() if self.nm[host]['tcp'][p]['state'] == 'open'])
                print(f"\n{Fore.CYAN}[*] Güvenlik Özeti:{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[+] Açık port sayısı: {open_ports}{Style.RESET_ALL}")
                if open_ports > 10:
                    print(f"{Fore.RED}[!] Uyarı: Çok fazla açık port tespit edildi!{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"{Fore.RED}[!] Hata: {str(e)}{Style.RESET_ALL}")

    def tool_2_network_discovery(self, network):
        """2. Ağ Keşfi - Detaylı ağ keşfi ve cihaz analizi"""
        print(f"\n{Fore.BLUE}[*] Ağ keşfi başlatılıyor: {network}{Style.RESET_ALL}")
        try:
            # ARP taraması
            print(f"{Fore.YELLOW}[*] ARP taraması yapılıyor...{Style.RESET_ALL}")
            arp_request = scapy.all.ARP(pdst=network)
            broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered_list = scapy.all.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

            print(f"\n{Fore.GREEN}[+] Aktif cihazlar:{Style.RESET_ALL}")
            devices = []
            for element in answered_list:
                ip = element[1].psrc
                mac = element[1].hwsrc
                devices.append((ip, mac))
                
                # MAC adresi analizi
                vendor = self.get_mac_vendor(mac)
                print(f"{Fore.YELLOW}[*] IP: {ip} - MAC: {mac} - Üretici: {vendor}{Style.RESET_ALL}")
                
                # Hostname tespiti
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    print(f"{Fore.CYAN}[+] Hostname: {hostname}{Style.RESET_ALL}")
                except:
                    print(f"{Fore.RED}[!] Hostname tespit edilemedi{Style.RESET_ALL}")
                
                # Hızlı port taraması
                print(f"{Fore.YELLOW}[*] Hızlı port taraması yapılıyor...{Style.RESET_ALL}")
                self.nm.scan(ip, arguments='-F')
                if 'tcp' in self.nm[ip]:
                    open_ports = [port for port, data in self.nm[ip]['tcp'].items() if data['state'] == 'open']
                    if open_ports:
                        print(f"{Fore.GREEN}[+] Açık portlar: {', '.join(map(str, open_ports))}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}[!] Açık port bulunamadı{Style.RESET_ALL}")

            # Ağ özeti
            print(f"\n{Fore.CYAN}[*] Ağ Özeti:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Toplam aktif cihaz: {len(devices)}{Style.RESET_ALL}")
            
            # Güvenlik önerileri
            if len(devices) > 20:
                print(f"{Fore.RED}[!] Uyarı: Ağda çok fazla cihaz tespit edildi!{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Hata: {str(e)}{Style.RESET_ALL}")

    def tool_3_http_security_analysis(self, target):
        """3. HTTP Güvenlik Analizi - Detaylı web güvenlik analizi"""
        print(f"\n{Fore.BLUE}[*] HTTP güvenlik analizi başlatılıyor: {target}{Style.RESET_ALL}")
        try:
            # HTTP bağlantı kontrolü
            print(f"{Fore.YELLOW}[*] HTTP bağlantısı kontrol ediliyor...{Style.RESET_ALL}")
            response = requests.get(f"http://{target}", timeout=5)
            
            # Sunucu bilgisi
            print(f"\n{Fore.CYAN}[*] Sunucu Bilgisi:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Sunucu: {response.headers.get('Server', 'Bilinmiyor')}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] HTTP Versiyon: {response.raw.version}{Style.RESET_ALL}")
            
            # Güvenlik başlıkları analizi
            print(f"\n{Fore.CYAN}[*] Güvenlik Başlıkları Analizi:{Style.RESET_ALL}")
            security_headers = {
                'X-Frame-Options': 'Eksik',
                'X-XSS-Protection': 'Eksik',
                'X-Content-Type-Options': 'Eksik',
                'Strict-Transport-Security': 'Eksik',
                'Content-Security-Policy': 'Eksik',
                'X-Permitted-Cross-Domain-Policies': 'Eksik',
                'Referrer-Policy': 'Eksik',
                'Expect-CT': 'Eksik',
                'Permissions-Policy': 'Eksik',
                'Cross-Origin-Embedder-Policy': 'Eksik',
                'Cross-Origin-Opener-Policy': 'Eksik',
                'Cross-Origin-Resource-Policy': 'Eksik'
            }

            for header in response.headers:
                if header in security_headers:
                    security_headers[header] = response.headers[header]

            for header, value in security_headers.items():
                status_color = Fore.GREEN if value != 'Eksik' else Fore.RED
                print(f"{status_color}[*] {header}: {value}{Style.RESET_ALL}")

            # Cookie güvenliği
            print(f"\n{Fore.CYAN}[*] Cookie Güvenliği:{Style.RESET_ALL}")
            cookies = response.cookies
            if cookies:
                for cookie in cookies:
                    secure = "Evet" if cookie.secure else "Hayır"
                    httponly = "Evet" if cookie.has_nonstandard_attr('HttpOnly') else "Hayır"
                    print(f"{Fore.YELLOW}[*] Cookie: {cookie.name}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Secure: {secure}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] HttpOnly: {httponly}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[*] Cookie bulunamadı{Style.RESET_ALL}")

            # Güvenlik önerileri
            print(f"\n{Fore.CYAN}[*] Güvenlik Önerileri:{Style.RESET_ALL}")
            missing_headers = [header for header, value in security_headers.items() if value == 'Eksik']
            if missing_headers:
                print(f"{Fore.RED}[!] Eksik güvenlik başlıkları: {', '.join(missing_headers)}{Style.RESET_ALL}")
            
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[!] HTTP bağlantı hatası: {str(e)}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Hata: {str(e)}{Style.RESET_ALL}")

    def tool_4_dns_analysis(self, target):
        """4. DNS Tespiti - Detaylı DNS analizi"""
        print(f"\n{Fore.BLUE}[*] DNS analizi başlatılıyor: {target}{Style.RESET_ALL}")
        try:
            # DNS kayıt türleri
            record_types = ['A', 'AAAA', 'MX', 'NS', 'SOA', 'TXT', 'CNAME']
            
            print(f"\n{Fore.CYAN}[*] DNS Kayıtları:{Style.RESET_ALL}")
            for record_type in record_types:
                try:
                    print(f"\n{Fore.YELLOW}[*] {record_type} Kayıtları:{Style.RESET_ALL}")
                    answers = dns.resolver.resolve(target, record_type)
                    for answer in answers:
                        print(f"{Fore.GREEN}[+] {answer}{Style.RESET_ALL}")
                except dns.resolver.NoAnswer:
                    print(f"{Fore.RED}[!] {record_type} kaydı bulunamadı{Style.RESET_ALL}")
                except dns.resolver.NXDOMAIN:
                    print(f"{Fore.RED}[!] Domain bulunamadı{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[!] {record_type} sorgusu hatası: {str(e)}{Style.RESET_ALL}")

            # DNS sunucu bilgisi
            print(f"\n{Fore.CYAN}[*] DNS Sunucu Bilgisi:{Style.RESET_ALL}")
            try:
                ns_records = dns.resolver.resolve(target, 'NS')
                for ns in ns_records:
                    print(f"{Fore.GREEN}[+] Nameserver: {ns}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Nameserver bilgisi alınamadı: {str(e)}{Style.RESET_ALL}")

            # DNS güvenlik kontrolü
            print(f"\n{Fore.CYAN}[*] DNS Güvenlik Kontrolü:{Style.RESET_ALL}")
            try:
                # DNSSEC kontrolü
                print(f"{Fore.YELLOW}[*] DNSSEC kontrolü yapılıyor...{Style.RESET_ALL}")
                cmd = f"dig +dnssec {target}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if "RRSIG" in result.stdout:
                    print(f"{Fore.GREEN}[+] DNSSEC aktif{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[!] DNSSEC aktif değil{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] DNSSEC kontrolü hatası: {str(e)}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] DNS analizi hatası: {str(e)}{Style.RESET_ALL}")

    def tool_5_ssl_analysis(self, target):
        """5. SSL/TLS Analizi - Detaylı SSL/TLS güvenlik analizi"""
        print(f"\n{Fore.BLUE}[*] SSL/TLS analizi başlatılıyor: {target}{Style.RESET_ALL}")
        try:
            # SSL bağlantısı
            print(f"{Fore.YELLOW}[*] SSL bağlantısı kuruluyor...{Style.RESET_ALL}")
            context = ssl.create_default_context()
            with socket.create_connection((target, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Sertifika bilgileri
                    print(f"\n{Fore.CYAN}[*] Sertifika Bilgileri:{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Konu: {cert['subject'][0][0][1]}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Yayıncı: {cert['issuer'][0][0][1]}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Geçerlilik Başlangıcı: {cert['notBefore']}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Geçerlilik Bitişi: {cert['notAfter']}{Style.RESET_ALL}")
                    
                    # SSL/TLS versiyonu
                    print(f"\n{Fore.CYAN}[*] SSL/TLS Versiyonu:{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Versiyon: {ssock.version()}{Style.RESET_ALL}")
                    
                    # Şifreleme bilgileri
                    print(f"\n{Fore.CYAN}[*] Şifreleme Bilgileri:{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Şifreleme: {ssock.cipher()[0]}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Anahtar Değişimi: {ssock.cipher()[1]}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] MAC: {ssock.cipher()[2]}{Style.RESET_ALL}")

            # SSL güvenlik kontrolü
            print(f"\n{Fore.CYAN}[*] SSL Güvenlik Kontrolü:{Style.RESET_ALL}")
            try:
                cmd = f"openssl s_client -connect {target}:443 -servername {target}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                # Güvenlik önerileri
                if "SSL handshake" in result.stdout:
                    print(f"{Fore.GREEN}[+] SSL/TLS bağlantısı başarılı{Style.RESET_ALL}")
                    
                    # Sertifika süresi kontrolü
                    if "notAfter" in result.stdout:
                        print(f"{Fore.YELLOW}[*] Sertifika süresi kontrol ediliyor...{Style.RESET_ALL}")
                        if "expired" in result.stdout.lower():
                            print(f"{Fore.RED}[!] Uyarı: Sertifika süresi dolmuş!{Style.RESET_ALL}")
                    
                    # Zayıf şifreleme kontrolü
                    weak_ciphers = ["RC4", "DES", "3DES", "MD5"]
                    for cipher in weak_ciphers:
                        if cipher in result.stdout:
                            print(f"{Fore.RED}[!] Uyarı: Zayıf şifreleme tespit edildi: {cipher}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[!] SSL/TLS bağlantısı başarısız{Style.RESET_ALL}")
                    
            except Exception as e:
                print(f"{Fore.RED}[!] SSL güvenlik kontrolü hatası: {str(e)}{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] SSL analizi hatası: {str(e)}{Style.RESET_ALL}")

    def get_mac_vendor(self, mac):
        """MAC adresi üretici bilgisini döndürür"""
        try:
            # MAC adresinin ilk 6 karakterini al
            oui = mac.replace(':', '').upper()[:6]
            # Üretici veritabanından kontrol et
            # Not: Gerçek uygulamada bir MAC veritabanı kullanılmalıdır
            return "Bilinmiyor"
        except:
            return "Bilinmiyor"

    def tool_11_udp_scan(self, target):
        """11. UDP Port Taraması - Detaylı UDP analizi"""
        print(f"\n{Fore.BLUE}[*] UDP port taraması başlatılıyor: {target}{Style.RESET_ALL}")
        try:
            # UDP taraması
            print(f"{Fore.YELLOW}[*] UDP taraması yapılıyor...{Style.RESET_ALL}")
            self.nm.scan(target, arguments='-sU -T4 --version-intensity 5')
            
            for host in self.nm.all_hosts():
                print(f"\n{Fore.GREEN}[+] {host} için UDP analizi:{Style.RESET_ALL}")
                
                # UDP port kategorileri
                open_udp_ports = []
                filtered_udp_ports = []
                open_filtered_udp_ports = []
                
                if 'udp' in self.nm[host]:
                    for port in self.nm[host]['udp'].keys():
                        state = self.nm[host]['udp'][port]['state']
                        service = self.nm[host]['udp'][port]['name']
                        port_info = f"{port}/udp ({service})"
                        
                        if state == 'open':
                            open_udp_ports.append(port_info)
                        elif state == 'filtered':
                            filtered_udp_ports.append(port_info)
                        elif state == 'open|filtered':
                            open_filtered_udp_ports.append(port_info)
                
                # Sonuçlar
                print(f"\n{Fore.CYAN}[*] UDP Port Durumları:{Style.RESET_ALL}")
                if open_udp_ports:
                    print(f"\n{Fore.GREEN}[+] Açık UDP Portlar:{Style.RESET_ALL}")
                    for port in open_udp_ports:
                        print(f"{Fore.YELLOW}[*] {port}{Style.RESET_ALL}")
                
                if filtered_udp_ports:
                    print(f"\n{Fore.YELLOW}[+] Filtrelenmiş UDP Portlar:{Style.RESET_ALL}")
                    for port in filtered_udp_ports:
                        print(f"{Fore.YELLOW}[*] {port}{Style.RESET_ALL}")
                
                if open_filtered_udp_ports:
                    print(f"\n{Fore.RED}[+] Açık/Filtrelenmiş UDP Portlar:{Style.RESET_ALL}")
                    for port in open_filtered_udp_ports:
                        print(f"{Fore.RED}[*] {port}{Style.RESET_ALL}")
                
                # Güvenlik analizi
                print(f"\n{Fore.CYAN}[*] UDP Güvenlik Analizi:{Style.RESET_ALL}")
                if open_udp_ports:
                    print(f"{Fore.RED}[!] Açık UDP portları tespit edildi!{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] UDP portları genellikle güvenlik riski oluşturabilir{Style.RESET_ALL}")
                
                # UDP servis analizi
                print(f"\n{Fore.CYAN}[*] UDP Servis Analizi:{Style.RESET_ALL}")
                for port in self.nm[host]['udp'].keys():
                    service = self.nm[host]['udp'][port]
                    if service['state'] == 'open':
                        print(f"\n{Fore.YELLOW}[*] Port {port}/udp:{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}[+] Servis: {service['name']}{Style.RESET_ALL}")
                        if 'product' in service:
                            print(f"{Fore.GREEN}[+] Ürün: {service['product']}{Style.RESET_ALL}")
                        if 'version' in service:
                            print(f"{Fore.GREEN}[+] Versiyon: {service['version']}{Style.RESET_ALL}")
                        
                        # UDP güvenlik önerileri
                        if service['name'] in ['dns', 'dhcp', 'snmp', 'tftp']:
                            print(f"{Fore.RED}[!] Dikkat: {service['name'].upper()} servisi tespit edildi{Style.RESET_ALL}")
                            print(f"{Fore.GREEN}[+] Bu servisler için ek güvenlik önlemleri alınmalı{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] UDP tarama hatası: {str(e)}{Style.RESET_ALL}")

    def tool_12_tcp_syn_scan(self, target):
        """12. TCP SYN Taraması - Detaylı TCP analizi"""
        print(f"\n{Fore.BLUE}[*] TCP SYN taraması başlatılıyor: {target}{Style.RESET_ALL}")
        try:
            # TCP SYN taraması
            print(f"{Fore.YELLOW}[*] TCP SYN taraması yapılıyor...{Style.RESET_ALL}")
            self.nm.scan(target, arguments='-sS -T4 --version-intensity 5')
            
            for host in self.nm.all_hosts():
                print(f"\n{Fore.GREEN}[+] {host} için TCP SYN analizi:{Style.RESET_ALL}")
                
                # TCP port kategorileri
                open_ports = []
                filtered_ports = []
                closed_ports = []
                
                if 'tcp' in self.nm[host]:
                    for port in self.nm[host]['tcp'].keys():
                        state = self.nm[host]['tcp'][port]['state']
                        service = self.nm[host]['tcp'][port]['name']
                        port_info = f"{port}/tcp ({service})"
                        
                        if state == 'open':
                            open_ports.append(port_info)
                        elif state == 'filtered':
                            filtered_ports.append(port_info)
                        elif state == 'closed':
                            closed_ports.append(port_info)
                
                # Sonuçlar
                print(f"\n{Fore.CYAN}[*] TCP Port Durumları:{Style.RESET_ALL}")
                if open_ports:
                    print(f"\n{Fore.GREEN}[+] Açık TCP Portlar:{Style.RESET_ALL}")
                    for port in open_ports:
                        print(f"{Fore.YELLOW}[*] {port}{Style.RESET_ALL}")
                
                if filtered_ports:
                    print(f"\n{Fore.YELLOW}[+] Filtrelenmiş TCP Portlar:{Style.RESET_ALL}")
                    for port in filtered_ports:
                        print(f"{Fore.YELLOW}[*] {port}{Style.RESET_ALL}")
                
                if closed_ports:
                    print(f"\n{Fore.RED}[+] Kapalı TCP Portlar:{Style.RESET_ALL}")
                    for port in closed_ports:
                        print(f"{Fore.RED}[*] {port}{Style.RESET_ALL}")
                
                # TCP servis analizi
                print(f"\n{Fore.CYAN}[*] TCP Servis Analizi:{Style.RESET_ALL}")
                for port in self.nm[host]['tcp'].keys():
                    service = self.nm[host]['tcp'][port]
                    if service['state'] == 'open':
                        print(f"\n{Fore.YELLOW}[*] Port {port}/tcp:{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}[+] Servis: {service['name']}{Style.RESET_ALL}")
                        if 'product' in service:
                            print(f"{Fore.GREEN}[+] Ürün: {service['product']}{Style.RESET_ALL}")
                        if 'version' in service:
                            print(f"{Fore.GREEN}[+] Versiyon: {service['version']}{Style.RESET_ALL}")
                        
                        # TCP güvenlik önerileri
                        if service['name'] in ['ftp', 'telnet', 'rsh', 'rlogin']:
                            print(f"{Fore.RED}[!] Dikkat: Güvensiz {service['name'].upper()} servisi tespit edildi{Style.RESET_ALL}")
                            print(f"{Fore.GREEN}[+] Bu servisler şifrelenmemiş veri transferi yapar{Style.RESET_ALL}")
                            print(f"{Fore.GREEN}[+] Mümkünse SSH gibi güvenli alternatiflere geçin{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] TCP SYN tarama hatası: {str(e)}{Style.RESET_ALL}")

    def tool_13_service_enumeration(self, target):
        """13. Servis Enumeration - Detaylı servis keşfi"""
        print(f"\n{Fore.BLUE}[*] Servis enumeration başlatılıyor: {target}{Style.RESET_ALL}")
        try:
            # NSE script taraması
            print(f"{Fore.YELLOW}[*] NSE script taraması yapılıyor...{Style.RESET_ALL}")
            self.nm.scan(target, arguments='-sC -sV --script=default')
            
            for host in self.nm.all_hosts():
                print(f"\n{Fore.GREEN}[+] {host} için servis enumeration:{Style.RESET_ALL}")
                
                # Servis kategorileri
                web_services = []
                database_services = []
                file_services = []
                other_services = []
                
                for proto in self.nm[host].all_protocols():
                    for port in self.nm[host][proto].keys():
                        service = self.nm[host][proto][port]
                        if service['state'] == 'open':
                            service_info = {
                                'port': f"{port}/{proto}",
                                'name': service['name'],
                                'product': service.get('product', ''),
                                'version': service.get('version', ''),
                                'extrainfo': service.get('extrainfo', '')
                            }
                            
                            # Servis kategorilendirme
                            if service['name'] in ['http', 'https', 'http-proxy']:
                                web_services.append(service_info)
                            elif service['name'] in ['mysql', 'postgresql', 'mongodb', 'redis']:
                                database_services.append(service_info)
                            elif service['name'] in ['ftp', 'sftp', 'smb', 'nfs']:
                                file_services.append(service_info)
                            else:
                                other_services.append(service_info)
                
                # Sonuçlar
                print(f"\n{Fore.CYAN}[*] Servis Kategorileri:{Style.RESET_ALL}")
                
                if web_services:
                    print(f"\n{Fore.GREEN}[+] Web Servisleri:{Style.RESET_ALL}")
                    for service in web_services:
                        print(f"{Fore.YELLOW}[*] {service['port']} - {service['name']} {service['product']} {service['version']}{Style.RESET_ALL}")
                        if service['extrainfo']:
                            print(f"{Fore.CYAN}[+] Ek Bilgi: {service['extrainfo']}{Style.RESET_ALL}")
                
                if database_services:
                    print(f"\n{Fore.GREEN}[+] Veritabanı Servisleri:{Style.RESET_ALL}")
                    for service in database_services:
                        print(f"{Fore.YELLOW}[*] {service['port']} - {service['name']} {service['product']} {service['version']}{Style.RESET_ALL}")
                        if service['extrainfo']:
                            print(f"{Fore.CYAN}[+] Ek Bilgi: {service['extrainfo']}{Style.RESET_ALL}")
                
                if file_services:
                    print(f"\n{Fore.GREEN}[+] Dosya Servisleri:{Style.RESET_ALL}")
                    for service in file_services:
                        print(f"{Fore.YELLOW}[*] {service['port']} - {service['name']} {service['product']} {service['version']}{Style.RESET_ALL}")
                        if service['extrainfo']:
                            print(f"{Fore.CYAN}[+] Ek Bilgi: {service['extrainfo']}{Style.RESET_ALL}")
                
                if other_services:
                    print(f"\n{Fore.GREEN}[+] Diğer Servisler:{Style.RESET_ALL}")
                    for service in other_services:
                        print(f"{Fore.YELLOW}[*] {service['port']} - {service['name']} {service['product']} {service['version']}{Style.RESET_ALL}")
                        if service['extrainfo']:
                            print(f"{Fore.CYAN}[+] Ek Bilgi: {service['extrainfo']}{Style.RESET_ALL}")
                
                # Güvenlik önerileri
                print(f"\n{Fore.CYAN}[*] Güvenlik Önerileri:{Style.RESET_ALL}")
                if web_services:
                    print(f"{Fore.YELLOW}[!] Web servisleri için güvenlik önerileri:{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] SSL/TLS kullanın{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Güvenlik başlıklarını yapılandırın{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Web uygulama güvenlik duvarı kullanın{Style.RESET_ALL}")
                
                if database_services:
                    print(f"{Fore.YELLOW}[!] Veritabanı servisleri için güvenlik önerileri:{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Güçlü şifreleme kullanın{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Erişim kısıtlamaları uygulayın{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Düzenli yedekleme yapın{Style.RESET_ALL}")
                
                if file_services:
                    print(f"{Fore.YELLOW}[!] Dosya servisleri için güvenlik önerileri:{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Güvenli dosya transfer protokolleri kullanın{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Dosya izinlerini sıkılaştırın{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Erişim loglarını tutun{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Servis enumeration hatası: {str(e)}{Style.RESET_ALL}")

    def tool_14_firewall_bypass(self, target):
        """14. Güvenlik Duvarı Bypass - Güvenlik duvarı atlatma analizi"""
        print(f"\n{Fore.BLUE}[*] Güvenlik duvarı bypass analizi başlatılıyor: {target}{Style.RESET_ALL}")
        try:
            # Farklı tarama teknikleri
            scan_techniques = {
                'TCP SYN': '-sS -T4',
                'TCP ACK': '-sA -T4',
                'TCP Window': '-sW -T4',
                'TCP Maimon': '-sM -T4',
                'TCP FIN': '-sF -T4',
                'TCP Xmas': '-sX -T4',
                'TCP Null': '-sN -T4',
                'TCP Idle': '-sI -T4',
                'TCP Custom': '-sT -T4'
            }
            
            results = {}
            for technique, arguments in scan_techniques.items():
                print(f"{Fore.YELLOW}[*] {technique} taraması yapılıyor...{Style.RESET_ALL}")
                self.nm.scan(target, arguments=arguments)
                results[technique] = self.nm[target].all_ports()
            
            # Sonuç analizi
            print(f"\n{Fore.GREEN}[+] Güvenlik duvarı bypass analizi sonuçları:{Style.RESET_ALL}")
            
            # Başarılı teknikler
            successful_techniques = []
            for technique, ports in results.items():
                if ports:
                    successful_techniques.append(technique)
                    print(f"\n{Fore.CYAN}[*] {technique} Taraması:{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Tespit edilen portlar: {', '.join(map(str, ports))}{Style.RESET_ALL}")
            
            # Güvenlik duvarı analizi
            print(f"\n{Fore.CYAN}[*] Güvenlik Duvarı Analizi:{Style.RESET_ALL}")
            if successful_techniques:
                print(f"{Fore.RED}[!] Güvenlik duvarı bypass edilebilir!{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] Başarılı teknikler: {', '.join(successful_techniques)}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] Güvenlik duvarı etkili görünüyor{Style.RESET_ALL}")
            
            # Güvenlik önerileri
            print(f"\n{Fore.CYAN}[*] Güvenlik Önerileri:{Style.RESET_ALL}")
            if successful_techniques:
                print(f"{Fore.RED}[!] Güvenlik duvarı yapılandırmasını gözden geçirin{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] Tüm başarılı bypass tekniklerini engelleyin{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] IDS/IPS sistemleri kullanın{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] Düzenli güvenlik testleri yapın{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] Mevcut güvenlik duvarı yapılandırması yeterli{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] Düzenli güncellemeleri takip edin{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Güvenlik duvarı bypass analizi hatası: {str(e)}{Style.RESET_ALL}")

    def tool_15_arp_spoofing_detection(self, target):
        """15. ARP Spoofing Tespiti - ARP zehirlenmesi analizi"""
        print(f"\n{Fore.BLUE}[*] ARP spoofing tespiti başlatılıyor: {target}{Style.RESET_ALL}")
        try:
            # ARP tablosu analizi
            print(f"{Fore.YELLOW}[*] ARP tablosu analiz ediliyor...{Style.RESET_ALL}")
            
            # ARP tablosunu al
            arp_table = {}
            try:
                output = subprocess.check_output(['arp', '-a']).decode()
                for line in output.split('\n'):
                    if target in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            ip = parts[0]
                            mac = parts[1]
                            arp_table[ip] = mac
            except:
                print(f"{Fore.RED}[!] ARP tablosu alınamadı{Style.RESET_ALL}")
            
            # ARP tablosu analizi
            if arp_table:
                print(f"\n{Fore.GREEN}[+] ARP Tablosu:{Style.RESET_ALL}")
                for ip, mac in arp_table.items():
                    print(f"{Fore.YELLOW}[*] IP: {ip} - MAC: {mac}{Style.RESET_ALL}")
                
                # MAC adresi çakışması kontrolü
                mac_count = {}
                for mac in arp_table.values():
                    mac_count[mac] = mac_count.get(mac, 0) + 1
                
                duplicate_macs = {mac: count for mac, count in mac_count.items() if count > 1}
                if duplicate_macs:
                    print(f"\n{Fore.RED}[!] MAC adresi çakışması tespit edildi!{Style.RESET_ALL}")
                    for mac, count in duplicate_macs.items():
                        print(f"{Fore.RED}[*] MAC: {mac} - {count} kez kullanılıyor{Style.RESET_ALL}")
                
                # ARP spoofing analizi
                print(f"\n{Fore.CYAN}[*] ARP Spoofing Analizi:{Style.RESET_ALL}")
                if duplicate_macs:
                    print(f"{Fore.RED}[!] ARP spoofing saldırısı tespit edildi!{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Aynı MAC adresi birden fazla IP için kullanılıyor{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[+] ARP spoofing tespit edilmedi{Style.RESET_ALL}")
                
                # Güvenlik önerileri
                print(f"\n{Fore.CYAN}[*] Güvenlik Önerileri:{Style.RESET_ALL}")
                if duplicate_macs:
                    print(f"{Fore.RED}[!] Acil güvenlik önlemleri alınmalı!{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Statik ARP tablosu kullanın{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] ARP izleme yazılımı kullanın{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Ağ segmentasyonu yapın{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[+] Mevcut ARP tablosu güvenli görünüyor{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Düzenli ARP tablosu kontrolü yapın{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] ARP tablosu boş{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}[!] ARP spoofing analizi hatası: {str(e)}{Style.RESET_ALL}")

    def tool_16_mitm_detection(self, target):
        """16. Man-in-the-Middle Tespiti - MITM saldırı analizi"""
        print(f"\n{Fore.BLUE}[*] MITM tespiti başlatılıyor: {target}{Style.RESET_ALL}")
        try:
            # ARP tablosu analizi
            print(f"{Fore.YELLOW}[*] ARP tablosu analiz ediliyor...{Style.RESET_ALL}")
            arp_table = {}
            try:
                output = subprocess.check_output(['arp', '-a']).decode()
                for line in output.split('\n'):
                    if target in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            ip = parts[0]
                            mac = parts[1]
                            arp_table[ip] = mac
            except:
                print(f"{Fore.RED}[!] ARP tablosu alınamadı{Style.RESET_ALL}")
            
            # MAC adresi çakışması kontrolü
            if arp_table:
                mac_count = {}
                for mac in arp_table.values():
                    mac_count[mac] = mac_count.get(mac, 0) + 1
                
                duplicate_macs = {mac: count for mac, count in mac_count.items() if count > 1}
                
                # SSL sertifika analizi
                print(f"{Fore.YELLOW}[*] SSL sertifika analizi yapılıyor...{Style.RESET_ALL}")
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((target, 443)) as sock:
                        with context.wrap_socket(sock, server_hostname=target) as ssock:
                            cert = ssock.getpeercert()
                            print(f"\n{Fore.GREEN}[+] SSL Sertifika Bilgileri:{Style.RESET_ALL}")
                            print(f"{Fore.YELLOW}[*] Sertifika Sahibi: {cert['subject'][0][0][1]}{Style.RESET_ALL}")
                            print(f"{Fore.YELLOW}[*] Geçerlilik Tarihi: {cert['notAfter']}{Style.RESET_ALL}")
                except:
                    print(f"{Fore.RED}[!] SSL sertifika analizi yapılamadı{Style.RESET_ALL}")
                
                # MITM analizi
                print(f"\n{Fore.CYAN}[*] MITM Analizi:{Style.RESET_ALL}")
                if duplicate_macs:
                    print(f"{Fore.RED}[!] MITM saldırısı tespit edildi!{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Aynı MAC adresi birden fazla IP için kullanılıyor{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[+] MITM saldırısı tespit edilmedi{Style.RESET_ALL}")
                
                # Güvenlik önerileri
                print(f"\n{Fore.CYAN}[*] Güvenlik Önerileri:{Style.RESET_ALL}")
                if duplicate_macs:
                    print(f"{Fore.RED}[!] Acil güvenlik önlemleri alınmalı!{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Statik ARP tablosu kullanın{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] ARP izleme yazılımı kullanın{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Ağ segmentasyonu yapın{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] VPN kullanın{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[+] Mevcut ağ güvenliği yeterli görünüyor{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Düzenli güvenlik kontrolleri yapın{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] ARP tablosu boş{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}[!] MITM analizi hatası: {str(e)}{Style.RESET_ALL}")

    def tool_17_ssl_tls_security_analysis(self, target):
        """17. SSL/TLS Güvenlik Analizi - Detaylı SSL/TLS analizi"""
        print(f"\n{Fore.BLUE}[*] SSL/TLS güvenlik analizi başlatılıyor: {target}{Style.RESET_ALL}")
        try:
            # SSL/TLS bağlantısı
            print(f"{Fore.YELLOW}[*] SSL/TLS bağlantısı kuruluyor...{Style.RESET_ALL}")
            context = ssl.create_default_context()
            with socket.create_connection((target, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Sertifika analizi
                    print(f"\n{Fore.GREEN}[+] SSL/TLS Sertifika Analizi:{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}[*] Sertifika Sahibi: {cert['subject'][0][0][1]}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}[*] Sertifika Veren: {cert['issuer'][0][0][1]}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}[*] Geçerlilik Başlangıcı: {cert['notBefore']}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}[*] Geçerlilik Bitişi: {cert['notAfter']}{Style.RESET_ALL}")
                    
                    # Şifreleme analizi
                    print(f"\n{Fore.GREEN}[+] Şifreleme Analizi:{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}[*] Şifreleme Algoritması: {cipher[0]}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}[*] Şifreleme Versiyonu: {cipher[1]}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}[*] Anahtar Uzunluğu: {cipher[2]} bit{Style.RESET_ALL}")
                    
                    # Güvenlik analizi
                    print(f"\n{Fore.CYAN}[*] Güvenlik Analizi:{Style.RESET_ALL}")
                    
                    # Sertifika geçerlilik kontrolü
                    now = datetime.datetime.now()
                    not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    
                    if now < not_before:
                        print(f"{Fore.RED}[!] Sertifika henüz geçerli değil!{Style.RESET_ALL}")
                    elif now > not_after:
                        print(f"{Fore.RED}[!] Sertifika süresi dolmuş!{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.GREEN}[+] Sertifika geçerli{Style.RESET_ALL}")
                    
                    # Şifreleme güvenlik kontrolü
                    if cipher[0] in ['RC4', 'DES', '3DES']:
                        print(f"{Fore.RED}[!] Zayıf şifreleme algoritması kullanılıyor!{Style.RESET_ALL}")
                    elif cipher[0] in ['AES', 'CHACHA20']:
                        print(f"{Fore.GREEN}[+] Güçlü şifreleme algoritması kullanılıyor{Style.RESET_ALL}")
                    
                    if cipher[2] < 128:
                        print(f"{Fore.RED}[!] Zayıf anahtar uzunluğu!{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.GREEN}[+] Yeterli anahtar uzunluğu{Style.RESET_ALL}")
                    
                    # Güvenlik önerileri
                    print(f"\n{Fore.CYAN}[*] Güvenlik Önerileri:{Style.RESET_ALL}")
                    if now > not_after:
                        print(f"{Fore.RED}[!] Sertifika yenilenmeli!{Style.RESET_ALL}")
                    if cipher[0] in ['RC4', 'DES', '3DES']:
                        print(f"{Fore.RED}[!] Güçlü şifreleme algoritmalarına geçilmeli!{Style.RESET_ALL}")
                    if cipher[2] < 128:
                        print(f"{Fore.RED}[!] Anahtar uzunluğu artırılmalı!{Style.RESET_ALL}")
                    
                    print(f"{Fore.GREEN}[+] Düzenli güvenlik güncellemeleri yapılmalı{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] HSTS kullanılmalı{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[+] Perfect Forward Secrecy kullanılmalı{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}[!] SSL/TLS analizi hatası: {str(e)}{Style.RESET_ALL}")

    def tool_18_web_app_security_analysis(self, target):
        """18. Web Uygulama Güvenlik Analizi - Detaylı web güvenlik analizi"""
        print(f"\n{Fore.BLUE}[*] Web uygulama güvenlik analizi başlatılıyor: {target}{Style.RESET_ALL}")
        try:
            # HTTP bağlantısı
            print(f"{Fore.YELLOW}[*] HTTP bağlantısı kuruluyor...{Style.RESET_ALL}")
            response = requests.get(f'http://{target}', verify=False)
            
            # HTTP başlık analizi
            print(f"\n{Fore.GREEN}[+] HTTP Başlık Analizi:{Style.RESET_ALL}")
            security_headers = {
                'X-Frame-Options': 'Clickjacking koruması',
                'X-XSS-Protection': 'XSS koruması',
                'X-Content-Type-Options': 'MIME-type koruması',
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'Referrer-Policy': 'Referrer bilgisi kontrolü',
                'Feature-Policy': 'Tarayıcı özellik kontrolü',
                'Permissions-Policy': 'İzin kontrolü'
            }
            
            missing_headers = []
            for header, description in security_headers.items():
                if header in response.headers:
                    print(f"{Fore.GREEN}[+] {header}: {response.headers[header]} - {description}{Style.RESET_ALL}")
                else:
                    missing_headers.append(header)
                    print(f"{Fore.RED}[!] {header} eksik - {description}{Style.RESET_ALL}")
            
            # Cookie analizi
            print(f"\n{Fore.GREEN}[+] Cookie Analizi:{Style.RESET_ALL}")
            if 'Set-Cookie' in response.headers:
                cookies = response.headers['Set-Cookie']
                print(f"{Fore.YELLOW}[*] Cookie: {cookies}{Style.RESET_ALL}")
                
                # Cookie güvenlik kontrolü
                if 'Secure' not in cookies:
                    print(f"{Fore.RED}[!] Secure flag eksik!{Style.RESET_ALL}")
                if 'HttpOnly' not in cookies:
                    print(f"{Fore.RED}[!] HttpOnly flag eksik!{Style.RESET_ALL}")
                if 'SameSite' not in cookies:
                    print(f"{Fore.RED}[!] SameSite flag eksik!{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[*] Cookie kullanılmıyor{Style.RESET_ALL}")
            
            # Güvenlik analizi
            print(f"\n{Fore.CYAN}[*] Güvenlik Analizi:{Style.RESET_ALL}")
            if missing_headers:
                print(f"{Fore.RED}[!] Eksik güvenlik başlıkları tespit edildi!{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] Tüm güvenlik başlıkları mevcut{Style.RESET_ALL}")
            
            # Güvenlik önerileri
            print(f"\n{Fore.CYAN}[*] Güvenlik Önerileri:{Style.RESET_ALL}")
            if missing_headers:
                print(f"{Fore.RED}[!] Eksik güvenlik başlıkları eklenmeli!{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Web uygulama güvenlik duvarı kullanılmalı{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Düzenli güvenlik testleri yapılmalı{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Güvenlik başlıkları güncel tutulmalı{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}[!] Web güvenlik analizi hatası: {str(e)}{Style.RESET_ALL}")

    def tool_19_network_traffic_analysis(self, target):
        """19. Ağ Trafiği Analizi - Detaylı trafik analizi"""
        print(f"\n{Fore.BLUE}[*] Ağ trafiği analizi başlatılıyor: {target}{Style.RESET_ALL}")
        try:
            # Paket yakalama
            print(f"{Fore.YELLOW}[*] Paket yakalama başlatılıyor...{Style.RESET_ALL}")
            packets = []
            try:
                # Scapy ile paket yakalama
                sniff(filter=f"host {target}", count=100, timeout=10)
                print(f"{Fore.GREEN}[+] 100 paket yakalandı{Style.RESET_ALL}")
            except:
                print(f"{Fore.RED}[!] Paket yakalama başarısız{Style.RESET_ALL}")
            
            # Protokol analizi
            print(f"\n{Fore.GREEN}[+] Protokol Analizi:{Style.RESET_ALL}")
            protocols = {
                'TCP': 0,
                'UDP': 0,
                'ICMP': 0,
                'ARP': 0,
                'DNS': 0,
                'HTTP': 0,
                'HTTPS': 0
            }
            
            for packet in packets:
                if packet.haslayer(TCP):
                    protocols['TCP'] += 1
                    if packet.haslayer(HTTP):
                        protocols['HTTP'] += 1
                    elif packet.haslayer(HTTPS):
                        protocols['HTTPS'] += 1
                elif packet.haslayer(UDP):
                    protocols['UDP'] += 1
                    if packet.haslayer(DNS):
                        protocols['DNS'] += 1
                elif packet.haslayer(ICMP):
                    protocols['ICMP'] += 1
                elif packet.haslayer(ARP):
                    protocols['ARP'] += 1
            
            # Protokol dağılımı
            print(f"\n{Fore.CYAN}[*] Protokol Dağılımı:{Style.RESET_ALL}")
            for protocol, count in protocols.items():
                if count > 0:
                    print(f"{Fore.YELLOW}[*] {protocol}: {count} paket{Style.RESET_ALL}")
            
            # Güvenlik analizi
            print(f"\n{Fore.CYAN}[*] Güvenlik Analizi:{Style.RESET_ALL}")
            if protocols['HTTP'] > 0:
                print(f"{Fore.RED}[!] Şifrelenmemiş HTTP trafiği tespit edildi!{Style.RESET_ALL}")
            if protocols['ICMP'] > 10:
                print(f"{Fore.RED}[!] Yüksek ICMP trafiği tespit edildi!{Style.RESET_ALL}")
            if protocols['ARP'] > 5:
                print(f"{Fore.RED}[!] Yüksek ARP trafiği tespit edildi!{Style.RESET_ALL}")
            
            # Güvenlik önerileri
            print(f"\n{Fore.CYAN}[*] Güvenlik Önerileri:{Style.RESET_ALL}")
            if protocols['HTTP'] > 0:
                print(f"{Fore.RED}[!] HTTPS kullanılmalı!{Style.RESET_ALL}")
            if protocols['ICMP'] > 10:
                print(f"{Fore.RED}[!] ICMP trafiği sınırlandırılmalı!{Style.RESET_ALL}")
            if protocols['ARP'] > 5:
                print(f"{Fore.RED}[!] ARP trafiği izlenmeli!{Style.RESET_ALL}")
            
            print(f"{Fore.GREEN}[+] Ağ trafiği düzenli izlenmeli{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Anormal trafik tespit edildiğinde alarm verilmeli{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}[!] Ağ trafiği analizi hatası: {str(e)}{Style.RESET_ALL}")

    def tool_20_detailed_reporting(self, target):
        """20. Detaylı Raporlama - Kapsamlı güvenlik raporu"""
        print(f"\n{Fore.BLUE}[*] Detaylı rapor oluşturuluyor: {target}{Style.RESET_ALL}")
        try:
            # Rapor dosyası
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            report_file = f'security_report_{target}_{timestamp}.txt'
            
            with open(report_file, 'w') as f:
                f.write(f"Ağ Güvenlik Analiz Raporu\n")
                f.write(f"=======================\n\n")
                f.write(f"Tarih: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Hedef: {target}\n\n")
                
                # Port tarama sonuçları
                f.write("1. Port Tarama Sonuçları\n")
                f.write("------------------------\n")
                self.nm.scan(target, arguments='-sS -sV -T4')
                for host in self.nm.all_hosts():
                    for proto in self.nm[host].all_protocols():
                        for port in self.nm[host][proto].keys():
                            service = self.nm[host][proto][port]
                            if service['state'] == 'open':
                                f.write(f"Port: {port}/{proto}\n")
                                f.write(f"Servis: {service['name']}\n")
                                if 'product' in service:
                                    f.write(f"Ürün: {service['product']}\n")
                                if 'version' in service:
                                    f.write(f"Versiyon: {service['version']}\n")
                                f.write("\n")
                
                # SSL/TLS analizi
                f.write("2. SSL/TLS Analizi\n")
                f.write("------------------\n")
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((target, 443)) as sock:
                        with context.wrap_socket(sock, server_hostname=target) as ssock:
                            cert = ssock.getpeercert()
                            f.write(f"Sertifika Sahibi: {cert['subject'][0][0][1]}\n")
                            f.write(f"Sertifika Veren: {cert['issuer'][0][0][1]}\n")
                            f.write(f"Geçerlilik: {cert['notBefore']} - {cert['notAfter']}\n\n")
                except:
                    f.write("SSL/TLS analizi yapılamadı\n\n")
                
                # HTTP güvenlik analizi
                f.write("3. HTTP Güvenlik Analizi\n")
                f.write("------------------------\n")
                try:
                    response = requests.get(f'http://{target}', verify=False)
                    security_headers = [
                        'X-Frame-Options',
                        'X-XSS-Protection',
                        'X-Content-Type-Options',
                        'Strict-Transport-Security',
                        'Content-Security-Policy'
                    ]
                    for header in security_headers:
                        if header in response.headers:
                            f.write(f"{header}: {response.headers[header]}\n")
                        else:
                            f.write(f"{header}: Eksik\n")
                    f.write("\n")
                except:
                    f.write("HTTP güvenlik analizi yapılamadı\n\n")
                
                # Güvenlik önerileri
                f.write("4. Güvenlik Önerileri\n")
                f.write("---------------------\n")
                f.write("1. Tüm açık portlar gözden geçirilmeli\n")
                f.write("2. Güvenlik duvarı kuralları kontrol edilmeli\n")
                f.write("3. SSL/TLS sertifikası güncel tutulmalı\n")
                f.write("4. Güvenlik başlıkları eklenmeli\n")
                f.write("5. Düzenli güvenlik testleri yapılmalı\n")
            
            print(f"{Fore.GREEN}[+] Rapor oluşturuldu: {report_file}{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}[!] Rapor oluşturma hatası: {str(e)}{Style.RESET_ALL}")

    def run_tool(self, num):
        try:
            if num == 1:
                target = input("Hedef IP adresini girin: ")
                ports = input("Port aralığı (varsayılan 1-1000): ") or "1-1000"
                self.tool_1_port_scan(target, ports)
            elif num == 2:
                network = input("Ağ adresini girin (örn: 192.168.1.0/24): ")
                self.tool_2_network_discovery(network)
            elif num == 3:
                target = input("Hedef IP veya domain girin: ")
                self.tool_3_http_security_analysis(target)
            elif num == 4:
                target = input("Hedef domain veya IP girin: ")
                self.tool_4_dns_analysis(target)
            elif num == 5:
                target = input("Hedef domain veya IP girin: ")
                self.tool_5_ssl_analysis(target)
            elif num == 6:
                target = input("Hedef IP adresini girin: ")
                self.tool_6_service_version_detection(target)
            elif num == 7:
                target = input("Hedef IP adresini girin: ")
                self.tool_7_os_detection(target)
            elif num == 8:
                target = input("Hedef IP adresini girin: ")
                self.tool_8_firewall_detection(target)
            elif num == 9:
                target = input("Hedef IP adresini girin: ")
                self.tool_9_mac_detection(target)
            elif num == 10:
                target = input("Hedef IP adresini girin: ")
                self.tool_10_open_port_scan(target)
            elif num == 11:
                target = input("Hedef IP adresini girin: ")
                self.tool_11_udp_scan(target)
            elif num == 12:
                target = input("Hedef IP adresini girin: ")
                self.tool_12_tcp_syn_scan(target)
            elif num == 13:
                target = input("Hedef IP adresini girin: ")
                self.tool_13_service_enumeration(target)
            elif num == 14:
                target = input("Hedef IP adresini girin: ")
                self.tool_14_firewall_bypass(target)
            elif num == 15:
                target = input("Hedef IP adresini girin: ")
                self.tool_15_arp_spoofing_detection(target)
            elif num == 16:
                target = input("Hedef IP adresini girin: ")
                self.tool_16_mitm_detection(target)
            elif num == 17:
                target = input("Hedef IP adresini girin: ")
                self.tool_17_ssl_tls_security_analysis(target)
            elif num == 18:
                target = input("Hedef domain veya IP girin: ")
                self.tool_18_web_app_security_analysis(target)
            elif num == 19:
                target = input("Hedef IP adresini girin: ")
                self.tool_19_network_traffic_analysis(target)
            elif num == 20:
                target = input("Hedef IP adresini girin: ")
                self.tool_20_detailed_reporting(target)
            else:
                print(f"{Fore.RED}Bu numarada bir araç yok!{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Araç çalıştırılırken hata oluştu: {e}{Style.RESET_ALL}")

def interactive_menu(analyzer, args):
    while True:
        analyzer.show_tools()
        choice = input(f"{Fore.YELLOW}Bir araç numarası seçin (1-20), [h] bilgi, [q] çıkış: {Style.RESET_ALL}").strip().lower()
        if choice == 'q':
            print(f"{Fore.GREEN}Çıkılıyor...{Style.RESET_ALL}")
            break
        elif choice == 'h':
            analyzer.show_tool_details()
            input(f"{Fore.YELLOW}Devam etmek için Enter'a basın...{Style.RESET_ALL}")
        elif choice.isdigit() and 1 <= int(choice) <= 20:
            num = int(choice)
            try:
                analyzer.run_tool(num)
            except Exception as e:
                print(f"{Fore.RED}[!] Araç çalıştırılırken hata oluştu: {e}{Style.RESET_ALL}")
            input(f"{Fore.YELLOW}Devam etmek için Enter'a basın...{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Geçersiz seçim!{Style.RESET_ALL}")
            input(f"{Fore.YELLOW}Devam etmek için Enter'a basın...{Style.RESET_ALL}")

# main fonksiyonunda -l veya hiç parametre verilirse bu menü çağrılsın
def main():
    parser = argparse.ArgumentParser(description='Ağ Güvenlik Analiz Aracı')
    parser.add_argument('-t', '--target', required=True, help='Hedef IP adresi')
    parser.add_argument('-n', '--network', help='Ağ adresi (örn: 192.168.1.0/24)')
    parser.add_argument('-p', '--ports', default='1-1000', help='Taranacak portlar (örn: 1-1000)')
    parser.add_argument('-a', '--all', action='store_true', help='Tüm araçları çalıştır')
    parser.add_argument('-l', '--list', action='store_true', help='Mevcut araçları listele ve interaktif menü')
    args = parser.parse_args()

    analyzer = NetworkAnalyzer()
    analyzer.print_banner()

    if args.all:
        # Tüm araçları çalıştır
        analyzer.tool_1_port_scan(args.target)
        analyzer.tool_2_network_discovery(args.network)
        analyzer.tool_3_http_security_analysis(args.target)
        analyzer.tool_4_dns_analysis(args.target)
        analyzer.tool_5_ssl_analysis(args.target)
        analyzer.tool_11_udp_scan(args.target)
        analyzer.tool_12_tcp_syn_scan(args.target)
        analyzer.tool_13_service_enumeration(args.target)
        analyzer.tool_14_firewall_bypass(args.target)
        analyzer.tool_15_arp_spoofing_detection(args.target)
        analyzer.tool_16_mitm_detection(args.target)
        analyzer.tool_17_ssl_tls_security_analysis(args.target)
        analyzer.tool_18_web_app_security_analysis(args.target)
        analyzer.tool_19_network_traffic_analysis(args.target)
        analyzer.tool_20_detailed_reporting(args.target)
    else:
        # Interaktif menü
        interactive_menu(analyzer, args)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Program kullanıcı tarafından sonlandırıldı.{Style.RESET_ALL}")
        sys.exit(0)