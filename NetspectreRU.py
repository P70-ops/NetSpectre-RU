#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw
from datetime import datetime
from colorama import init, Fore, Style, Back
import os
import argparse
import re
import signal
import sys
from threading import Thread
import time
import scapy

# === Initialize Colorama ===
init(autoreset=True)

# === Global Variables ===
LOG_TO_FILE = True
LOG_FILE = "packet_log.txt"
PACKET_COUNT = 0
RUNNING = True
DNS_CACHE = {}

# === Banner ===
def show_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"""{Fore.RED}{Style.BRIGHT}
╔════════════════════════════════════════════════════════════════╗
║   █▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█   ║
║   █  {Fore.WHITE}🇷 КИБЕР-СЕТЕВОЙ СНИФФЕР • RUSSIAN PACKET EYE v2.0  {Fore.RED}█   ║
║   █▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█   ║
╠════════════════════════════════════════════════════════════════╣
║   ⚡ МОНИТОРИНГ ПАКЕТОВ АКТИВЕН | НАЖМИТЕ Ctrl+C ДЛЯ ВЫХОДА    ║
╚════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")

# === Signal Handler ===
def signal_handler(sig, frame):
    global RUNNING
    print(f"\n{Fore.RED}[!] Остановка перехвата пакетов...{Style.RESET_ALL}")
    RUNNING = False
    time.sleep(1)
    print(f"\n{Fore.YELLOW}[*] Всего перехвачено пакетов: {PACKET_COUNT}{Style.RESET_ALL}")
    sys.exit(0)

# === Argument Parser ===
def parse_args():
    parser = argparse.ArgumentParser(description='Russian Packet Eye - Advanced Network Sniffer')
    parser.add_argument('-i', '--interface', help='Network interface to sniff on', default=None)
    parser.add_argument('-f', '--filter', help='BPF filter for packets', default="ip")
    parser.add_argument('-o', '--output', help='Output log file', default="packet_log.txt")
    parser.add_argument('-v', '--verbose', help='Verbose output', action='store_true')
    return parser.parse_args()

# === DNS Resolver ===
def resolve_dns(packet):
    if DNS in packet and packet[DNS].qr == 0:  # DNS query
        query = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
        DNS_CACHE[packet[IP].src] = query
        return query
    elif IP in packet and packet[IP].src in DNS_CACHE:
        return DNS_CACHE[packet[IP].src]
    return None

# === HTTP Data Extractor ===
def extract_http_data(packet):
    if TCP in packet and (packet[TCP].dport == 80 or packet[TCP].sport == 80) and Raw in packet:
        try:
            raw = packet[Raw].load.decode('utf-8', errors='ignore')
            if any(method in raw for method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD']):
                lines = raw.split('\r\n')
                method = lines[0].split(' ')[0] if lines else ''
                host = next((line.split(': ')[1] for line in lines if 'Host:' in line), '')
                return f"HTTP {method} {host}"
        except:
            pass
    return None

# === Packet Formatter ===
def format_packet(pkt_time, src, sport, dst, dport, proto, size, dns_info=None, http_info=None):
    color_map = {
        'TCP': Fore.BLUE,
        'UDP': Fore.YELLOW,
        'ICMP': Fore.MAGENTA,
        'DNS': Fore.CYAN,
        'HTTP': Fore.GREEN,
        'OTHER': Fore.WHITE
    }
    
    proto_color = color_map.get(proto, Fore.WHITE)
    
    base = f"{Fore.CYAN}[{pkt_time}] {Fore.WHITE}{src:<15}:{sport:<5} → {dst:<15}:{dport:<5} {proto_color}{proto:<6} {Fore.WHITE}{size:<4} bytes"
    
    if dns_info:
        base += f" {Fore.CYAN}DNS: {dns_info}"
    if http_info:
        base += f" {Fore.GREEN}{http_info}"
    
    return base

# === Packet Processor ===
def process_packet(packet):
    global PACKET_COUNT
    
    if not RUNNING:
        return
    
    pkt_time = datetime.now().strftime('%H:%M:%S.%f')[:-3]
    size = len(packet)
    PACKET_COUNT += 1
    
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        sport, dport = "-", "-"
        proto = "OTHER"
        dns_info = None
        http_info = None
        
        # Protocol detection
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            proto = "TCP"
            
            # HTTP detection
            http_info = extract_http_data(packet)
            if http_info:
                proto = "HTTP"
            
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            proto = "UDP"
            
            # DNS detection
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                dns_info = resolve_dns(packet)
                if dns_info:
                    proto = "DNS"
                    
        elif ICMP in packet:
            proto = "ICMP"
        
        # Format and display packet
        line = format_packet(pkt_time, src, sport, dst, dport, proto, size, dns_info, http_info)
        print(line)
        
        # Log to file if enabled
        if LOG_TO_FILE:
            with open(LOG_FILE, 'a') as f:
                log_line = f"{pkt_time}\t{src}\t{sport}\t{dst}\t{dport}\t{proto}\t{size}\t{dns_info or '-'}\t{http_info or '-'}\n"
                f.write(log_line)

# === Statistics Thread ===
def stats_thread():
    global PACKET_COUNT
    while RUNNING:
        time.sleep(5)
        print(f"\n{Fore.YELLOW}[*] Статистика: {PACKET_COUNT} пакетов перехвачено | {datetime.now().strftime('%H:%M:%S')}{Style.RESET_ALL}")

# === Main Function ===
def main():
    global LOG_TO_FILE, LOG_FILE, RUNNING
    
    args = parse_args()
    LOG_FILE = args.output
    
    show_banner()
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start statistics thread
    Thread(target=stats_thread, daemon=True).start()
    
    # Initialize log file
    if LOG_TO_FILE:
        with open(LOG_FILE, 'w') as f:
            f.write("TIMESTAMP\tSRC_IP\tSRC_PORT\tDEST_IP\tDEST_PORT\tPROTO\tSIZE\tDNS_INFO\tHTTP_INFO\n")
    
    print(f"{Fore.GREEN}[*] Начало перехвата пакетов на интерфейсе: {args.interface or 'по умолчанию'}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] Используется фильтр: {args.filter}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] Логирование в файл: {LOG_FILE if LOG_TO_FILE else 'отключено'}{Style.RESET_ALL}\n")
    
    # Start sniffing
    sniff(
        iface=args.interface,
        filter=args.filter,
        prn=process_packet,
        store=False
    )

if __name__ == "__main__":
    main()

#sudo python3 NetspectreRU.py
#sudo python3 NetspectreRU.py -i wlp3s0 -f "tcp port 443"
