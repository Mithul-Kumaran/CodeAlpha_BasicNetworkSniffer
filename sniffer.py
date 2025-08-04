from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime
import logging
import sys

# Optional: Colored output for terminals
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False

# Logging setup
logging.basicConfig(
    filename='packet_log.txt',
    filemode='a',
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
)

# Pretty print with color fallback
def cprint(text, color=None):
    if COLOR_ENABLED and color:
        print(color + text + Style.RESET_ALL)
    else:
        print(text)

# Human-readable protocol names
PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

def process_packet(packet):
    try:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        info = [f"[{timestamp}] Packet captured:"]

        if IP in packet:
            ip_layer = packet[IP]
            src = ip_layer.src
            dst = ip_layer.dst
            proto = PROTOCOLS.get(ip_layer.proto, str(ip_layer.proto))
            info.append(f"  From {src} --> {dst}")
            info.append(f"  Protocol: {proto}")

            # TCP Layer
            if TCP in packet:
                tcp = packet[TCP]
                info.append(f"  TCP Ports: {tcp.sport} -> {tcp.dport}")

            # UDP Layer
            elif UDP in packet:
                udp = packet[UDP]
                info.append(f"  UDP Ports: {udp.sport} -> {udp.dport}")

            # ICMP Layer
            elif ICMP in packet:
                icmp = packet[ICMP]
                info.append(f"  ICMP Type: {icmp.type}, Code: {icmp.code}")

            # Raw Payload
            if Raw in packet:
                raw_data = packet[Raw].load
                try:
                    payload = raw_data.decode(errors='ignore')
                    info.append(f"  Payload: {payload[:100]}")  # Truncate long payloads
                except:
                    info.append("  Payload: <binary data>")

            output = "\n".join(info)
            cprint(output, Fore.CYAN)
            logging.info(output)

    except Exception as e:
        logging.error(f"Error processing packet: {e}")
        cprint(f"[ERROR] {e}", Fore.RED)

def main():
    print("="*60)
    cprint("Starting Enhanced Packet Sniffer...", Fore.GREEN)
    print("="*60)
    try:
        # You can modify filter to 'tcp', 'udp', or 'icmp' as needed
        sniff(filter="ip", prn=process_packet, store=0)
    except KeyboardInterrupt:
        cprint("\nSniffer stopped by user.", Fore.YELLOW)
        sys.exit()
    except Exception as e:
        cprint(f"[FATAL] {e}", Fore.RED)
        sys.exit(1)

if __name__ == "__main__":
    main()
