# DNS_client.py
from scapy.all import *

# Configuration (from your previous context)
VIRTUAL_IP = "192.168.1.201"  # Custom IP address
VIRTUAL_MAC = "11:22:33:44:55:66"  # Example MAC (use your generated MAC)
INTERFACE = "ens33"  # Network interface
DNS_SERVER = "192.168.1.200"  # DNS server to query (e.g., Google's DNS)
DNS_SERVER_MAC = "66:55:44:33:22:11"
DOMAIN = "foobar.blah"  # Domain to query

# Build DNS request packet
dns_request = (
    Ether(src=VIRTUAL_MAC, dst=DNS_SERVER_MAC)/
    IP(src=VIRTUAL_IP, dst=DNS_SERVER) /
    UDP(sport=RandShort(), dport=53) /  # Random source port, DNS port 53
    DNS(
        rd=1,  # Recursion desired
        qd=DNSQR(qname=DOMAIN, qtype="A")  # Query for A record
    )
)

# Send the DNS request
sendp(dns_request, iface=INTERFACE, verbose=False)
print(f"Sent DNS request for {DOMAIN} to {DNS_SERVER}")
