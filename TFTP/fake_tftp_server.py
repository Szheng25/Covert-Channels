#!/usr/bin/python3
#
# fake_tftp_server.py
#
#initializations
from scapy.all import *
import os
import struct
import time

# Configuration
IFACE = "ens33"  # User's interface
FAKE_IP = "192.0.2.100"
FAKE_MAC = "aa:bb:cc:dd:ee:ff"
SERVER_PORT = 1069
TFTP_PORT = 69
SECRET_MESSAGE = "Keep it secret"

# Global state
client_ip = None
client_mac = None
client_port = None
offset = 0
current_block = 0
waiting_ack = False
block_sizes = []
fake_content = b''
n_blocks = 0
bits = None

print("=== TFTP Server Debug Start ===")
print(f"Configuration: iface={IFACE}, server={FAKE_IP}:{SERVER_PORT}")

def send_next():
    global offset, current_block, waiting_ack, n_blocks, block_sizes, fake_content, client_ip, client_mac, client_port, bits
    if current_block > n_blocks:
        print("All blocks sent, transfer complete.")
        current_block = 0
        offset = 0
        waiting_ack = False
        return
    size = block_sizes[current_block - 1]
    data = fake_content[offset:offset + size]
    blk_num = struct.pack('!H', current_block)
    payload = b'\x00\x03' + blk_num + data
    pkt = (Ether(src=FAKE_MAC, dst=client_mac) /
           IP(src=FAKE_IP, dst=client_ip) /
           UDP(sport=SERVER_PORT, dport=client_port) /
           Raw(load=payload))
    bit = int(bits[current_block - 1])
    print(f"Sending block {current_block} with size {size} (bit {bit}) to client MAC {client_mac}")
    try:
        sendp(pkt, iface=IFACE, verbose=0)
        print(f"Block {current_block} sent successfully")
    except Exception as e:
        print(f"Error sending block {current_block}: {e}")
    offset += size
    current_block += 1
    waiting_ack = True

def send_arp_reply(req_pkt):
    global FAKE_IP, FAKE_MAC
    try:
        arp_reply = (Ether(src=FAKE_MAC, dst=req_pkt[Ether].src) /
                     ARP(hwsrc=FAKE_MAC, hwdst=req_pkt[ARP].hwsrc,
                         psrc=FAKE_IP, pdst=req_pkt[ARP].psrc, op=2))
        print(f"Sending ARP reply to {req_pkt[ARP].psrc} (MAC {req_pkt[Ether].src}) with our MAC {FAKE_MAC}")
        sendp(arp_reply, iface=IFACE, verbose=0)
    except Exception as e:
        print(f"Error sending ARP reply: {e}")

def pkt_callback(pkt):
    global client_ip, client_mac, client_port, offset, current_block, waiting_ack, block_sizes, fake_content, n_blocks, bits
    print(f"Packet captured in server: {pkt.summary()}")
    print(f"From {pkt[Ether].src}:{pkt[IP].src if IP in pkt else pkt[ARP].psrc if ARP in pkt else 'N/A'} to {pkt[Ether].dst}:{pkt[IP].dst if IP in pkt else pkt[ARP].pdst if ARP in pkt else 'N/A'}")
    # Handle ARP requests
    if ARP in pkt and pkt[ARP].op == 1 and pkt[ARP].pdst == FAKE_IP:
        print("ARP request for server IP detected!")
        send_arp_reply(pkt)
        time.sleep(1) # <--------- necessary
        return  # Don't process further as ARP
    # Handle IP/UDP TFTP
    if IP not in pkt or pkt[IP].dst != FAKE_IP:
        print("Skipped: IP dst mismatch or no IP")
        return

    print("IP dst matches")
    if UDP not in pkt:
        print("Skipped: No UDP")
        return
    print(f"UDP dport: {pkt[UDP].dport}")
    udp_payload = bytes(pkt[UDP].payload)
    print(f"UDP payload length: {len(udp_payload)}")
    print(f"UDP payload preview: {udp_payload[:20]}")
    if len(udp_payload) < 2:
        print("Skipped: Payload too short")
        return
    if pkt[UDP].dport == TFTP_PORT and udp_payload[:2] == b'\x00\x01':
        print("RRQ detected!")
        client_ip = pkt[IP].src
        client_port = pkt[UDP].sport
        client_mac = pkt[Ether].src
        print(f"Client: {client_ip}:{client_port} MAC {client_mac}")
        bits = ''.join(format(ord(c), '08b') for c in SECRET_MESSAGE)
        n_bits = len(bits)
        block_sizes = []
        for i in range(n_bits):
            bit = int(bits[i])
            size = 512 if bit == 0 else 511
            block_sizes.append(size)
        total_size = sum(block_sizes)
        fake_content = os.urandom(total_size)
        n_blocks = n_bits
        offset = 0
        current_block = 1
        waiting_ack = False
        send_next()
    elif pkt[UDP].dport == SERVER_PORT and udp_payload[:2] == b'\x00\x04':
        ack_block = struct.unpack('!H', udp_payload[2:4])[0]
        print(f"ACK received for block {ack_block}")
        if waiting_ack and ack_block == current_block - 1:
            waiting_ack = False
            send_next()

# Main
if __name__ == "__main__":
    print("Entering main block...")
    try:
        # Filter for ARP broadcasts and targeted traffic
        filter_str = f"(arp host {FAKE_IP} or ether dst {FAKE_MAC})"
        print(f"Filter string prepared: {filter_str}")
        print(f"Starting TFTP server emulation on {IFACE}...")
        print(f"Listening for ARP requests and RRQ to {FAKE_IP}:{TFTP_PORT}")
        print(f"Secret message bits will be encoded in DATA block lengths (even=0, odd=1)")
        sniff(iface=IFACE, filter=filter_str, prn=pkt_callback)
    except Exception as e:
        print(f"General error in server: {e}")
    finally:
        print("=== TFTP Server Debug End ===")
