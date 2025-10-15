#!/usr/bin/python3
# fake_tftp_client.py
#
from scapy.all import *
import os
import struct

# Configuration
IFACE = "ens33"  # User's interface
SERVER_IP = "192.0.2.100"
SERVER_MAC = "aa:bb:cc:dd:ee:ff"
CLIENT_IP = "192.0.2.101"
CLIENT_MAC = "11:22:33:44:55:66"
SERVER_PORT = 1069
TFTP_PORT = 69
CLIENT_PORT = 1068  # Ephemeral port for this session
FILENAME = "fakefile.txt"  # Arbitrary filename for RRQ

# Global state
received_blocks = []
current_block = 0
block_sizes = []
done = False

print("=== TFTP Client Debug Start ===")
print(f"Configuration: iface={IFACE}, server={SERVER_IP}:{SERVER_PORT}, client={CLIENT_IP}:{CLIENT_PORT}")

def send_ack(block_num):
    global CLIENT_IP, CLIENT_MAC, SERVER_IP, SERVER_MAC, CLIENT_PORT, SERVER_PORT
    try:
        blk_num = struct.pack('!H', block_num)
        payload = b'\x00\x04' + blk_num
        pkt = (Ether(src=CLIENT_MAC, dst=SERVER_MAC) /
               IP(src=CLIENT_IP, dst=SERVER_IP) /
               UDP(sport=CLIENT_PORT, dport=SERVER_PORT) /
               Raw(load=payload))
        print(f"Sending ACK for block {block_num} to MAC {SERVER_MAC}")
        sendp(pkt, iface=IFACE, verbose=0)
    except Exception as e:
        print(f"Error sending ACK: {e}")

def resolve_server_mac():
    global SERVER_MAC
    try:
        print("Sending ARP request to resolve server MAC...")
        arp_request = (Ether(dst="ff:ff:ff:ff:ff:ff",src=CLIENT_MAC) /
                       ARP(pdst=SERVER_IP, hwsrc=CLIENT_MAC, psrc=CLIENT_IP))
        answered, unanswered = srp(arp_request, timeout=5, iface=IFACE, verbose=1)
        if answered:
            resolved_pkt = answered[0][1]
            resolved_mac = resolved_pkt[Ether].src
            print(f"Resolved server MAC: {resolved_mac}")
            SERVER_MAC = resolved_mac  # Update with resolved
            return True
        else:
            print("No ARP reply received, using hardcoded MAC")
            # Still send dummy broadcast
            dummy_broadcast = Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") / IP(src=CLIENT_IP, dst=SERVER_IP) / ICMP()
            sendp(dummy_broadcast, iface=IFACE, verbose=0)
            return False
    except Exception as e:
        print(f"Error in ARP resolution: {e}")
        return False

def send_rrq(resolved_mac):
    global CLIENT_IP, CLIENT_MAC, SERVER_IP, SERVER_MAC, CLIENT_PORT, TFTP_PORT, FILENAME
    try:
        print("Preparing RRQ packet...")
        mode = b'octet'
        payload = b'\x00\x01' + FILENAME.encode() + b'\x00' + mode + b'\x00'
        print(f"RRQ payload length: {len(payload)}, preview: {payload[:20]}")
        pkt = (Ether(src=CLIENT_MAC, dst=resolved_mac) /
               IP(src=CLIENT_IP, dst=SERVER_IP) /
               UDP(sport=CLIENT_PORT, dport=TFTP_PORT) /
               Raw(load=payload))
        print(f"Sending RRQ packet to MAC {resolved_mac}...")
        sendp(pkt, iface=IFACE, verbose=1)
        print("RRQ sent successfully")
    except Exception as e:
        print(f"Error sending RRQ: {e}")

def decode_message(block_sizes):
    bits = []
    for size in block_sizes:
        bit = 1 if size % 2 == 1 else 0
        bits.append(str(bit))
    bits_str = ''.join(bits)
    message = ''
    for i in range(0, len(bits_str), 8):
        byte_str = bits_str[i:i+8]
        if len(byte_str) == 8:
            message += chr(int(byte_str, 2))
    return message

def pkt_callback(pkt):
    global current_block, received_blocks, block_sizes, done
    print(f"--- Packet captured in client ---")
    print(pkt.summary())
    print(f"Full from {pkt[Ether].src}:{pkt[IP].src if IP in pkt else 'N/A'}:{pkt[UDP].sport if UDP in pkt else 'N/A'} to {pkt[Ether].dst}:{pkt[IP].dst if IP in pkt else 'N/A'}:{pkt[UDP].dport if UDP in pkt else 'N/A'}")
    if IP not in pkt or pkt[IP].src != SERVER_IP:
        print("Skipped: IP src mismatch or no IP")
        print("--- End packet ---")
        return
    print("IP src matches")
    if UDP not in pkt:
        print("Skipped: No UDP")
        print("--- End packet ---")
        return
    print(f"UDP sport: {pkt[UDP].sport}, dport: {pkt[UDP].dport}")
    udp_payload = bytes(pkt[UDP].payload)
    print(f"UDP payload length: {len(udp_payload)}")
    print(f"UDP payload preview: {udp_payload[:20]}")
    if len(udp_payload) < 2:
        print("Skipped: Payload too short")
        print("--- End packet ---")
        return
    load = udp_payload
    if load[:2] == b'\x00\x03':  # DATA
        block_num = struct.unpack('!H', load[2:4])[0]
        data = load[4:]
        size = len(data)
        print(f"Received DATA block {block_num} size {size}")
        if block_num == 1:
            current_block = 1
            received_blocks = []
            block_sizes = []
        if block_num == current_block:
            received_blocks.append(data)
            block_sizes.append(size)
            send_ack(block_num)
            current_block += 1
    print("--- End packet ---")

if __name__ == "__main__":
    print("Entering main block...")
    try:
        # Resolve server MAC via ARP before sending RRQ
        resolve_success = resolve_server_mac()
        resolved_mac = SERVER_MAC if resolve_success else "aa:bb:cc:dd:ee:ff"  # Fallback
        # No filter for broad capture/debugging
        filter_str = f"(ip dst host {CLIENT_IP})"
        print(f"Filter string: {filter_str} (disabled for debugging)")
        print(f"Starting TFTP client on {IFACE}...")
        print(f"Sending RRQ for {FILENAME} to {SERVER_IP}:{TFTP_PORT} using MAC {resolved_mac}")
        send_rrq(resolved_mac)
        print(f"Listening for DATA from {SERVER_IP}:{SERVER_PORT} to {CLIENT_IP}:{CLIENT_PORT} (broad sniff, 60s timeout)")
        pkts = sniff(iface=IFACE, filter=filter_str, prn=pkt_callback, timeout=60)
        print(f"Total packets captured: {len(pkts)}")
        if block_sizes:
            print("Timeout reached, decoding received blocks.")
            message = decode_message(block_sizes)
            print(f"Decoded secret message: {message}")
            fake_file = b''.join(received_blocks)
            with open("received_fakefile.bin", "wb") as f:
                f.write(fake_file)
            print("Fake file saved as received_fakefile.bin")
            print(f"Received {len(block_sizes)} blocks, expected ~104 for full message.")
        else:
            print("No blocks received within timeout.")
            print("Debug tip: Run 'tcpdump -i ens33 -n udp port 1069 or port 1068' on client during test to confirm if DATA arrives at wire level.")
    except Exception as e:
        print(f"General error in client: {e}")
    finally:
        print("=== TFTP Client Debug End ===")
