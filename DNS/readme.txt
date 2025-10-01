TO RUN:
- On server
    `sudo python3 DNS_server_fake.py`
- On server 2nd window
    `sudo tpdump –i ens33 ether host 11:22:33:44:55:66 and udp port 53`
- On client
    `sudo python3 DNS_client.py`
- tcpdump output should be:
    20:05:53.419730 IP 192.168.1.201.52543 >
    192.168.1.200.domain: 0+ A? foobar.blah. (29)
    20:05:53.430410 IP 192.168.80.200.domain >
    192.168.1.201.52543: 0*- 1/0/0 A 121.212.105.134 (56)

Modify DNS_client.py
⚫ qd=DNSQR(qname=DOMAIN, qtype="A")
    ⚫ qd=DNSQR(qname=DOMAIN, qtype=“TXT")
⚫ DOMAIN = "foobar.blah" # Domain to query
    ⚫ DOMAIN = “a.b.c.foobar.blah" # Domain to query
⚫ Automate sending a message by crafting sub-domain labels
    ⚫ send.help.foobar.blah
    ⚫ lost.in.mountains.foobar.blah

Modify DNS_server_fake.py
⚫ Collect sub-domains from requests into a message
⚫ Replace fake IP and TXT data with return message

Bonus Assignment
⚫ Modify the DNS client and server to:
    ⚫ Act as a C2 (command and control) channel
        ⚫ Either server sends commands to the client to run or vice-versa
    ⚫ Implement the following commands
        ⚫ Fetch a file (base64 if binary)
        ⚫ Send a file (base64 if binary)
        ⚫ Run a command and return results