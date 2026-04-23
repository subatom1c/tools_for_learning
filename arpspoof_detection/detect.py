from scapy.all import sniff

debug = True

# maps IP to MAC
ARP_TABLE = {}

def processPacket(packet):
    # possible attacker's ip & mac
    src_ip = packet['ARP'].psrc
    src_mac = packet['Ether'].src

    if (debug):
        print(f"src_ip = {src_ip}, src_mac = {src_mac}")

    # check if we have this IP mapped
    if src_ip in ARP_TABLE.keys():
        # racecondition: whoever sends the packet with the IP first won't get flagged as arpspoof
        # ex: if attacker gets another computers IP and sends it first, we map victim_ip -> attacker_mac

        # previous mac stored in the table (probably the original computer, not attacker)
        real_mac = ARP_TABLE[src_ip]

        # we see the mac changed, meaning that someone is trying to arpspoof
        if real_mac != src_mac:
            print("arpspoof detected")

    else:
        # we haven't seen this ip, lets add it to the table
        ARP_TABLE[src_ip] = src_mac

# lets sniff some packets, filtering for arp requests and run our program
sniff(count = 0, filter = "arp", store = 0, prn = processPacket)
        