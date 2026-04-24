from scapy.all import sniff
import sys

known_macs = set()
filename = "known_macs"
clean_known_macs_file = len(sys.argv) > 1 and sys.argv[1] == "-clean"

def init():

    if clean_known_macs_file:
        open(filename, "w").close()
    with open(filename, "r") as file:
        for line in file:
            mac = line.strip().replace("MAC: ", "")
            known_macs.add(mac)
            

def serialize(mac):
    with open(filename, "a") as file:
        file.write(f"MAC: {mac}\n")

def analyze_packet(packet):
    
    mac_address = packet['Ether'].hwsrc

    if mac_address not in known_macs:
        print("new device detected")
        print(f"adding new device to known hosts: {mac_address}")
        known_macs.add(mac_address)
        serialize(mac_address)

init()
sniff(prn = analyze_packet, store = False)