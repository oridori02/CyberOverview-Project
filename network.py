"""
Simulation of ARP requests and replies in a simple network.
"""


# Hosts in the network are represented as dictionaries
host1 = {"name": "host1", "ip": "192.168.1.1", "mac": "AA:AA:AA:AA:AA:01", "arp_table": {}}
host2 = {"name": "host2", "ip": "192.168.1.2", "mac": "AA:AA:AA:AA:AA:02", "arp_table": {}}
host3 = {"name": "host3", "ip": "192.168.1.3", "mac": "AA:AA:AA:AA:AA:03", "arp_table": {}}

network = [host1, host2, host3]

def send_arp_request(sender, target_ip, network):
    print(f"{sender['name']} sends ARP request for {target_ip}")
    # Broadcast to all hosts in the network
    for host in network:
        if host["ip"] == target_ip:
            send_arp_reply(host, sender)

def send_arp_reply(responder, requester):
    print(f"{responder['name']} replies to {requester['name']}")
    # requester saves the IP->MAC mapping in its ARP table
    requester["arp_table"][responder["ip"]] = responder["mac"]

# --- Simulation ---
# Host1 asks for Host2
send_arp_request(host1, "192.168.1.2", network)
# Host2 asks for Host3
send_arp_request(host2, "192.168.1.3", network)
# Host3 asks for Host1
send_arp_request(host3, "192.168.1.1", network)

# --- show ARP Tables ---
for host in network:
    print(f"{host['name']} ARP Table: {host['arp_table']}")

