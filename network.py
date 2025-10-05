"""
Simulation of ARP requests and replies in a simple network.
"""


# Maximum number of ARP entries per host (how big is the ARP table) it will be a FIFO cache
MAX_ARP_ENTRIES = 10


# Hosts in the network are represented as dictionaries
host1 = {"name": "host1", "ip": "192.168.1.1", "mac": "AA:AA:AA:AA:AA:01", "arp_table": {}}
host2 = {"name": "host2", "ip": "192.168.1.2", "mac": "AA:AA:AA:AA:AA:02", "arp_table": {}}
host3 = {"name": "host3", "ip": "192.168.1.3", "mac": "AA:AA:AA:AA:AA:03", "arp_table": {}}
attacker = {"name": "attacker", "ip": "192.168.1.99", "mac": "BB:BB:BB:BB:BB:99", "arp_table": {}}

network = [host1, host2, host3, attacker]

def send_arp_request(sender, target_ip, network):
    print(f"{sender['name']} sends ARP request for {target_ip}")
    # Broadcast to all hosts in the network
    for host in network:
        if host["ip"] == target_ip:
            send_arp_reply(host, sender, target_ip)


def update_arp_table(host, ip, mac):
    # Check if already present
    if ip in host["arp_table"]:
        return  # do nothing if already present
    # Tabelle voll?
    if len(host["arp_table"]) >= MAX_ARP_ENTRIES:
        # Remove the first inserted item (FIFO)
        oldest_ip = list(host["arp_table"].keys())[0]
        del host["arp_table"][oldest_ip]
    # add new entry
    host["arp_table"][ip] = mac

def send_arp_reply(responder, requester, claimed_ip):
    print(f"{responder['name']} replies to {requester['name']} claiming {claimed_ip} is at {responder['mac']}")
    update_arp_table(requester, claimed_ip, responder["mac"])

def reset_arp_tables(network):
    for h in network:
        h["arp_table"].clear()
        
# --- show ARP Tables ---
def print_arp_tables(network):
    print("\nARP TABLES:")
    for host in network:
        print(f"{host['name']} ARP Table: {host['arp_table']}")
    print("\n")


# TODO: Implement ARP cache timeout (not done here for simplicity)
# TODO: Implement ARP spoofing detection (not done here for simplicity)
# TODO: Implement Gratuitous ARP (not done here for simplicity)
# TODO: Implement spoofed ARP replies (not done here for simplicity)
# TODO implement ARP spoofing attack simulation (not done here for simplicity)
# TODO implement ARP spoofing attack detection (not done here for simplicity)



# --- Simulation ---
print("\nPART A — Legitimate exchanges\n")

send_arp_request(host1, host2["ip"], network)  # host2 replies
send_arp_request(host2, host3["ip"], network)  # host3 replies
send_arp_request(host3, host1["ip"], network)  # host1 replies

print_arp_tables([host1, host2, host3])
reset_arp_tables(network)

print("\nPART B — Attack: attacker injects reply BEFORE victim request\n")

# attacker claims the IP host2['ip'], but uses its own MAC (responder['mac'])
send_arp_reply(attacker, host1, host2["ip"])

print_arp_tables([host1])

# Host1 sends ARP request for host2
send_arp_request(host1, host2["ip"], network)

# host2 will reply, but because update_arp_table does not overwrite, host1 keeps attacker's mapping
print_arp_tables([host1])
