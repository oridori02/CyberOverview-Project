# ARP Spoofing Lab Documentation

## Problem Statement

This project aims to illustrate an Address Resolution Protocol (ARP) spoofing attack inside a fully controlled Docker network environment. The ARP protocol lacks authentication, which allows a malicious host to fabricate ARP replies and contaminate a victim’s ARP cache. In our setup the attacker continously broadcasts that the server’s IP address corresponds to the attacker’s MAC address. Furthermore, this causes the victim to route traffic to the attacker rather than the legitimate server. The attack is executed using the scapy library at Layer 2 by constructing Ethernet and ARP reply frames and periodically resending them to sustain the poisoning effect. When IP forwarding is disabled, this results in a denial of service, but if it is enabled, it facilitates man-in-the-middle interception and possible session hijacking. The success of the attack is verified by monitoring the victim’s ARP entry change to reflect the attacker’s MAC address and by capturing the redirected traffic on the attacker using tcpdump.



## Lab Objectives

- Poison ARP cache: Show that the victim’s ARP entry for the entry changes to the attacker’s MAC address.
- Intercept/redirect traffic (MITM): With IP forwarding enabled on the attacker, generate traffic from the target to the server and capture it to prove interception.
- Run safely: Use an isolated Docker bridge.
- Develop a mitigation strategy.
- Implement and evaluate a proposed active detection framework.

## Security Implications

This lab demonstrates why:
- Public and private WiFi networks are vulnerable to MITM attacks
- ARP spoofing can bypass network segmentation
- Encryption (HTTPS/VPN) is crucial on untrusted networks
- Network monitoring for ARP anomalies is important

## References

- [Docker Networking](https://docs.docker.com/network/)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [iproute2 Utilities](https://wiki.linuxfoundation.org/networking/iproute2)
- [ARP Protocol RFC 826](https://tools.ietf.org/html/rfc826)
- [Detecting ARP Spoofing: An Active Technique] (https://www.researchgate.net/profile/Sukumar-Nandi-3/publication/221160823_Detecting_ARP_Spoofing_An_Active_Technique/links/0912f50bdc98054c75000000/Detecting-ARP-Spoofing-An-Active-Technique.pdf?origin=publication_detail&_tp=eyJjb250ZXh0Ijp7ImZpcnN0UGFnZSI6InB1YmxpY2F0aW9uIiwicGFnZSI6InB1YmxpY2F0aW9uRG93bmxvYWQiLCJwcmV2aW91c1BhZ2UiOiJwdWJsaWNhdGlvbiJ9fQ)

## Documentation of project

The lab consists of three Docker containers connected via a custom bridge network:

| Container | IP Address | MAC Address | Role |
| --- | --- | --- | --- |
| server | 10.10.10.10 | 02:42:0a:0a:0a:0a | Victim |
| target | 10.10.10.50 | 02:42:0a:0a:0a:32 | Target |
| attacker | 10.10.10.100 | 02:42:0a:0a:0a:64 | Attacker |

### Network Configuration

- Subnet: 10.10.10.0/24
- Network Name: arplab
- Driver: bridge
- No IPv6 support

### Containers:

- Attacker - 10.10.10.100 (Scapy, tcpdump, ip_forward=1)
- Target - 10.10.10.50 (offer/victim)
- Server - 10.10.10.10 (gateway, generates traffic)

### How it works

- Poisoning
    - Attacker sends an ARP-reply to the target that says “10.10.10.10 (spoof ip) is on the attackers MAC address.
    - Target updates its ARP-cache to the attackers MAC address.
- Man-in-the-middle
    - When IP-forwarding is activated on the attacker the traffic between the target and the server is sent via the attacker
    - This is proven with tcpdump on the attacker-
- Restore
    - When the script is canceled, the targets MAC address gets restored to the servers true MAC.

## Documentation on testing the project

### Setup

```bash
# Network creation
docker network create --subnet 10.10.10.0/24 arplab

# Creating the containers
docker run -d --name attacker --hostname attacker \
  --network arplab --ip 10.10.10.100 \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  --sysctl net.ipv4.ip_forward=1 \
  kalilinux/kali-rolling sleep infinity

docker run -d --name target --hostname target \
  --network arplab --ip 10.10.10.50 \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  kalilinux/kali-rolling sleep infinity

docker run -d --name server --hostname server \
  --network arplab --ip 10.10.10.10 \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  kalilinux/kali-rolling sleep infinity

# Installing required packages
docker exec -it attacker bash -lc 'apt-get update && apt-get install -y python3-scapy tcpdump iproute2 iputils-ping'
docker exec -it target   bash -lc 'apt-get update && apt-get install -y iputils-ping iproute2 tcpdump curl python3-scapy'
docker exec -it server   bash -lc 'apt-get update && apt-get install -y python3 iproute2'

# A simple HTTP-server on the server
docker exec -d server bash -lc 'cd /tmp && python3 -m http.server 8000'
```

The setup of the docker network should look like this:

```bash
hasim@Hasim:~/compsec$ docker network inspect arplab
[
    {
        "Name": "arplab",
        "Id": "3ac7750f494f81275894d43ecc06c1b7121332a74e9e110c47a85422069fda71",
        "Created": "2025-10-07T13:33:58.317529004+02:00",
        "Scope": "local",
        "Driver": "bridge",
        "EnableIPv6": false,
        "IPAM": {
            "Driver": "default",
            "Options": {},
            "Config": [
                {
                    "Subnet": "10.10.10.0/24"
                }
            ]
        },
        "Internal": false,
        "Attachable": false,
        "Ingress": false,
        "ConfigFrom": {
            "Network": ""
        },
        "ConfigOnly": false,
        "Containers": {
            "03a37c0bf5c2c6ffe576c3436c6e7b00cf35f196176b5b5636e44158bc697b0a": {
                "Name": "target",
                "EndpointID": "8779a17d36479c64ecc4a4f6ae2fa74e8d3a05ecbc58f32e771f87d53369b922",
                "MacAddress": "02:42:0a:0a:0a:32",
                "IPv4Address": "10.10.10.50/24",
                "IPv6Address": ""
            },
            "6aca217428ef61ea4ca41e0c6f465a1b401b37c136f8afcc13dab733f3e2d7fb": {
                "Name": "server",
                "EndpointID": "8871decfb279030b2f4d67881f3ed9b01c1f91344263846454880c09a547fbc2",
                "MacAddress": "02:42:0a:0a:0a:0a",
                "IPv4Address": "10.10.10.10/24",
                "IPv6Address": ""
            },
            "929ecd03ef57272923b83aa1cf22202a547e1d78744f3b875bd2f7f51b849c09": {
                "Name": "attacker",
                "EndpointID": "f040f5a067a19e1fe93eb143d1c1778571591473a11fff48bf7c3db975d004e6",
                "MacAddress": "02:42:0a:0a:0a:64",
                "IPv4Address": "10.10.10.100/24",
                "IPv6Address": ""
            }
        },
        "Options": {},
        "Labels": {}
    }
]
```

### Copy the script

cd to src here first.

```bash
docker cp spoof.py attacker:/root/spoof.py
```

### Before the poisoning

```bash
# On the target - create an ARP entry and display the initial MAC
docker exec -it target bash -lc 'ping -c1 10.10.10.10 || true; ip neigh show 10.10.10.10'
```

![image.png](images/image.png)

This figure shows that the server has read the targets MAC address and that ping works normally before the attack.

### Run the spoofer

```bash
docker exec -it attacker python3 /root/spoof.py 10.10.10.50 10.10.10.10 eth0
# Keep it running until done with testing
```

### Verify poisoning

```bash
docker exec -it target bash -lc 'ping -c1 10.10.10.10 || true; ip neigh show 10.10.10.10'
# The expected is that the lladdr == attackers MAC
```

![image.png](images/image%201.png)

This photo shows before and after the arp spoofing script is running, the MAC address of the server now has the same MAC address as the attacker. The ping is showing ICMP redirect. The targets arp cache is infected, and the target thinks that the attacker is the server.

### Prove MITM

```bash
# In a terminal, run tcpdump in the attackers network
docker exec -it attacker bash -lc "tcpdump -i eth0 -n host 10.10.10.50"
```

```bash
# In another terminal generate traffic from the target
docker exec -it target bash -lc "curl -s http://10.10.10.10:8000/ | head || ping -c3 10.10.10.10"
# Expected result is that packets in both directions is shown on the attacker (SYN/SYN-ACK/ACK)
```

![image.png](images/image%202.png)

![image.png](images/image%203.png)

![image.png](images/image%204.png)

The first picture is showing a tcpdump  which shows that the attackers MAC is announced for IP 10.10.10.10 which is the poisoning itself. In addition is shows that the target learns the wrong MAC, becuase it has the attackers MAC.

The second picture confirms a MITM attack, the tcpdump on attacker shows full TCP/HTTP flow between 10.10.10.50 ↔ 10.10.10.10

The last picture is extra proof on the attackers logs that a GET request is terminated at the attacker.


## For the active detection:

Ensure that the spoofer is still running!

### Copy the script

In another terminal

cd to Defense Lab here first.

```bash
docker cp active-detect(Nversion).py target:/root/active-detect.py
```


### Start the active detetction

```bash
docker exec -it target python3 /root/active-detect.py
# keep it running until done with testing
```

This script runs on the target machine and passivly detects if there is an ARP-spoofing attack going on. It sends a warning and updates the arp cache to the correct Mac address.

Here, the attacker's MAC is: d2:fe:e6:c8:12:17
The server's MAC is: f2:60:cc:cd:21:b3

![image.png](images/AttackerFirst.png)
![image.png](images/LegitimateFirst.png)

The two picture show how the introduced detection tool works. When there are inconsistencies in the IP-MAC mappings seen in the network and on the target machine, it actively queries the claimed IP using ARP requests and TCP SYNs (and examines the replies).
It compares responses against cached/expected MAC addresses; discrepancies indicate spoofing. The techniques enables us to identify the true MAC that is under attack (the server's MAC in this case which is then added to the tusted list).


### Restoration

Stop the spoofer with Ctrl+C
Stop the active detection with Ctrl+C

On the target machine:

```bash
docker exec -it target bash -lc 'ip neigh flush all; ping -c1 10.10.10.10 || true; ip neigh show 10.10.10.10'
# Expected is that the MAC address is now restored
```

### Cleanup

```bash
docker rm -f attacker target server
docker network rm arplab
```
