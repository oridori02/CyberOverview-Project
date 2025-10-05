#!/usr/bin/env python3
"""
ARP Spoofing Detector
- Passive detection + active verification (TCP SYN)
- Real network edition
"""

from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
import threading
import datetime
import time
import random
import os

# Configuration parameters
ARP_REQ_TTL = 10          # Time window to consider a reply 'on time' after our request (seconds)
IP_MAC_TTL = 900          # Learned IP→MAC TTL (seconds)
TCP_TIMEOUT = 3           # Timeout for TCP SYN probe (seconds)
CLEANUP_INTERVAL = 120    # How often to run the cleanup (seconds)

LOCK = threading.Lock()   # lock to protect shared structures


# Shared tables
IP_MAC_PAIRS = {}         # ip -> (mac, timestamp)
ARP_REQ_TABLE = {}        # ip -> timestamp of our ARP request
ARP_RESP_SEEN = {}        # ip -> set(mac)  (detect multiple responders)


# Helper functions
def log(msg):
    """Print a message with time stamp."""
    print(f"[{datetime.datetime.now().isoformat()}] {msg}")


def is_full_cycle(ip_addr):
    """
    Check whether we have a recent ARP request for ip_addr.
    - If a request exists and its age <= ARP_REQ_TTL -> return True.
    - If a request exists but expired -> remove it and return False.
    - If no request exists -> return False.
    """
    now = datetime.datetime.now()
    with LOCK:
        req_ts = ARP_REQ_TABLE.get(ip_addr)
        if not req_ts:
            return False
        age = (now - req_ts).total_seconds()
        if age <= ARP_REQ_TTL:
            return True
        del ARP_REQ_TABLE[ip_addr]
        log(f"[DEBUG] Expired ARP request for {ip_addr} removed (age {age:.1f}s)")
        return False


def cleanup_loop():
    """
    Periodically remove expired entries from ARP_REQ_TABLE and IP_MAC_PAIRS.
    Runs as a daemon thread every CLEANUP_INTERVAL seconds (e.g. 120s).
    """
    while True:
        now = datetime.datetime.now()
        with LOCK:
            # remove old ARP requests (older than ARP_REQ_TTL)
            stale_reqs = [ip for ip, t in ARP_REQ_TABLE.items() if (now - t).total_seconds() > ARP_REQ_TTL]
            for ip in stale_reqs:
                del ARP_REQ_TABLE[ip]
                log(f"[CLEANUP] Removed stale ARP request entry for {ip}")

            # remove expired IP-MAC pairs (older than IP_MAC_TTL)
            stale_pairs = [ip for ip, (mac, t) in IP_MAC_PAIRS.items() if (now - t).total_seconds() > IP_MAC_TTL]
            for ip in stale_pairs:
                del IP_MAC_PAIRS[ip]
                log(f"[CLEANUP] Removed expired trusted pair for {ip}")

        time.sleep(CLEANUP_INTERVAL)


# Detection
def add_arp_request(pkt):
    """Record ARP requests our host sends."""
    if ARP in pkt:
        with LOCK:
            ARP_REQ_TABLE[pkt[ARP].pdst] = datetime.datetime.now()


def handle_arp_reply(pkt):
    """Process an incoming ARP reply packet."""
    if not (ARP in pkt and Ether in pkt):
        log("[INFO] Malformed ARP packet received")
        return

    ip_src = pkt[ARP].psrc
    mac_src = pkt[ARP].hwsrc

    # record MACs seen replying for this IP
    with LOCK:
        if ip_src not in ARP_RESP_SEEN:
            ARP_RESP_SEEN[ip_src] = set()
        ARP_RESP_SEEN[ip_src].add(mac_src)

        if len(ARP_RESP_SEEN[ip_src]) > 1:
            log(f"[ALERT] Multiple ARP responders for {ip_src}: {ARP_RESP_SEEN[ip_src]}")
            return

    # if we already trusted this IP and MAC, update timestamp or raise alarm on change
    if ip_src in IP_MAC_PAIRS:
        known_mac, _ = IP_MAC_PAIRS[ip_src]
        if known_mac != mac_src:
            log(f"[WARNING] IP-MAC change detected for {ip_src}: {known_mac} -> {mac_src}")
            # Run verification for further evidence
            spoof_detection(pkt)
            return
        # Known and matching -> refresh timestamp
        with LOCK:
            IP_MAC_PAIRS[ip_src] = (known_mac, datetime.datetime.now())
        return

    # New IP observed -> run spoof detection
    spoof_detection(pkt)


def spoof_detection(pkt):
    """Active verification: TCP SYN + compare response MAC to ARP hwsrc."""
    if not (Ether in pkt and ARP in pkt):
        return

    ip_ = pkt[ARP].psrc
    mac_ = pkt[ARP].hwsrc

    # Check if this is a full-cycle (recent ARP request)
    has_recent = is_full_cycle(ip_)

    if not has_recent:
        # Half-cycle: send our own ARP request to corroborate
        try:
            send(ARP(op=1, pdst=ip_), verbose=False)
            log(f"[INFO] Sent ARP request to {ip_} to corroborate (half-cycle)")
        except Exception as e:
            log(f"[INFO] Error sending corroborating ARP request: {e}")
        return

    # Full-cycle: perform TCP SYN verification
    tcp_verified = False
    proxy_detected = False
    flags = None

    # Try common ports
    for dport in [80, 443, 22]:
        sport = random.randint(1025, 65535)
        ether = Ether(dst=mac_)
        ip_hdr = IP(dst=ip_)
        syn = TCP(sport=sport, dport=dport, flags="S", seq=random.randint(0, 0xFFFFFFFF))

        try:
            resp = srp1(ether / ip_hdr / syn, timeout=TCP_TIMEOUT, verbose=False)
        except Exception as e:
            log(f"[INFO] TCP probe error to {ip_}:{dport}: {e}")
            resp = None

        if not resp:
            continue

        # If we got a TCP response, check flags and response MAC
        if resp.haslayer(TCP):
            flags = resp.sprintf("%TCP.flags%")

            # check ethernet src of the response (proxy detection)
            resp_mac = resp[Ether].src if Ether in resp else None
            if resp_mac and resp_mac.lower() != mac_.lower():
                proxy_detected = True
            
            # Port responsive if SYN/ACK or RST
            if "SA" in flags or "R" in flags:
                tcp_verified = True
                break

    # Decision
    if tcp_verified:
        if proxy_detected:
            log(f"[ALERT] TCP verified but proxy suspected for {ip_}")
        else:
            with LOCK:
                IP_MAC_PAIRS[ip_] = (mac_, datetime.datetime.now())
            log(f"[OK] Verified and added to trusted list: {ip_} -> {mac_} (flags={flags})")
            
            # clear ARP_RESP_SEEN history for this IP
            with LOCK:
                ARP_RESP_SEEN.pop(ip_, None)
                
    else:
        if proxy_detected:
            log(f"[ALERT] Proxy/manipulation suspected for {ip_} (no TCP verify but resp_mac mismatch)")
        else:
            log(f"[ALERT] No TCP response on probes for {ip_} — possible fake IP-MAC pair")



# Sniffing threads
def outgoing_arp_request(pkt):
    """Return True if pkt is an ARP request we sent."""
    return ARP in pkt and pkt[ARP].op == 1 and pkt[ARP].psrc == get_if_addr(conf.iface)

def incoming_arp_reply(pkt):
    """Return True if pkt is an ARP reply from another host."""
    return ARP in pkt and pkt[ARP].op == 2 and pkt[ARP].psrc != get_if_addr(conf.iface)

def sniff_requests_thread():
    """Sniff outgoing ARP requests to record them."""
    try:
        sniff(filter='arp', lfilter=outgoing_arp_request, prn=add_arp_request, iface=conf.iface, store=0)
    except Exception as e:
        log(f"Request sniffer error: {e}")


def sniff_replies_thread():
    """Sniff incoming ARP replies and handle them."""
    try:
        sniff(filter='arp', lfilter=incoming_arp_reply, prn=handle_arp_reply, iface=conf.iface, store=0)
    except Exception as e:
        log(f"Reply sniffer error: {e}")


# Main
if __name__ == "__main__":
    if os.geteuid() != 0:
        log("Warning: not running as root. Sniff/send may fail unless python has CAP_NET_RAW capability.")

    log(f"Starting ARP detector on interface {conf.iface}")

    # Start cleanup thread
    cleaner = threading.Thread(target=cleanup_loop, daemon=True)
    cleaner.start()

    t_req = threading.Thread(target=sniff_requests_thread, daemon=True)
    t_rep = threading.Thread(target=sniff_replies_thread, daemon=True)
    t_req.start()
    t_rep.start()

    log("ARP detection started. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("Shutting down.")
