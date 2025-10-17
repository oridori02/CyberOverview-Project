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

# Configuration
ARP_REQ_TTL = 10          # Time window to consider a reply 'on time' after our request (seconds)
IP_MAC_TTL = 900          # Learned IP→MAC TTL (seconds)
TCP_TIMEOUT = 3           # Timeout for TCP SYN probe (seconds)
CLEANUP_INTERVAL = 120    # How often to run the cleanup (seconds)
EVAL_DELAY = 1.0       # seconds to wait after sending the outgoing request before evaluating
DEBOUNCE_SEC = 0.8     # avoid scheduling multiple outgoing requests immediately

LOCK = threading.Lock()   # lock to protect shared structures

# Shared tables
IP_MAC_PAIRS = {}         # ip -> (mac, timestamp)
ARP_REQ_TABLE = {}        # ip -> timestamp of our ARP request
ARP_RESP_SEEN = {}        # ip -> set(mac)  (detect multiple responders)

#Logging
def log(msg):
    """Print a message with time stamp."""
    print(f"[{datetime.datetime.now().isoformat()}] {msg}")


# Cleanup expired entries
def cleanup_tables():
    """Periodically remove expired entries from ARP_REQ_TABLE and IP_MAC_PAIRS."""
    while True:
        now = datetime.datetime.now()
        with LOCK:
            # remove old ARP requests
            stale_reqs = [ip for ip, t in ARP_REQ_TABLE.items() if (now - t).total_seconds() > ARP_REQ_TTL]
            for ip in stale_reqs:
                del ARP_REQ_TABLE[ip]
                log(f"[CLEANUP] Removed stale ARP request entry for {ip}")

            # remove expired IP-MAC pairs
            stale_pairs = [ip for ip, (mac, t) in IP_MAC_PAIRS.items() if (now - t).total_seconds() > IP_MAC_TTL]
            for ip in stale_pairs:
                del IP_MAC_PAIRS[ip]
                log(f"[CLEANUP] Removed expired trusted pair for {ip}")

        time.sleep(CLEANUP_INTERVAL)


# Detection
def add_arp_request(pkt):
    if ARP in pkt:
        ip = pkt[ARP].pdst
        now = datetime.datetime.now()
        with LOCK:
            last = ARP_REQ_TABLE.get(ip)
            if last and (now - last).total_seconds() < 1:
                # Duplicate ARP request within 1s — ignore it
                return
            ARP_REQ_TABLE[ip] = now
        t = threading.Timer(ARP_REQ_TTL, evaluate_responders, args=(ip, now))
        t.daemon = True
        t.start()
        log(f"[DEBUG] ARP request for {ip} recorded, evaluator scheduled in {ARP_REQ_TTL}s")

def handle_arp_reply(pkt):
    """Process an incoming ARP reply packet. If no recent outgoing request exists,
    generate a proper outgoing ARP request (host-like) and schedule full-cycle evaluation."""
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

    log(f"[DEBUG] ARP reply seen: {ip_src} is at {mac_src} (eth.src={pkt[Ether].src})")

    # If we already trusted this IP and MAC, update timestamp or schedule verification on change
    with LOCK:
        current = IP_MAC_PAIRS.get(ip_src)

    if current:
        known_mac, _ = current
        if known_mac != mac_src:
            log(f"[WARNING] IP-MAC change detected for {ip_src}: {known_mac} -> {mac_src}")
            # send half-cycle corroboration (as before) and schedule full-cycle evaluation
            spoof_detection(pkt)
            schedule_fullcycle_evaluation(ip_src)
            return
        # refresh trusted timestamp
        with LOCK:
            IP_MAC_PAIRS[ip_src] = (known_mac, datetime.datetime.now())
        return

    # No trusted mapping exists -> trigger outgoing host-like ARP request if no recent request
    with LOCK:
        recent_req = ip_src in ARP_REQ_TABLE and (datetime.datetime.now() - ARP_REQ_TABLE[ip_src]).total_seconds() <= ARP_REQ_TTL

    if not recent_req:
        try:
            # Build a host-like ARP who-has with proper source IP/MAC (so it's an "outgoing" request)
            src_ip = get_if_addr(conf.iface)
            src_mac = get_if_hwaddr(conf.iface)
            out_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac) / ARP(op=1, hwsrc=src_mac, psrc=src_ip, pdst=ip_src)
            sendp(out_pkt, iface=conf.iface, verbose=False)
            log(f"[INFO] Sent outgoing ARP request for {ip_src} (host-like) to elicit replies")
        except Exception as e:
            log(f"[INFO] Error sending outgoing ARP request: {e}")

        # schedule full-cycle evaluation
        schedule_fullcycle_evaluation(ip_src)
    else:
        log(f"[DEBUG] Recent outgoing request exists for {ip_src}, waiting for its evaluator")

def spoof_detection(pkt):
    if not (Ether in pkt and ARP in pkt):
        return

    ip_ = pkt[ARP].psrc
    mac_ = pkt[ARP].hwsrc

    with LOCK:
        has_recent = ip_ in ARP_REQ_TABLE and (datetime.datetime.now() - ARP_REQ_TABLE[ip_]).total_seconds() <= ARP_REQ_TTL

    if not has_recent:
        try:
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=ip_), iface=conf.iface, verbose=False)
            log(f"[INFO] Sent ARP request to {ip_} to corroborate (half-cycle)")
        except Exception as e:
            log(f"[INFO] Error sending corroborating ARP request: {e}")

# ----------------------
# Evaluator after ARP_REQ_TTL
# ----------------------
def evaluate_responders(ip, ts):
    """
    Evaluate responders after ARP_REQ_TTL.
    Active verification: TCP SYN + compare response MAC to ARP hwsrc.
    """
    with LOCK:
        ARP_REQ_TABLE.pop(ip, None)
        responders = set(ARP_RESP_SEEN.get(ip, set()))
        ARP_RESP_SEEN.pop(ip, None)

    if not responders:
        log(f"[WARNING] No responders for {ip} in the request window")
        return

    log(f"[INFO] Evaluating responders for {ip}: {responders}")
    verified = set()
    proxy_flags = {}
    ports = [80, 443, 22]

    for mac in responders:
        tcp_ok = False
        proxy_flag = False
        flags_seen = None
        for dport in ports:
            sport = random.randint(1025, 65535)
            ether = Ether(dst=mac)
            ip_hdr = IP(dst=ip)
            syn = TCP(sport=sport, dport=dport, flags="S", seq=random.randint(0, 0xFFFFFFFF))
            try:
                resp = srp1(ether / ip_hdr / syn, timeout=TCP_TIMEOUT, iface=conf.iface, verbose=False)
            except Exception as e:
                log(f"[DEBUG] TCP probe error to {ip}:{dport} via {mac}: {e}")
                resp = None
            if not resp:
                continue
            if resp.haslayer(TCP):
                flags_seen = resp.sprintf("%TCP.flags%")
                resp_mac = resp[Ether].src if Ether in resp else None
                if resp_mac and resp_mac.lower() != mac.lower():
                    proxy_flag = True
                if "SA" in flags_seen or "R" in flags_seen:
                    tcp_ok = True
                    break
                
        proxy_flags[mac] = proxy_flag
        if tcp_ok and not proxy_flag:
            verified.add(mac)

    # Decision
    if len(verified) == 1:
        chosen_mac = next(iter(verified))
        with LOCK:
            IP_MAC_PAIRS[ip] = (chosen_mac, datetime.datetime.now())
        log(f"[OK] Verified and added to trusted list: {ip} -> {chosen_mac}")

    elif len(verified) == 0:
        for mac in responders:
            if proxy_flags.get(mac):
                log(f"[ALERT] Proxy/manipulation suspected for {ip} (MAC {mac}) — TCP verify failed")
            else:
                log(f"[ALERT] No TCP response on probes for {ip} (MAC {mac}) — possible fake IP-MAC pair")

    else:
        log(f"[ALERT] Multiple verified responders for {ip}: {verified}.")
        

# Sniffing
def outgoing_arp_request(pkt):
    return ARP in pkt and pkt[ARP].op == 1 and pkt[ARP].psrc == get_if_addr(conf.iface)

def incoming_arp_reply(pkt):
    return ARP in pkt and pkt[ARP].op == 2 and pkt[ARP].psrc != get_if_addr(conf.iface)

def sniff_requests_thread():
    try:
        sniff(filter='arp', lfilter=outgoing_arp_request, prn=add_arp_request, iface=conf.iface, store=0)
    except Exception as e:
        log(f"Request sniffer error: {e}")

def sniff_replies_thread():
    try:
        sniff(filter='arp', lfilter=incoming_arp_reply, prn=handle_arp_reply, iface=conf.iface, store=0)
    except Exception as e:
        log(f"Reply sniffer error: {e}")


def schedule_fullcycle_evaluation(ip, delay=EVAL_DELAY):
    """Record synthetic outgoing request timestamp and schedule evaluate_responders(ip, ts)."""
    now = datetime.datetime.now()
    with LOCK:
        last = ARP_REQ_TABLE.get(ip)
        if last and (now - last).total_seconds() < DEBOUNCE_SEC:
            return  # already scheduled recently
        ARP_REQ_TABLE[ip] = now
    t = threading.Timer(delay, evaluate_responders, args=(ip, now))
    t.daemon = True
    t.start()


# Main
if __name__ == "__main__":
    if os.geteuid() != 0:
        log("Warning: not running as root. Sniff/send may fail unless python has CAP_NET_RAW capability.")

    log(f"Starting ARP detector on interface {conf.iface}")

    # Start cleanup thread
    cleaner = threading.Thread(target=cleanup_tables, daemon=True)
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
