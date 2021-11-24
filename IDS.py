import os
from scapy.all import *
from scapy.layers.http import HTTPRequest # import HTTP packet
import socket
import datetime
import json
import threading
import time
from termcolor import colored
import netifaces
import getopt
import signal
import logging



mac = netifaces.ifaddresses('enp0s3')[netifaces.AF_LINK][0]["addr"]
time_window = -1
blacklist_time = -1
ports_threshold = -1
syn_threshold = -1
count = 0
packets = {}
detections = {}

lock = threading.RLock()

#IP -> [packet1, packet2...]
#IP2 -> [packet1, packet2...]

def clear():
    os.system('clear')


def print_ports():
    global packets
    while True:
        time.sleep(5)   
        # clear()     
        for src in packets:
            print("Source = {}".format(src))
            ports = []
            for p,t in packets[src]:
                if p.haslayer("TCP"):
                    if p.getlayer("TCP").dport not in ports:
                        ports.append(p.getlayer("TCP").dport)
            print(ports)

def print_packets():
    global packets
    while True:
        time.sleep(5)
        clear()
        for src in packets:
            print("{}:".format(src))
            for p,t in packets[src]:
                print("\t{}".format((p,t)))

def sniff_packets(iface=None):
    if iface:
        sniff(prn=process_packet, iface=iface, store=False)
    else:
        sniff(prn=process_packet, store=False)


def process_packet(packet):
    src_mac = packet.getlayer("Ethernet").src
    if src_mac != mac:
        with lock:
            if src_mac not in packets and src_mac not in detections:
                packets[src_mac] = []
            packets[src_mac].append((packet, datetime.datetime.now()))
    if not packet.haslayer("Ethernet"):
        print(packet.show())


def remove_outdated(window):
    global packets
    while True:
        pkt = {}
        with lock:
            for src in packets:
                for p in packets[src]:
                    if p[1] > datetime.datetime.now() - datetime.timedelta(seconds = window):
                        if src not in pkt:
                            pkt[src] = []
                        pkt[src].append(p)
            packets = pkt

def port_scanning():
    global packets
    while True:
        with lock:
            pkt = packets.copy()
        for src in pkt:
            if src not in detections:
                ports = []
                for p,t in pkt[src]:
                    if p.haslayer("TCP"):
                        if p.getlayer("TCP").dport not in ports:
                            ports.append(p.getlayer("TCP").dport)
                if len(ports) > ports_threshold:
                    now = datetime.datetime.now()
                    print(colored("\n[!] Port Scanning Detected from MAC: {}, IP: {} at {}".format(src, p.getlayer("IP").src, now), "red"))
                    logging.critical("Port Scanning detected from {} - {} at {}".format(src, p.getlayer("IP").src, now))
                    os.system("sudo iptables -A INPUT -m mac --mac-source {} -j DROP".format(src))
                    print("\t - Blocking address {}".format(src))
                    detections[src] = (p.getlayer("IP").src, now) 

def syn_flood():
    global packets
    while True:
        with lock:
            pkt = packets.copy()
        for src in pkt:
            if src not in detections:
                count = 1
                for p,t in pkt[src]:
                    if p.haslayer("TCP") and p.getlayer("TCP").flags & 2:
                        count += 1
                if count > syn_threshold:
                    now = datetime.datetime.now()
                    print(colored("\n[!] SYN FLOOD Detected from {} - {} at {}".format(src, p.getlayer("IP").src, now), "red"))
                    logging.critical("SYN FLOOD Detected from {} - {} at {}".format(src, p.getlayer("IP").src, now))
                    print("\t - Blocking address {}".format(src))
                    os.system("sudo iptables -A INPUT -m mac --mac-source {} -j DROP".format(src))
                    detections[src] = (p.getlayer("IP").src, now) 


def clear_detections():
    global detections
    global blacklist_time
    while True:
        time.sleep(blacklist_time/2)
        det = {}
        with lock:
            for src in detections:
                if detections[src][1] > datetime.datetime.now() - datetime.timedelta(seconds = blacklist_time):
                    det[src] = detections[src]
                else:
                    print("Detections = {}".format(detections))
                    os.system("sudo iptables -D INPUT -m mac --mac-source {} -j DROP".format(src))
                    print(colored("[-] Removing {} from blacklisted addresses".format(src), "green"))
            detections = det
            

def usage():
    print("Usage: sudo python3 IDS.py")
    print("\t-h: show current usage help message. Alias --help.")
    print("\t-w: set the time window length in seconds in which the traffic flow is analysed. Alias --window.")
    print("\t-p: set the number of ports to be scanned in order to raise an alert. The MAC address of the scanning host will be blocked using iptables. Alias --port-threshold.")
    print("\t-s: set the number of SYN packets to receive before raising and alert and blocking the MAC address of the sender using iptables. Alias --syn-threshold.")
    print("\t-b: set the blacklist time after which a MAC address will be removed from the blocked ones and will be checked for attacks again. Alias --blacklist.")
    print("\n All the parameters are optional, if omitted default ones will be used.\n")
    sys.exit(0)

def handler(signum, frame):
    print("\n[+] Restoring iptables before quitting")
    os.system("sudo iptables-restore < iptables.bak")
    os.system("sudo rm -rf iptables.bak")
    print("[-] Cleanup done. Quitting...")
    os._exit(0)
 
 
def main():

    if os.geteuid() != 0:
        print("IDS needs root access to sniff traffic and update firewall rules. Please run as root!")
        sys.exit(1)
    
    global time_window
    global blacklist_time
    global ports_threshold
    global syn_threshold

    os.system("sudo rm -rf IDS.log")

    logging.basicConfig(filename="IDS.log", level=logging.DEBUG)

    signal.signal(signal.SIGINT, handler)

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hw:p:s:b:", ["help", "window", "port-threshold", "syn-threshold", "blacklist"])
    except getopt.GetoptError:
        usage()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-w", "--window"):
            print("[+] Setting time window to {} seconds".format(a))
            time_window = int(a)
        elif o in ("-p", "--port-threshold"):
            print("[+] Setting port-threshold to {}".format(a))
            ports_threshold = int(a)
        elif o in ("-s", "--syn-threshold"):
            print("[+] Setting syn-threshold to {}".format(a))
            syn_threshold = int(a)
        elif o in ("-b", "--blacklist"):
            print("[+] Setting blacklist time to {}".format(a))
            blacklist_time = int(a)
        else:
            assert False, "unhandled option {}".format(o)


    if time_window == -1:
        time_window = 10
        print("[*] Using default time window of {} seconds".format(time_window))
    if ports_threshold == -1:
        ports_threshold = 50
        print("[*] Using default port threshold of {} ports".format(ports_threshold))
    if syn_threshold == -1:
        syn_threshold = 100
        print("[*] Using default syn threshold of {} SYN packets".format(syn_threshold))
    if blacklist_time == -1:
        blacklist_time = 10
        print("[*] Using default blacklist time of {} seconds".format(blacklist_time))

    os.system("sudo iptables-save > iptables.bak")
    print("\n[*] iptables backup created in ./iptables.bak")


    iface = "enp0s3"
    cleaning_thread = threading.Thread(target=remove_outdated, args=(time_window,))
    cleaning_thread.start()

    print_thread = threading.Thread(target=print_ports)
    # print_thread.start()

    check_port_scanning = threading.Thread(target=port_scanning)
    check_port_scanning.start()

    check_syn_flood = threading.Thread(target=syn_flood)
    check_syn_flood.start()

    clear_detections_entry = threading.Thread(target=clear_detections)
    clear_detections_entry.start()

    sniff_packets(iface)


if __name__ == "__main__":
    main()

    