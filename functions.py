import logging
import subprocess
import sys

from scapy.interfaces import get_if_list


def suppress_loggers():
    # This will suppress all messages that have a lower level of seriousness than error messages,
    # while running or loading Scapy
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
    logging.getLogger("scapy.loading").setLevel(logging.ERROR)


def set_promiscuous(net_iface):
    # Setting network interface in promiscuous mode
    '''
    Wikipedia: In computer networking, promiscuous mode or "promisc mode"[1] is a mode for a wired network interface
    controller (NIC) or wireless network interface controller (WNIC) that causes the controller to pass all traffic
    it receives to the central processing unit (CPU) rather than passing only the frames that the controller is
    intended to receive.
    This mode is normally used for packet sniffing that takes place on a router or on a computer connected to a hub.
    '''
    try:
        subprocess.call(["ifconfig", net_iface, "promisc"], stdout=None, stderr=None, shell=False)
    except Exception as e:
        print(":Failed to configure interface as promiscuous.", repr(e))
        exit()
    else:
        # Executed if the try clause does not raise an exception
        print(":Interface %s was set to PROMISC mode." % net_iface)


def get_iface():
    # Asking the user for input - the interface on which to run the sniffer
    iflist = ", ".join(get_if_list())
    net_iface = input(f"* Enter the interface on which to run the sniffer ({iflist}): ") or "eth0"
    if net_iface not in get_if_list():
        print(f":wrong iface: {net_iface}")
        exit()
    else:
        print(f":selected iface: {net_iface}")
        return net_iface


def get_packetcount():
    # Asking the user for the number of packets to sniff (the "count" parameter)
    packet_count = int(input("* Enter the number of packets to capture (0 is infinity): ") or 0)
    print(f":packet count: {packet_count}")
    # Considering the case when the user enters 0 (infinity)
    if int(packet_count) != 0:
        print(":The program will capture %d packets." % int(packet_count))

    elif int(packet_count) == 0:
        print(":The program will capture packets until the timeout expires.")
    return packet_count


def get_snifftime():
    # Asking the user for the time interval to sniff (the "timeout" parameter)
    sniff_time = int(input("* Enter the number of seconds to run the capture (default 30): ") or 30)

    # Handling the value entered by the user
    if int(sniff_time) != 0:
        print(":The program will capture packets for %d seconds." % int(sniff_time))
    return sniff_time


protocols = dict(arp="arp", bootp="bootp", icmp="icmp", all="all")
protocols["0"] = "all"


def get_protocol():
    # Asking the user for any protocols filter he might want to apply to the sniffing process
    # For this example I chose three protocols: ARP, BOOTP, ICMP
    # You can customize this to add your own desired protocols
    sniff_protocol = input("* Enter the protocols to filter by (arp|bootp|icmp|0 is all): ") or "0"
    if sniff_protocol not in protocols.keys():
        print(f":Wrong protocols {sniff_protocol}")
        exit()
    # Considering the case when the user enters 0 (meaning all protocols)
    print(f":Selected protocol: {sniff_protocol}")
    if (sniff_protocol == "arp") or (sniff_protocol == "bootp") or (sniff_protocol == "icmp"):
        print("The program will capture only %s packets." % sniff_protocol.upper())
    elif sniff_protocol == "0":
        print(":The program will capture all protocols.")
    return sniff_protocol


def get_snifferlog():
    # Asking the user to enter the name and path of the log file to be created
    file_name = input("* Please give a name to the log file (default /dev/stdout): ")
    # Creating the text file (if it doesn't exist) for packet logging and/or opening it for appending

    sniffer_log = open(file_name, "a") if file_name else sys.stdout
    return file_name if file_name else "/dev/stdout", sniffer_log
