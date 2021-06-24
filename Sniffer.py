# Please refer to the commented section below for a short Scapy recap!

# In Scapy, we will use the sniff() function to capture network packets.
# To see a list of what functions Scapy has available, open Scapy and run the lsc() function.
# Run the ls() function to see ALL the supported protocols.
# Run the ls(protocols) function to see the fields and default values for any protocols. E.g. ls(BOOTP)
# See packet layers and contents with the .show() method.
# Dig into a specific packet layer using a list index: pkts[3][2].summary()
# ...the first index chooses the packet out of the pkts list,
# the second index chooses the layer for that specific packet.
# Using the .command() method will return a string for the command necessary to recreate that sniffed packet.

# To see the list of optional arguments for the sniff() function:
# print(sniff.__doc__)
'''
Sniff packets and return a list of packets.

Arguments:

  count: number of packets to capture. 0 means infinity.

  store: whether to store sniffed packets or discard them

  prn: function to apply to each packet. If something is returned, it
      is displayed.

      Ex: prn = lambda x: x.summary()

  filter: BPF filter to apply.

  lfilter: Python function applied to each packet to determine if
      further action may be done.

      Ex: lfilter = lambda x: x.haslayer(Padding)

  offline: PCAP file (or list of PCAP files) to read packets from,
      instead of sniffing them

  timeout: stop sniffing after a given time (default: None).

  L2socket: use the provided L2socket (default: use conf.L2listen).

  opened_socket: provide an object (or a list of objects) ready to use
      .recv() on.

  stop_filter: Python function applied to each packet to determine if
      we have to stop the capture after this packet.

      Ex: stop_filter = lambda x: x.haslayer(TCP)

  iface: interface or list of interfaces (default: None for sniffing
      on all interfaces).

The iface, offline and opened_socket parameters can be either an
element, a list of elements, or a dict object mapping an element to a
label (see examples below).

Examples:

  >>> sniff(filter="arp")

  >>> sniff(lfilter=lambda pkt: ARP in pkt)

  >>> sniff(iface="eth0", prn=Packet.summary)

  >>> sniff(iface=["eth0", "mon0"],
  ...       prn=lambda pkt: "%s: %s" % (pkt.sniffed_on,
  ...                                   pkt.summary()))

  >>> sniff(iface={"eth0": "Ethernet", "mon0": "Wifi"},
  ...       prn=lambda pkt: "%s: %s" % (pkt.sniffed_on,
  ...                                   pkt.summary()))
'''

# Importing the necessary modules
try:
    from scapy.all import *
    from scapy.layers.inet import IP
except ImportError:
    print("Scapy package for Python is not installed on your system.")
    sys.exit()

import sys
from functions import suppress_loggers, set_promiscuous, get_iface, get_packetcount, get_snifftime, get_protocol, \
    get_snifferlog, protocols

suppress_loggers()
# Printing a message to the user; always use "sudo scapy" in Linux!
print("\n! Make sure to run this program as ROOT !\n")

# Asking the user for some parameters:
# interface on which to sniff,
# the number of packets to sniff,
# the time interval to sniff, the protocols

net_iface = get_iface()
set_promiscuous(net_iface)
packet_count = get_packetcount()
sniff_time = get_snifftime()
protocol = get_protocol()
file_name, sniffer_log = get_snifferlog()


# This is the function that will be called for each captured packet
# The function will extract parameters from the packet and then log each packet to the log file
def packet_logger_decorator(protocol, sniffer_log):
    def packet_logger(packet: scapy.layers.l2.Ether):
        # Getting the current timestamp
        now = datetime.now()

        # Writing the packet information to the log file, also considering the protocols or 0 for all protocols

        # print(type(packet))
        # print(getattr(packet, "haslayer", "no haslayer"))

        # methods = [method for method in dir(packet[0]) if not method.startswith("_")]
        # prot = [method for method in dir(packet) if "lay" in method]
        # print(methods)
        # print(prot)
        # print(packet.summary())
        # packet.show()
        # while True:
        #     packet.getlayer()

        # def ddir(obj):
        #     return [m for m in dir(obj) if not m.startswith("_")]
        #
        # def vvars(obj):
        #     return [m for m in vars(obj) if not m.startswith("_")]

        # for layer in packet.layers():
        #     # print(layer)
        #     # print(ddir(layer))
        #     # print(vvars(layer))
        #     print(layer.name())
        # def get_packet_layers(packet):
        #     counter = 0
        #     while True:
        #         layer = packet.getlayer(counter)
        #         if layer is None:
        #             break
        #
        #         yield layer
        #         counter += 1
        #
        # for layer in get_packet_layers(packet):
        #     print(layer.name)
        #
        # if packet.haslayer(IP):
        #     print(
        #         f"{datetime.now()} | "
        #         f"Protocol: {protocols[protocol].upper()} | "
        #         f"SMAC: {packet[0].src} | "
        #         f"DMAC: {packet[0].dst}",
        #         f"SIP : {packet[0][IP].src} | "
        #         f"DIP : {packet[0][IP].dst}",
        #         file=sniffer_log
        #     )
        # else:
        #     print(
        #         f"{datetime.now()} | "
        #         f"Protocol: {protocols[protocol].upper()} | "
        #         f"SMAC: {packet[0].src} | "
        #         f"DMAC: {packet[0].dst}",
        #         # f"SIP : {packet[0][IP].src} | "
        #         # f"DIP : {packet[0][IP].dst}",
        #         file=sniffer_log
        #     )
        print(f"{datetime.now()} | {packet.summary()}")
        # print(packet.payload.layers())
        # print(packet[packet.payload.layers()[0]])
        for count in range(len(packet.layers())):
            print(packet.getlayer(count).name)
    return packet_logger


# Printing an informational message to the screen
print("\n* Starting the capture...")

# Running the sniffing process (with or without a filter)
if protocol == "0":
    sniff(
        iface=net_iface,
        count=int(packet_count),
        timeout=int(sniff_time),
        prn=packet_logger_decorator(protocol, sniffer_log)
    )

elif (protocol == "arp") or (protocol == "bootp") or (protocol == "icmp"):
    sniff(
        iface=net_iface,
        filter=protocol,
        count=int(packet_count),
        timeout=int(sniff_time),
        prn=packet_logger_decorator(protocol, sniffer_log)
    )

else:
    print("\nCould not identify the protocols.\n")
    sys.exit()

# Printing the closing message
print("\n* Please check the %s file to see the captured packets.\n" % file_name)

# Closing the log file
sniffer_log.close()

# End of the program.
# Feel free to modify it, test it, add new protocols to sniff and improve de code whenever you feel the need to.
