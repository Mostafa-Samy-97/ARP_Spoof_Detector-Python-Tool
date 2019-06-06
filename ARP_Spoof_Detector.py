#!usr/bin/env python 

# ARP_Spoofer_Detector Python Tool Version 1.0
# Developed By Mostafa_Samy
# Github Link ==>> https://github.com/Mostafa-Samy-97

'''
Steps : 
* Analyze ARP Layer of Responses Packets :
  - Check if IP is Gateway IP 
  - check if source mac is actually the Gateway's mac
  - this method will detect attacks even if the attack was lanuched before the execution of the tool
'''

import scapy.all as scapy
from getmac import get_mac_address
import time


# Get Which Network Interface of User to use it in Scanning
network_interface = raw_input('\nEnter your Network Interface > ')


# Create Sniffing Function Allow us to sniff Packets and Analyze them
def sniff(interface) :
    print('\n[+] Scan ARP Spoof Attack ....')
    # Delay 2 Second before execute our Sniff Method
    time.sleep(2)
    # iface ==> Network Interface | store ==> Do not Save Packets in Memory (Low Load) | prn ==> Callback Function
    scapy.sniff(iface=interface, store=False, prn=sniffed_packet_callback)


# Prepare our Callback Function after Sniffing Packets
def sniffed_packet_callback(packet) :
    # Check if packet has ARP Layer first and check if this Packet is Response
    # op parameter refers to Packet type | (2) ==> Means its type is Response not Request 
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2 :
        try :
            # Get Real Mac Address of Gateway IP 
            # psrc ==> refers to Source IP in ARP Layer of our Sniffed Packet 
            real_mac = get_mac_address(packet[scapy.ARP].psrc)
            # Get Response Mac in our Packet
            # hwsrc ==> refers to Source Mac Address 
            response_mac = packet[scapy.ARP].hwsrc
    
            # Compare the real and response Mac Address and Check if there is ARP_Spoof Attack
            if real_mac != response_mac :
                print('\n[!] Warning your Machine is under ARP Spoof Attack !')
            else :
                print('\n[+] NO ARP SPOOF ATTACK FOUND ! [your Machine is Fine]')        

        except IndexError :
            pass            


# Run Sniff Method and Start Scanning
sniff(network_interface)            