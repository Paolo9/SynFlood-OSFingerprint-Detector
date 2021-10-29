from scapy.all import *
from collections import Counter
import logging

syn_threshold = 5
count=Counter()
icmp_types=[17, 13, 15]
syn_flag = False
osfp_flag = False

logging.basicConfig(
        filename='detector.log',
        format='%(asctime)s-%(levelname)s: %(message)s',
        datefmt='%A %x %X',
        level=logging.INFO
        )

print(get_if_list(), '\nChoose interface: ') # for windows use conf.IFACES
iface = input()

def flood(pkt):
    global syn_flag
    if TCP in pkt and pkt[TCP].flags == 'S' :
        fld=pkt.sprintf('{IP:%IP.src%}')
        count[fld] += 1
        if count.most_common(1)[0][1] > syn_threshold :
            print ('syn flood attack from', fld)
            syn_flag = True
            count[fld] = 0

def fingerprint(pkt):
    global osfp_flag
    if ICMP in pkt :
        if ( pkt[ICMP].type == 8 and pkt[ICMP].code > 0 ) or pkt[ICMP].type in icmp_types :
            fprn=pkt.sprintf('{IP:%IP.src%}')
            print ('possible OS fingerprint from', fprn)
            osfp_flag = True

def logger(pkt):
    global syn_flag, osfp_flag
    if syn_flag :
        logging.warning('SYN flood attack from IP: ' + str(pkt[IP].src) + ' on PORT: ' + str(pkt[TCP].dport))
        syn_flag = False
    elif osfp_flag :
        logging.warning('Possible OS fingerprint from IP: ' + str(pkt[IP].src))
        osfp_flag = False
    else :
        logging.info(str(pkt[IP].src) + ' Normal')

def main(pkt):
    fingerprint(pkt)
    flood(pkt)
    logger(pkt)

sniff(iface=iface, prn=main, count=0)