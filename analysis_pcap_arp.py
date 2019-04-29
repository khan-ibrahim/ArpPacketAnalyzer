import sys
import dpkt
import socket

#Tested for Python 3

def getARP(pcapFileName):
    #Returns [timestamp, ARP packet] list. ARP packet is in raw byte form.
    f = open(pcapFileName, 'rb')
    pcap = dpkt.pcap.Reader(f)

    arpPackets = []

    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type == 0x0806:
            arpPackets.append([ts, eth.arp.__bytes__()])
    return arpPackets

def formatMacBits(macBits):
    return '{}:{}:{}:{}:{}:{}'.format(macBits[0:2],macBits[2:4],macBits[4:6],macBits[6:8],macBits[8:10],macBits[10:12])

def printArpPkt(pkt):
    print('Hardware type:{}'.format(int.from_bytes(pkt[0:2], byteorder='big')))
    print('Protocol type:{}'.format(int.from_bytes(pkt[2:4], byteorder='big')))
    print('Hardware size:{}'.format(pkt[4]))
    print('Protocol size:{}'.format(pkt[5]))
    print('Opcode:{}'.format(int.from_bytes(pkt[6:8], byteorder='big')))
    print('Sender MAC address:{}'.format(formatMacBits(pkt[8:14].hex())))
    print('Sender IP address:{}'.format(socket.inet_ntoa(pkt[14:18])))
    print('Target MAC address:{}'.format(formatMacBits(pkt[18:24].hex())))
    print('Target IP address:{}'.format(socket.inet_ntoa(pkt[24:28])))
    return

def printPackets(arpPackets):
    for ts, pkt in arpPackets:
        print('Time Stamp:{}-----------------'.format(ts))
        printArpPkt(pkt)
        print()

def main(pcapFileName):
    arpPackets = getARP(pcapFileName)
    printPackets(arpPackets)

if __name__ == '__main__':
    print(sys.version)
    if len(sys.argv) == 2:
        main(sys.argv[1])
    else:
        print('usage: analysis_pcap_arp <pcapFileName>')
        exit()
