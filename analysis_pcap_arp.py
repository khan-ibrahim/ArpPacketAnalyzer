import dpkt

def getARP(pcapFileName):

    f = open(pcapFileName, 'rb')
    pcap = dpkt.pcap.Reader(f)

    arpPackets = []

    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type == 0x0806:
            arpPackets.append([ts, eth.arp.__bytes__()])
    return arpPackets

def printArpPkt(bytes):
    return

def printPackets(arpPackets):
    i = 0
    for ts, pkt in arpPackets:
        print('Time Stamp:{}-----------------'.format(ts))
        print('Hardware type:{}'.format(pkt[0:2]))
        print('Protocol type:{}'.format(pkt[2:4]))
        print('Hardware size:{}'.format(pkt[4]))
        print('Protocol size:{}'.format(pkt[5]))
        print('Opcode:{}'.format(pkt[6:8]))
        print('Sender MAC address:{}'.format(pkt[8:14]))
        print('Sender IP address:{}'.format(pkt[14:18]))
        print('Target MAC address:{}'.format(pkt[18:24]))
        print('Target IP address:{}'.format(pkt[24:28]))
        print()

def main(pcapFileName):
    arpPackets = getARP(pcapFileName)
    printPackets(arpPackets)

if __name__ == '__main__':
    main()
