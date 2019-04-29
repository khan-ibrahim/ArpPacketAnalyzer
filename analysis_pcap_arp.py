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

def main(pcapFileName):
    arpPackets = getARP(pcapFileName)
    
if __name__ == '__main__':
    main()
