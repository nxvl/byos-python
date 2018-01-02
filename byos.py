import socket
import struct

def main():
    packets = socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.ntohs(3)
    )

    while True:
        ethernet_data, address = packets.recvfrom(65536)
        dest_mac, src_mac, protocol, ip_data = ethernet_dissect(ethernet_data)

        if protocol == 8:
            ip_protocol, source_ip, target_ip, ipdata = ipv4_packet(ip_data)
            source, destination = udp_packet(ipdata)
            if dest_mac == "01:00:5E:00:00:FB":
                print("[+] mDNS IPv4 Packet Received")
                if ip_protocol == 17:
                    print((
                        "\t[-] Source IP: {} Source Port: {} "
                        "Destination IP: {} Destination Port: {}").format(
                            source_ip,source,target_ip,destination
                        ))
                    if destination == 5353:
                        print("mDNS Packet from {} to {}".format(
                            source_ip, target_ip
                        ))
            elif dest_mac == "33:33:00:00:00:FB":
                print("[+] mDNS IPv6 Packet Received")
            elif dest_mac == "01:00:5E:00:00:FC":
                print("[+] LLMNR IPv4 Packet Received")
                if ip_protocol ==17:
                    if destination == 5355:
                        print("\t[-] LLMNR Packet from {} to {}".format(
                            source_ip, target_ip
                        ))
            elif dest_mac == "33:33:00:00:00:01":
                print("[+] LLMNR IPv6 Packet received")

def ethernet_dissect(data):
    dest_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return (mac_format(dest_mac), mac_format(src_mac),
            socket.htons(protocol), data[14:])

def mac_format(mac):
    mac = map('{:02x}'.format, mac)
    return ':'.join(mac).upper()

def ipv4_packet(ip_data):
    ip_protocol, source_ip, target_ip = struct.unpack(
        '! 9x B 2x 4s 4s' , ip_data[:20]
    )
    return ip_protocol, ipv4(source_ip), ipv4(target_ip), ip_data[20:]

def ipv4(address):
    return '.'.join(map(str, address))

def udp_packet(ipdata):
    src_port, dst_port = struct.unpack('! H H', ipdata[:4])
    return src_port, dst_port

main()
