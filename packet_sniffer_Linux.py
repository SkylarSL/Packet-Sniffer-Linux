import socket
import struct
import time
import textwrap

TAB1 = "\t"
TAB2 = "\t\t"
TAB3 = "\t\t\t"
TAB4 = "\t\t\t\t"

# Return formatted MAC address
def get_mac_addr(bytes_addr):
    # Formats each chunk of the MAC addr to 2 hexadecimal places
    bytes_str = map('{:02x}'.format, bytes_addr)
    # Joins the sections with a ':' and makes it uppercase
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

# Unpacking ethernet frame
def ethernet_frame(data):
    # Actually unpacks the frame
    # Struct unpack allows us to unpack certain types
    # The '!' specifies it is network data
    # The '6s' specifies 6 bytes (characters)
    # The 'H' is a small unsigned int
    dest_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    # Return readable stuff and the rest of the data
    # The socket.htons takes the bytes and makes it readable (research this)
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(protocol), data[14:]

# Returns formatted IPv4 address
def get_ipv4_addr(bytes_addr):
    # Applies str to each part of bytes_addr and joins the str together with "."
    return ".".join(map(str, bytes_addr))

# Unpacks IPv4 packets
def ipv4_packets(data):
    # Get the length because the data comes after the header
    version_header_length = data[0]
    # Bit shift to the right to retreive the version ie. 11010101 >> 00001101
    version = version_header_length >> 4
    # Get the header length with some bit magic ie. 11010101 & 00001111 = 00000101, and x4 because 4 bytes per row
    # The length can only hold 4 bits so it only stores number of rows
    header_length = (version_header_length & 15) * 4
    # Unpacks data in header
    ttl, ip_proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return version, header_length, ttl, ip_proto, get_ipv4_addr(src), get_ipv4_addr(target), data[header_length:]

# Unpack ICMP packet
def icmp_packet_unpack(data):
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack TCP segment
def tcp_segment_unpack(data):
    src_port, dest_port, seq, ack, offset_reserved_flags = struct.unpack("! H H L L H", data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_ret = (offset_reserved_flags & 4) >> 2 
    flag_syn = (offset_reserved_flags & 2) >> 1 
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_ret, flag_syn, flag_fin, data[offset:]

# Unpack UDP segment
def udp_segment_unpack(data):
    src_port, dest_port, size = struct.unpack("! H H 2x H", data[:8])
    return src_port, dest_port, size, data[8:]

def main():
    # Gets the host, unecessary for linux
    HOST = socket.gethostbyname(socket.gethostname())
    # 'socket.ntohs(3)' converts it to a readable format
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    # Loop and listen to any data via the socket
    while True:
        time.sleep(1)
        # recieves all information through the socket
        raw_data, addr = connection.recvfrom(65535)
        dest_mac, src_mac, eth_protocol, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(TAB1 + 'Dest: {}, Src: {}, Protocol: {}'.format(dest_mac, src_mac, eth_protocol))

        # 8 for IPv4
        if eth_protocol == 8:
            version, header_length, ttl, ip_proto, src, dest, data = ipv4_packets(data)
            print(TAB2 + "IPv4 Packet: ")
            print(TAB2 + "Version: {}, Header Len: {}, TTL: {}, Protocol: {}, src: {}, dest: {}".format(version, header_length, ttl, ip_proto, src, dest))

            match ip_proto:
                case 1:
                    icmp_type, code, checksum, data = icmp_packet_unpack(data)
                    print(TAB3 + "ICMP Packet:")
                    print(TAB3 + "Type: {}, Code: {}, Check: {}".format(icmp_type, code, checksum))
                case 6:
                    src_port, dest_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_ret, flag_syn, flag_fin, data = tcp_segment_unpack(data)
                    print(TAB4 + "TCP Packet:")
                    print(TAB4 + "Src Port: {}, Dest Port: {}, Seq: {}, Ack: {}".format(src_port, dest_port, seq, ack))
                    print(TAB4 + "Flags: URG: {}, ACK: {}, PSH: {}, RET: {}, SYN: {}, FIN: {}".format(flag_urg, flag_ack, flag_psh, flag_ret, flag_syn, flag_fin)) 
                case 17:
                    src_port, dest_port, size, data = udp_segment_unpack(data)
                    print(TAB4 + "UDP Packet:")
                    print(TAB4 + "Src Port: {}, Dest Port: {}".format(src_port, dest_port))
                case _:
                    print(TAB4 + "Don't know the protocol used")


main()

