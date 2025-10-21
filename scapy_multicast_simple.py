#!/usr/bin/env python3
"""
ROS2 DDS SPDP multicast packet capture and Unicast Locator information extraction
"""
import socket
import struct
from scapy.all import sniff, IP, UDP, Raw, conf

# ROS2 DDS SPDP multicast configuration
MCAST_GRP = "239.255.0.1"
SPDP_PORT = 13150
LISTEN_IP = "0.0.0.0"

# RTPS Parameter ID definitions
PID_METATRAFFIC_UNICAST_LOCATOR = 0x0032
PID_DEFAULT_UNICAST_LOCATOR = 0x0031
PID_SENTINEL = 0x0001

def extract_unicast_locator(payload):
    """Extract Unicast Locator information from RTPS DATA Submessage"""
    offset = 20  # Skip RTPS header
    
    while offset < len(payload) - 4:
        submessage_id = payload[offset]
        length = struct.unpack('<H', payload[offset + 2:offset + 4])[0]
        
        if submessage_id != 0x15:  # Skip if not DATA Submessage
            offset += 4 + length
            continue

        # Parse ParameterList
        param_offset = offset + 4 + 24 
        param_list_end = offset + 4 + length

        while param_offset < param_list_end - 4:
            pid = struct.unpack('<H', payload[param_offset:param_offset+2])[0]
            param_length = struct.unpack('<H', payload[param_offset+2:param_offset+4])[0]

            if pid == PID_SENTINEL:  # End of ParameterList
                break

            if pid in [PID_METATRAFFIC_UNICAST_LOCATOR, PID_DEFAULT_UNICAST_LOCATOR]:
                locator_data = payload[param_offset+4 : param_offset+4+param_length]
                
                if len(locator_data) >= 24:
                    kind = struct.unpack('<I', locator_data[0:4])[0]
                    port = struct.unpack('<I', locator_data[4:8])[0]
                    
                    if kind == 1:  # UDPv4
                        ip_bytes = locator_data[20:24]
                        ip_addr = ".".join(map(str, ip_bytes))
                        return f"UDPv4:{ip_addr}:{port}"

            # Move to next parameter
            padding = (4 - (param_length % 4)) % 4
            param_offset += 4 + param_length + padding
        
        offset += 4 + length

    return None

def packet_handler(pkt):
    """Packet processing callback"""
    if pkt.haslayer(Raw):
        payload = bytes(pkt[Raw].load)
        
        if payload.startswith(b"RTPS") and pkt[UDP].dport == SPDP_PORT:
            src_ip = pkt[IP].src
            print(f"[+] SPDP Packet from: {src_ip}")
            
            locator = extract_unicast_locator(payload)
            if locator:
                print(f"  └── Unicast Locator: {locator}")
            else:
                print(f"  └── No Unicast Locator found")

def join_spdp_multicast():
    """Join SPDP multicast group"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((MCAST_GRP, SPDP_PORT))
        
        mreq = struct.pack("4s4s", socket.inet_aton(MCAST_GRP), socket.inet_aton(LISTEN_IP))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        print(f"[*] Successfully joined SPDP multicast group {MCAST_GRP}:{SPDP_PORT}")
        return sock
    except Exception as e:
        print(f"[!] Failed to join SPDP multicast group: {e}")
        return None

def main():
    print(f"[*] Starting SPDP Multicast Sniffer")
    
    # Join SPDP multicast group
    try:
        sock = join_spdp_multicast()
        if not sock:
            print(f"[!] Failed to join SPDP multicast group. Root privileges may be required.")
            return
    except Exception as e:
        print(f"[!] Failed to join SPDP multicast group: {e}")
        print(f"[!] Root privileges may be required, or there might be a network interface issue.")
        return

    print(f"[*] Starting packet capture for SPDP... (Press Ctrl+C to exit)")
    try:
        # Capture SPDP port only
        sniff(
            filter=f"udp and host {MCAST_GRP} and port {SPDP_PORT}",
            prn=packet_handler,
            store=False
        )
    except KeyboardInterrupt:
        print("\n[*] Sniffing stopped.")
    finally:
        # Clean up socket
        sock.close()

if __name__ == "__main__":
    main()
