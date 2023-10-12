# Insert in the for loop in main.py:
# ----------- FOR CONSOLE OUTPUT -----------

# raw_bytes = bytes(packet)
#
# ether_type = ""
# code_SAP = ""
# code_PID = ""
#
# if packet_info.get('frame_type') == "IEEE 802.3 LLC":
#     code_SAP = getSAP(raw_bytes)
#
# if packet_info.get('frame_type') == "IEEE 802.3 LLC & SNAP":
#     code_PID = getPID(raw_bytes)
#
# if packet_info.get('frame_type') == "ETHERNET II":
#     ether_type = getEtherType(raw_bytes)
#
# print(f"Packet {packet_count}| Length = {packet_info.get('len_frame_pcap')} bytes | Medium Length = {packet_info.get('len_frame_medium')} bytes")
# print(f"Destination MAC = {packet_info.get('dst_mac')} | Source MAC = {packet_info.get('src_mac')} | Frame Type = {packet_info.get('frame_type')}")
# if code_SAP != "":
#     print(f"SAP = {code_SAP}")
# if code_PID != "":
#     print(f"PID = {code_PID}")
# if ether_type != "":
#     print(f"Ether Type = {ether_type}")
#
# counter = 0
# for b in raw_bytes:
#     counter += 1
#     print(f"{b:02X}", end=" ")
#
#     if (counter % 16) == 0:
#         print()
#
# print("\n")


#_________________________________________________________________________________________________

# def getDataOnIndex(data, index, index2):
#     if ((data[index] << 8) | data[index2]) == 512:
#         return "XEROX PUP"
#     elif ((data[index] << 8) | data[index2]) == 267:  # 0x010B
#         return "PVSTP+"  # Per-VLAN Spanning Tree Protocol Plus
#     elif ((data[index] << 8) | data[index2]) == 513:
#         return "PUP Addr Trans"
#     elif ((data[index] << 8) | data[index2]) == 2048:
#         return "IPv4"  # Internet IP (IPv4)
#     elif ((data[index] << 8) | data[index2]) == 2049:
#         return "X.75 Internet"
#     elif ((data[index] << 8) | data[index2]) == 2053:
#         return "X.25 Level 3"
#     elif ((data[index] << 8) | data[index2]) == 2054:
#         return "ARP (Address Resolution Protocol)"
#     elif ((data[index] << 8) | data[index2]) == 8192:  # 0x2000
#         return "CDP"  # Cisco Discovery Protocol
#     elif ((data[index] << 8) | data[index2]) == 8196:  # 0x2004 | https://learningnetwork.cisco.com/s/article/ethernet-standards
#         return "DTP"  # Dynamic Trunking Protocol
#     elif ((data[index] << 8) | data[index2]) == 32821:
#         return "Reverse ARP"
#     elif ((data[index] << 8) | data[index2]) == 32923:
#         return "AppleTalk"  # Appletalk
#     elif ((data[index] << 8) | data[index2]) == 33011:
#         return "AppleTalk AARP (Kinetics)"
#     elif ((data[index] << 8) | data[index2]) == 33024:  # 0x8100
#         return "IEEE 802.1Q VLAN-tagged frames"
#     elif ((data[index] << 8) | data[index2]) == 33079:
#         return "Novell IPX"
#     elif ((data[index] << 8) | data[index2]) == 34525:
#         return "IPv6"
#     elif ((data[index] << 8) | data[index2]) == 34827:
#         return "PPP"
#     elif ((data[index] << 8) | data[index2]) == 34887:
#         return "MPLS"
#     elif ((data[index] << 8) | data[index2]) == 34888:
#         return "MPLS wit upstream-assigned label"
#     elif ((data[index] << 8) | data[index2]) == 34915:
#         return "PPPoE Discovery Stage"
#     elif ((data[index] << 8) | data[index2]) == 34916:
#         return "PPPoE Session Stage"
#     else:
#         return f"{data[index]:02X} {data[index]:02X}"

#_________________________________________________________________________________________________

# def getSAP(data):
#     if data[14] == 0x00 and data[15] == 0x00:
#         return "Null SAP"
#     elif data[14] == 0x02 and data[15] == 0x02:
#         return "LLC Sublayer Management / Individual"
#     elif data[14] == 0x03 and data[15] == 0x03:
#         return "LLC Sublayer Management / Group"
#     elif data[14] == 0x06 and data[15] == 0x06:
#         return "IP (DoD Internet Protocol)"
#     elif data[14] == 0x0E and data[15] == 0x0E:
#         return "PROWAY (IEC 955) Network Management, Maintenance and Installation"
#     # could be STP ?
#     elif data[14] == 0x42 and data[15] == 0x42:
#         return "STP"  # BPDU (Bridge PDU / 802.1 Spanning Tree)
#     elif data[14] == 0x4E and data[15] == 0x4E:
#         return "MMS (Manufacturing Message Service) EIA-RS 511"
#     elif data[14] == 0x5E and data[15] == 0x5E:
#         return "ISI IP"
#     elif data[14] == 0x7E and data[15] == 0x7E:
#         return "X.25 PLP (ISO 8208)"
#     elif data[14] == 0x8E and data[15] == 0x8E:
#         return "PROWAY (IEC 955) Active Station List Maintenance"
#     elif data[14] == 0xAA and data[15] == 0xAA:
#         return "SNAP (Sub-Network Access Protocol / non-IEEE SAPs)"
#     elif data[14] == 0xE0 and data[15] == 0xE0:
#         return "IPX"  # IPX(Novell Netware)
#     # NETBIOS wasn't in the .txt file
#     elif data[14] == 0xF0 and data[15] == 0xF0:
#         return "NETBIOS"
#     elif data[14] == 0xF4 and data[15] == 0xF4:
#         return "LAN Management"
#     elif data[14] == 0xFE and data[15] == 0xFE:
#         return "ISO Network Layer Proto ols"
#     elif data[14] == 0xFF and data[15] == 0xFF:
#         return "Global DSAP"
#     # when unknown, return the hex value
#     else:
#         return f"{data[14]:02X} {data[15]:02X}"

#_________________________________________________________________________________________________

# from get_frame_info

# if getFrameType(raw_bytes) == "IEEE 802.3 LLC":
#     packet_info = {
#         'frame_number': packet_count,
#         'len_frame_pcap': len(packet),
#         'len_frame_medium': len(packet) + 4 if len(packet) >= 60 else 64,
#         'frame_type': getFrameType(raw_bytes),
#         'src_mac': getSrcMAC(raw_bytes),
#         'dst_mac': getDstMAC(raw_bytes),
#         'hexa_frame': packet_hex_dump,
#         'sap': getSAP(raw_bytes)
#     }
# elif getFrameType(raw_bytes) == "IEEE 802.3 LLC & SNAP":
#     # validator does not know about other PIDs except 4 of them
#     # so returning null for other PIDs to pass the validator
#     packet_info = {
#         'frame_number': packet_count,
#         'len_frame_pcap': len(packet),
#         'len_frame_medium': len(packet) + 4 if len(packet) >= 60 else 64,
#         'frame_type': getFrameType(raw_bytes),
#         'src_mac': getSrcMAC(raw_bytes),
#         'dst_mac': getDstMAC(raw_bytes),
#         'hexa_frame': packet_hex_dump,
#         'pid': getPID(raw_bytes)
#     }
# elif getFrameType(raw_bytes) == "ETHERNET II":
#     packet_info = {
#         'frame_number': packet_count,
#         'len_frame_pcap': len(packet),
#         'len_frame_medium': len(packet) + 4 if len(packet) >= 60 else 64,
#         'frame_type': getFrameType(raw_bytes),
#         'src_mac': getSrcMAC(raw_bytes),
#         'dst_mac': getDstMAC(raw_bytes),
#         'hexa_frame': packet_hex_dump,
#         'ether_type': getEtherType(raw_bytes)
#     }
# else:  # IEEE 802.3 RAW
#     packet_info = {
#         'frame_number': packet_count,
#         'len_frame_pcap': len(packet),
#         'len_frame_medium': len(packet) + 4 if len(packet) >= 60 else 64,
#         'frame_type': getFrameType(raw_bytes),
#         'src_mac': getSrcMAC(raw_bytes),
#         'dst_mac': getDstMAC(raw_bytes),
#         'hexa_frame': packet_hex_dump,
#     }

#_________________________________________________________________________________________________

