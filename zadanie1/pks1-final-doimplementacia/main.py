from scapy.all import rdpcap
import ruamel.yaml as yaml

global parsed_data_ports_and_protocols
global data_4

# Load the contents of the file globally
with open("Protocols/ports-and-some-protocols.txt", "r") as file:
    global_data = file.read()
    parsed_data_ports_and_protocols = yaml.safe_load(global_data)

with open("Protocols/protocols-4.txt", "r") as file_4:
    data_4 = file_4.read()


def getDataFromFile(option, number):
    if option == "ether_types":
        for key, value in parsed_data_ports_and_protocols.get("ether_types", {}).items():
            if key == number:
                return value
    elif option == "saps":
        for key, value in parsed_data_ports_and_protocols.get("saps", {}).items():
            if key == number:
                return value
    elif option == "pid":
        for key, value in parsed_data_ports_and_protocols.get("pid", {}).items():
            if key == number:
                return value
    elif option == "tcp_protocols":
        for key, value in parsed_data_ports_and_protocols.get("tcp_protocols", {}).items():
            if key == number:
                return value
    elif option == "udp_protocols":
        for key, value in parsed_data_ports_and_protocols.get("udp_protocols", {}).items():
            if key == number:
                return value
    elif option == "ip_protocols":
        for key, value in parsed_data_ports_and_protocols.get("ip_protocols", {}).items():
            if key == number:
                return value
    elif option == "icmp_codes":
        for key, value in parsed_data_ports_and_protocols.get("icmp_codes", {}).items():
            if key == number:
                return value
    else:
        return "Error"


def get_frame_info(packet, packet_count):
    raw_bytes = bytes(packet)
    hexa_frame = ' '.join([f"{b:02X}" for b in raw_bytes])  # string of hexdump

    packet_hex_dump = ' '.join([hexa_frame[i:i + 2] for i in range(0, len(hexa_frame), 3)])
    packet_hex_dump = 'PIPENEWLINE' + 'NEWLINE'.join([packet_hex_dump[i:i + 47] for i in range(0, len(packet_hex_dump), 48)])

    # for IEEE 802.3 RAW
    packet_info = {
        'frame_number': packet_count,
        'len_frame_pcap': len(packet),
        'len_frame_medium': len(packet) + 4 if len(packet) >= 60 else 64,
        'frame_type': getFrameType(raw_bytes),
        'src_mac': getSrcMAC(raw_bytes),
        'dst_mac': getDstMAC(raw_bytes),
        'hexa_frame': packet_hex_dump,
    }

    # for other frame types, add more info
    if getFrameType(raw_bytes) == "IEEE 802.3 LLC":
        packet_info['sap'] = getSAP(raw_bytes)
    elif getFrameType(raw_bytes) == "IEEE 802.3 LLC & SNAP":
        packet_info['pid'] = getPID(raw_bytes)

    elif getFrameType(raw_bytes) == "ETHERNET II":
        packet_info['ether_type'] = getEtherType(raw_bytes)
        if getEtherType(raw_bytes) == "IPv4":
            packet_info['src_ip'] = getIPv4(raw_bytes, "s")
            packet_info['dst_ip'] = getIPv4(raw_bytes, "d")

            protocol = getIPv4Protocol(raw_bytes)
            packet_info['protocol'] = protocol

            if protocol == "tcp" or protocol == "udp":
                src_port = getTCPorUDP_port(raw_bytes, "s")
                dst_port = getTCPorUDP_port(raw_bytes, "d")

                packet_info['src_port'] = src_port
                packet_info['dst_port'] = dst_port

                name_src = getDataFromFile(f"{protocol}_protocols", src_port)
                name_dst = getDataFromFile(f"{protocol}_protocols", dst_port)

                if name_src is not None and name_src != "":
                    packet_info['app_protocol'] = name_src
                elif name_dst is not None and name_dst != "":
                    packet_info['app_protocol'] = name_dst

        elif getEtherType(raw_bytes) == "ARP":
            packet_info['src_ip'] = getIP_for_ARP(raw_bytes, "s")
            packet_info['dst_ip'] = getIP_for_ARP(raw_bytes, "d")

    return packet_info


def getDecimalFrom2BytesAfterOther(data, index1):
    return (data[index1] << 8) | data[index1+1]


def getEtherType(data):
    decimal = getDecimalFrom2BytesAfterOther(data, 12)
    return getDataFromFile("ether_types", decimal)


def getPID(data):
    decimal = getDecimalFrom2BytesAfterOther(data, 20)
    return getDataFromFile("pid", decimal)


# for SAPs
def getDecimalIf2BytesSame(data, index1):
    if data[index1] == data[index1+1]:
        return data[index1]
    else:
        return -1


def getSAP(data):
    decimal = getDecimalIf2BytesSame(data, 14)
    if decimal != -1:
        return getDataFromFile("saps", decimal)


def getFrameType(data):
    if getDecimalFrom2BytesAfterOther(data, 12) > 1500:  # 0x0600 dec 1536
        return "ETHERNET II"
    if getDecimalIf2BytesSame(data, 14) == 255:  # 0xFF
        return "IEEE 802.3 RAW"
    if getDecimalIf2BytesSame(data, 14) == 170:  # 0xAA
        return "IEEE 802.3 LLC & SNAP"

    return "IEEE 802.3 LLC"


def getDstMAC(data):
    return f"{data[0]:02X}:{data[1]:02X}:{data[2]:02X}:{data[3]:02X}:{data[4]:02X}:{data[5]:02X}"


def getSrcMAC(data):
    return f"{data[6]:02X}:{data[7]:02X}:{data[8]:02X}:{data[9]:02X}:{data[10]:02X}:{data[11]:02X}"


# for IPv4
def getIPv4(data, s_or_d):
    first_half = data[14] >> 4
    # myslel som ze bude potrebna aj druha polovica, ale ip adresy su stale na rovnakych indexoch
    # dalej su uz Options (optional)
    # second_half = data[14] & 0b00001111

    if first_half == 4:
        end_of_ip = 14 + 5 * 4  # 5*4 = 20; 20+14 = 34; before end_of_ip = 14 + second_half * 4
        if s_or_d == "d":
            return f"{data[end_of_ip-4]:d}.{data[end_of_ip-3]:d}.{data[end_of_ip-2]:d}.{data[end_of_ip-1]:d}"
        elif s_or_d == "s":
            return f"{data[end_of_ip - 8]:d}.{data[end_of_ip - 7]:d}.{data[end_of_ip - 6]:d}.{data[end_of_ip - 5]:d}"
        else:
            return ""
    return ""


def getIP_for_ARP(data, s_or_d):
    if s_or_d == "d":
        return f"{data[38]:d}.{data[39]:d}.{data[40]:d}.{data[41]:d}"
    elif s_or_d == "s":
        return f"{data[28]:d}.{data[29]:d}.{data[30]:d}.{data[31]:d}"

    return ""


def getIP_for_ARP_number(data, s_or_d):
    ip_string = ""
    if s_or_d == "d":
        ip_string = data['dst_ip']
    elif s_or_d == "s":
        ip_string = data['src_ip']

    numbers = ip_string.split(".")
    # convert numbers to int
    numbers = [int(i) for i in numbers]

    return numbers[0] << 24 | numbers[1] << 16 | numbers[2] << 8 | numbers[3]


def getIPv4Protocol(data):
    return getDataFromFile("ip_protocols", data[23])


def getARP_OPCode(data):
    opcode = getDecimalFrom2BytesAfterOther(data, 20)
    if opcode == 1:
        return "REQUEST"
    elif opcode == 2:
        return "REPLY"
    else:
        return "Unknown"


def getTCPorUDP_port(data, s_or_d):
    start_index = 14 + (data[14] & 0b00001111) * 4
    port_id = -1
    if s_or_d == "s":
        port_id = getDecimalFrom2BytesAfterOther(data, start_index)
    elif s_or_d == "d":
        port_id = getDecimalFrom2BytesAfterOther(data, start_index+2)

    return port_id


def helloHelp():
    print(f"""
Usage: {sys.argv[0]} <pcap_file> <-switch> <protocol>
Example: {sys.argv[0]} eth-1.pcap -p arp   
Supported switches: -p
Supported protocols: """, end="")
    protocols_list = []
    for line in data_4.splitlines():
        protocols_list.append(line)
    print(', '.join(protocols_list))


def main():
    # input checks
    protocol_to_find = ""
    if len(sys.argv) < 2:
        print("Missing arguments")
        print("For help use -h or --help")
        return

    if sys.argv[1] == "-h" or sys.argv[1] == "--help":
        helloHelp()
        return

    if len(sys.argv) == 3:
        print("Missing protocol")
        return

    if len(sys.argv) == 4 and sys.argv[2] != "-p":
        print("Wrong switch")
        return

    if len(sys.argv) > 4:
        print("Too many arguments")
        return

    if len(sys.argv) == 4:
        found = False
        for line in data_4.splitlines():
            if line == sys.argv[3].lower():
                found = True
                protocol_to_find = line.upper()
                break
        if not found:
            print("Protocol not found")
            return

    # read pcap file
    pcap_file = sys.argv[1]
    try:
        packets = rdpcap(pcap_file)
        packet_count = 0
        if protocol_to_find == "":
            output_data = {
                'name': 'PKS2023/24',
                'pcap_name': sys.argv[1],
                'packets': [],
            }
        elif protocol_to_find == "ARP":
            output_data = {
                'name': 'PKS2023/24',
                'pcap_name': sys.argv[1],
                'filter_name': protocol_to_find,
                # 'complete_comms': [],
                # 'partial_comms': [],
            }
        elif protocol_to_find == "CDP":
            output_data = {
                'name': 'PKS2023/24',
                'filter_name': protocol_to_find,
                'pcap_name': sys.argv[1],
                'packets': [],
            }

        # for IPv4 senders
        if protocol_to_find == "":
            ipv4_senders = {}
            output_data['ipv4_senders']: ipv4_senders  # Use a set to store unique IPv4 senders
        elif protocol_to_find == "ARP":
            # for ARP filter
            arp_requests = []
            arp_replies = []

            complete_comms = {}
            partial_comms = {}
            complete_comm_count = 1
            partial_comm_count = 1

        elif protocol_to_find =="CDP":
            number_frames = 0

        for packet in packets:
            packet_count += 1
            packet_info = get_frame_info(packet, packet_count)

            if protocol_to_find == "":
                output_data['packets'].append(packet_info)

                # for IPv4 senders
                if packet_info['frame_type'] == "ETHERNET II" and packet_info['ether_type'] == "IPv4":
                    src_ip = packet_info['src_ip']

                    if src_ip not in ipv4_senders:
                        ipv4_senders[src_ip] = 1
                    else:
                        ipv4_senders[src_ip] += 1

                    # Convert the dictionary to the desired list of dictionaries format
                    ipv4_senders_list = [{'node': ip, 'number_of_sent_packets': count} for ip, count in ipv4_senders.items()]
                    output_data['ipv4_senders'] = ipv4_senders_list

                    # Determine the maximum number of sent packets by individual senders
                    max_send_packets = max(ipv4_senders.values())
                    max_send_packets_by = [ip for ip, count in ipv4_senders.items() if count == max_send_packets]
                    output_data['max_send_packets_by'] = max_send_packets_by

            elif protocol_to_find == "ARP":

                # for ARP filter
                if packet_info['frame_type'] == "ETHERNET II" and packet_info['ether_type'] == "ARP":
                    src_ip = packet_info['src_ip']
                    dst_ip = packet_info['dst_ip']
                    packet_info['arp_opcode'] = getARP_OPCode(bytes(packet))

                    if packet_info['arp_opcode'] == "REQUEST":
                        arp_requests.append(packet_info)
                    elif packet_info['arp_opcode'] == "REPLY":
                        arp_replies.append(packet_info)

            elif protocol_to_find == "CDP":
                if packet_info['frame_type'] == "IEEE 802.3 LLC & SNAP" and packet_info['pid'] == "CDP":
                    number_frames += 1
                    output_data['packets'].append(packet_info)


        if protocol_to_find == "ARP":
            for request_packet in arp_requests:
                found_pair = False
                for reply_packet in arp_replies:
                    if request_packet['src_ip'] == reply_packet['dst_ip'] and request_packet['dst_ip'] == reply_packet['src_ip']:
                        src_ip_request_key = getIP_for_ARP_number(request_packet, "s")
                        dst_ip_request_key = getIP_for_ARP_number(request_packet, "d")
                        key = ""
                        if src_ip_request_key < dst_ip_request_key:
                            key = f"{src_ip_request_key}-{dst_ip_request_key}"
                        else:
                            key = f"{dst_ip_request_key}-{src_ip_request_key}"

                        # Complete ARP communication
                        if key not in complete_comms:
                            complete_comms[key] = comm = {
                              'number_comm': complete_comm_count,
                              'packets': [request_packet, reply_packet],
                            }
                        else:
                            comm = complete_comms[key]
                            comm['packets'].append(request_packet)
                            comm['packets'].append(reply_packet)

                        found_pair = True
                        complete_comm_count += 1
                        arp_replies.remove(reply_packet)
                        break

                if not found_pair:
                    src_ip_request_key = getIP_for_ARP_number(request_packet, "s")
                    dst_ip_request_key = getIP_for_ARP_number(request_packet, "d")
                    key = ""
                    if src_ip_request_key < dst_ip_request_key:
                        key = f"{src_ip_request_key}-{dst_ip_request_key}"
                    else:
                        key = f"{dst_ip_request_key}-{src_ip_request_key}"

                    if key not in partial_comms:
                        partial_comms[key] = comm = {
                            'number_comm': partial_comm_count,
                            'packets': [request_packet],
                        }
                    else:
                        comm = partial_comms[key]
                        comm['packets'].append(request_packet)

                    partial_comm_count += 1

            for reply_packet in arp_replies:
                src_ip_reply_key = getIP_for_ARP_number(reply_packet, "s")
                dst_ip_reply_key = getIP_for_ARP_number(reply_packet, "d")
                key = ""
                if src_ip_reply_key < dst_ip_reply_key:
                    key = f"{src_ip_reply_key}-{dst_ip_reply_key}"
                else:
                    key = f"{dst_ip_reply_key}-{src_ip_reply_key}"

                # Complete ARP communication
                if key not in partial_comms:
                    partial_comms[key] = comm = {
                        'number_comm': partial_comm_count,
                        'packets': [reply_packet],
                    }
                else:
                    comm = partial_comms[key]
                    comm['packets'].append(reply_packet)

                partial_comm_count += 1

            output_data['complete_comms'] = list(complete_comms.values())
            output_data['partial_comms'] = list(partial_comms.values())

        elif protocol_to_find == "CDP":
            output_data['number_frames'] = number_frames

        with open('output.yaml', 'w') as yaml_file:
            yaml_full = yaml.dump(output_data, default_flow_style=False, width=9999999)
            if protocol_to_find != "":
                yaml_full = yaml_full.replace('NEWLINE', '\n        ')
            else:
                yaml_full = yaml_full.replace('NEWLINE', '\n    ')
            yaml_full = yaml_full.replace('PIPE', '|')

            yaml_file.write(yaml_full)

            print("Output file created successfully")

    except Exception as e:
        print("Error opening or reading pcap file:", str(e))


if __name__ == "__main__":
    import sys

    main()
