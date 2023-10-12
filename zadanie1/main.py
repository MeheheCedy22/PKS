from scapy.all import rdpcap
import ruamel.yaml as yaml


def getDataFromFile(txt_file, option, number):
    # Load the contents of the file
    with open(txt_file, "r") as file:
        data = file.read()

    # Parse the YAML content into a dictionary
    parsed_data = yaml.safe_load(data)

    if option == "ether_types":
        for key, value in parsed_data.get("ether_types", {}).items():
            if key == number:
                return value
    elif option == "saps":
        for key, value in parsed_data.get("saps", {}).items():
            if key == number:
                return value
    elif option == "pid":
        for key, value in parsed_data.get("pid", {}).items():
            if key == number:
                return value
    elif option == "tcp_ports":
        for key, value in parsed_data.get("tcp_ports", {}).items():
            if key == number:
                return value
    elif option == "ip_protocols":
        for key, value in parsed_data.get("ip_protocols", {}).items():
            if key == number:
                return value
    elif option == "icmp_codes":
        for key, value in parsed_data.get("icmp_codes", {}).items():
            if key == number:
                return value
    else:
        return "Error"


def get_frame_info(packet, packet_count):
    raw_bytes = bytes(packet)
    hexa_frame = ' '.join([f"{b:02X}" for b in raw_bytes])  # string of hexdump

    packet_hex_dump = ' '.join([hexa_frame[i:i + 2] for i in range(0, len(hexa_frame), 3)])
    packet_hex_dump = 'PIPENEWLINE' + 'NEWLINE'.join([packet_hex_dump[i:i + 47] for i in range(0, len(packet_hex_dump), 48)])

    packet_info = {
        'frame_number': packet_count,
        'len_frame_pcap': len(packet),
        'len_frame_medium': len(packet) + 4 if len(packet) >= 60 else 64,
        'frame_type': getFrameType(raw_bytes),
        'src_mac': getSrcMAC(raw_bytes),
        'dst_mac': getDstMAC(raw_bytes),
        'hexa_frame': packet_hex_dump,
    }
    if getFrameType(raw_bytes) == "IEEE 802.3 LLC":
        packet_info['sap'] = getSAP(raw_bytes)
    elif getFrameType(raw_bytes) == "IEEE 802.3 LLC & SNAP":
        packet_info['pid'] = getPID(raw_bytes)
    elif getFrameType(raw_bytes) == "ETHERNET II":
        packet_info['ether_type'] = getEtherType(raw_bytes)
        if getEtherType(raw_bytes) == "IPv4":
            packet_info['src_ip'] = getIPv4(raw_bytes, "s")
            packet_info['dst_ip'] = getIPv4(raw_bytes, "d")
        # elif getFrameType(raw_bytes) == "IEEE 802.3 RAW":
        #     packet_info['src_ip'] =
        #     packet_info['dst_ip'] =

    return packet_info


def getDecimalFrom2BytesAfterOther(data, index1):
    return (data[index1] << 8) | data[index1+1]


def getEtherType(data):
    decimal = getDecimalFrom2BytesAfterOther(data, 12)
    return getDataFromFile("ports-etc-plus-mine.txt", "ether_types", decimal)


def getPID(data):
    decimal = getDecimalFrom2BytesAfterOther(data, 20)
    return getDataFromFile("ports-etc-plus-mine.txt", "pid", decimal)


# for SAPs
def getDecimalIf2BytesSame(data, index1):
    if data[index1] == data[index1+1]:
        return data[index1]
    else:
        return -1


def getSAP(data):
    decimal = getDecimalIf2BytesSame(data, 14)
    if decimal != -1:
        return getDataFromFile("ports-etc-plus-mine.txt", "saps", decimal)


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
    second_half = data[14] & 0b00001111

    if first_half == 4:
        end_of_ip = 14 + second_half * 4
        if s_or_d == "d":
            return f"{data[end_of_ip-4]:d}.{data[end_of_ip-3]:d}.{data[end_of_ip-2]:d}.{data[end_of_ip-1]:d}"
        elif s_or_d == "s":
            return f"{data[end_of_ip - 8]:d}.{data[end_of_ip - 7]:d}.{data[end_of_ip - 6]:d}.{data[end_of_ip - 5]:d}"
        else:
            return ""
    return ""

# def getIP_for_ARP(data, s_or_d):



def helloHelp():
    print("""

    """)


def main():
    if len(sys.argv) < 2:
        print()
        print(f"Usage: {sys.argv[0]} <pcap_file> <-switch>")
        print("For help use -h or --help")
        print(f"{sys.argv[0]} -h")
        return

    if sys.argv[1] == "-h" or sys.argv[1] == "--help":
        helloHelp()
        return

    pcap_file = sys.argv[1]

    try:
        packets = rdpcap(pcap_file)
        packet_count = 0
        output_data = {
            'name': 'PKS2023/24',
            'pcap_name': sys.argv[1],
            'packets': []
        }

        for packet in packets:
            packet_count += 1

            packet_info = get_frame_info(packet, packet_count)
            output_data['packets'].append(packet_info)

        with open('output.yaml', 'w') as yaml_file:
            yaml_full = yaml.dump(output_data, default_flow_style=False, width=9999999)
            yaml_full = yaml_full.replace('NEWLINE', '\n    ')
            yaml_full = yaml_full.replace('PIPE', '|')

            yaml_file.write(yaml_full)

    except Exception as e:
        print("Error opening or reading pcap file:", str(e))


if __name__ == "__main__":
    import sys

    main()
