# Implementing a simple reliable data transfer protocol over UDP
# Protocol name: Dzabede Nesta Protocol (DNP)
# Protocol server default: Port 18080
# Protocol client default: Port 18081

# Zmeny:
# zmena fragment number = fragement count
# zmena fragment offset = number of teh current fragment
# pridane dalsie signalizacne spravy

# DNP Header
# |                          PAYLOAD					                        |
# |                      DNP HEADER                                     |
#  MSG_TYPE   PACKET_LENGTH	 FRAG_COUNT  CURRENT_FRAG_NUMBER  CHECKSUM     DATA
#     1	         2	             2	         2	                 1	         10

# Data have 10B theoretical limit
# but:
# actually have 24B hardcoded limit
# 8B+24B = 32B with header1

# 32B Because FRAG_COUNT is only 2B long
# 2^16 = 65,536               DATA/possible FRAG_COUNT = minimal packet size
# For 2MegaByte data, we need 2,000,000/2^16 ~ 32 B packets

# Sys exit 10 je korektné ukončenie pri požiadavke na ukončenie spojenia
# Sys exit 20 je korektné ukončenie pri požiadavke na ukončenie programu


import socket
import sys
import threading
import os
import struct
import time
import math


# -------------
HEADER_SIZE = 8
MIN_FRAGMENT_SIZE = 10 # 8 + 10 = 18B
MAX_FRAGMENT_SIZE = 1464 # 8 + 1464 = 1472B
FORMAT = "utf-8"
KEEP_ALIVE_INTERVAL = 5 # seconds

# Message Types
# The numbers are not in binary representation,
# but they are used as ASCII values cuz of encoding
# RESERVED = "0"
KEEP_ALIVE = "1"
ESTABLISH_CONNECTION = "2"
TERMINATE_CONNECTION = "3"
SEND_MESSAGE = "4"
SEND_FILE = "5"
ERROR_IN_DELIVERY = "6"
DELIVERY_OK = "7"
SWITCH_ROLES = "8"
FILE_BIGGER_THAN_2MB = "9"
# -------------
PREV_IP = None
PREV_PORT = None

SERVER_SWITCHING_PORT = None
SERVER_WANTS_TO_SWITCH = False
CLIENT_SWITCH_REQ_FROM_SERVER = False

CLIENT_IP_FOR_SERVER_SWITCHING = None
CLIENT_PORT_FOR_SERVER_SWITCHING = None

REMEMBERED_SERVER_PORT = None

CONNECTED = True
# -------------


# checksum is basically parity in my implementation, where it is calculated
# only from the data part of the packet
# it is calculated as follows:
# split the data into 8 segments and calculate parity bit for each segment (even parity)
# then combine them into 1 byte but in binary so that the most significant bit is the first segment etc
# return the checksum as an integer
def checksum(string_message):
    # string to binary
    binary_string = ''.join(format(ord(c), '08b') for c in string_message)
    # divide into sections
    n = len(binary_string) // 8
    sections = [binary_string[i:i+n] for i in range(0, len(binary_string), n)]
    # calculate parity for each section
    parities = [str(section.count('1') % 2) for section in sections]
    # combine parity bits
    # added modulo 256 to prevent overflow because of decoding file in bytes to string and backwards
    # was getting checksums > 255
    return int(''.join(parities), 2) % 256


def checksum_binary(binary_message):
    # divide into sections
    n = len(binary_message) // 8
    sections = [binary_message[i:i+n] for i in range(0, len(binary_message), n)]
    # calculate parity for each section
    parities = [str(section.count(b'1') % 2) for section in sections]
    # combine parity bits
    # added modulo 256 to prevent overflow because of decoding file in bytes to string and backwards
    # was getting checksums > 255
    return int(''.join(parities), 2) % 256


def switch_roles(client_or_server, socket_for_switch, ip_address, port):
    print("Started switching process...")
    print(f"You are now - {client_or_server}")

    global PREV_IP
    PREV_IP = socket.gethostbyname(socket.gethostname())
    global PREV_PORT
    PREV_PORT = port

    while True:
        print("Enter your option: ")
        print("1 - Switch roles")
        print("2 - Quit switching")
        choice = input()

        if choice == "1":
            print("Switching roles...")
            if client_or_server == "client":
                client_or_server = "server"
                while True:
                    socket_for_switch.sendto(str.encode(SWITCH_ROLES), (ip_address, port))
                    data, ip_addr = socket_for_switch.recvfrom(1526)
                    data_decoded = str(data, encoding=FORMAT)
                    if data_decoded == SWITCH_ROLES:
                        print("Closing client program...")
                        print("Switching roles successful")
                        socket_for_switch.close()
                        Server(port)

                    else:
                        print("Switching message not received")
                        print("Resending switching message...")
            elif client_or_server == "server":
                client_or_server = "client"

                print("Switching roles message received from: ", ip_address)
                socket_for_switch.sendto(str.encode(SWITCH_ROLES), (ip_address, port))
                print("Closing server program...")
                socket_for_switch.close()
                # musi pockat abu sa nastartoval prvy server
                # na server side musi rychle kliknut do 5 sekund
                time.sleep(5)
                Client(ip_address, REMEMBERED_SERVER_PORT)

            # else netreba lebo aj tak iba ja setujem ci som client alebo server
            else:
                pass

        elif choice == "2":
            print("No switching...")
            PREV_IP = None
            PREV_PORT = None
            return "NO SWITCHING"
        else:
            print("Invalid input, try again")


def server_choice():
    print("Enter your option: ")
    print("1 - Switch roles")
    print("2 - Quit")
    print("Press whatever to continue")

    choice = input()
    return choice


def Server(PORT_switch):

    print("-----You are SERVER-----")

    # first connection
    socket_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    SERVER_IP = socket.gethostbyname(socket.gethostname())
    print("Server IP: ", SERVER_IP)
    if PORT_switch is None:
        port = int(input("Enter port: "))
        global SERVER_SWITCHING_PORT
        SERVER_SWITCHING_PORT = port
    else:
        port = PORT_switch
        print("Port: ", port)

    # remember port for switching
    global REMEMBERED_SERVER_PORT
    REMEMBERED_SERVER_PORT = port

    socket_server.bind(("", port))
    data, client_ip = socket_server.recvfrom(1526) # max eth frame size including preamble etc.
    socket_server.sendto(str.encode(ESTABLISH_CONNECTION), client_ip)
    print("Connection established with: ", client_ip)

    # server running
    while True:
        choice = server_choice()
        if choice == "1":
            print("Trying to switch roles...")

            global SERVER_WANTS_TO_SWITCH
            SERVER_WANTS_TO_SWITCH = True

        else:
            print("Nothing changed, continuing...")

        receive(socket_server)


def client_choice():
    print("Enter your option: ")
    print("1 - Send message")
    print("2 - Send file")
    print("3 - Switch roles")
    print("4 - Quit")

    choice = input()
    return choice


def Client(IP_switch, PORT_switch):

    while True:
        global CONNECTED, CLIENT_SWITCH_REQ_FROM_SERVER

        print("-----You are CLIENT-----")

        socket_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        CLIENT_IP = socket.gethostbyname(socket.gethostname())
        print("Client IP: ", CLIENT_IP)
        port = None
        SERVER_IP_FOR_CLIENT = None

        if IP_switch is None and PORT_switch is None:
            port = int(input("Enter port: "))
            SERVER_IP_FOR_CLIENT = input("Enter server IP: ")
        else:
            # treba PREV port aby tam poslal lebo on si svoj vygeneruje
            # ked tam bolo PORT_SWITCH tak chcel poslat na vlastne predosle spojenie ktore skoncilo
            port = PORT_switch
            SERVER_IP_FOR_CLIENT = IP_switch
            print("Port: ", port)
            print("Server IP: ", SERVER_IP_FOR_CLIENT)

        server_ip_and_port = (SERVER_IP_FOR_CLIENT, port)
        socket_client.sendto(str.encode(ESTABLISH_CONNECTION), server_ip_and_port)
        data, server_ip = socket_client.recvfrom(1526)
        data_decoded = str(data, encoding=FORMAT)

        if data_decoded == ESTABLISH_CONNECTION:
            print("Connection established with: ", server_ip)

            # turn on keep alive thread
            keep_alive_thread = threading.Thread(target=keep_alive, args=(socket_client, server_ip), daemon=True)
            keep_alive_thread.start()
            CONNECTED = True

            while True:
                choice = client_choice()

                # if server initiate switching
                if CLIENT_SWITCH_REQ_FROM_SERVER:
                    print("Server wants to switch")
                    CLIENT_SWITCH_REQ_FROM_SERVER = False
                    if keep_alive_thread.is_alive():
                        CONNECTED = False
                        keep_alive_thread.join()
                    print("Closing client program...")
                    print("Switching roles successful")
                    socket_client.close()
                    Server(port)

                # client choice menu
                if choice == "1": # send message
                    print("Sending message...")
                    send_message(socket_client, server_ip)

                elif choice == "2": # send file
                    print("Sending file...")
                    send_file(socket_client, server_ip)

                elif choice == "3": # switch roles
                    print("Switching roles...")
                    if keep_alive_thread.is_alive():
                        CONNECTED = False
                        keep_alive_thread.join()

                    switched = switch_roles("client", socket_client, SERVER_IP_FOR_CLIENT, port)
                    if switched == "NO SWITCHING":
                        CONNECTED = True
                        keep_alive_thread = threading.Thread(target=keep_alive, args=(socket_client, server_ip), daemon=True)
                        keep_alive_thread.start()

                elif choice == "4": # quit
                    print("Closing client program...")
                    if keep_alive_thread.is_alive():
                        CONNECTED = False
                        keep_alive_thread.join()

                    while True:
                        socket_client.sendto(str.encode(TERMINATE_CONNECTION), server_ip_and_port)
                        data, FILLER = socket_client.recvfrom(1526)
                        data_decoded_terminate = str(data, encoding=FORMAT)

                        if data_decoded_terminate == TERMINATE_CONNECTION:
                            socket_client.close()
                            print("All terminated, closing main program")
                            sys.exit(10)

                else:
                    print("Nothing changed, continuing...")


def keep_alive(socket_client, server_ip):
    global CONNECTED

    while True:
        if not CONNECTED:
            return
        socket_client.sendto(str.encode(KEEP_ALIVE), server_ip)
        socket_client.settimeout(30)
        try:
            data, FILLER = socket_client.recvfrom(1526)
        except socket.timeout as e:
            # print("Keep alive message not received from: ", server_ip)
            # print("Ending connection...")
            CONNECTED = False
            while not CONNECTED:
                pass
            return
        data_decoded = str(data, encoding=FORMAT)

        if data_decoded == SWITCH_ROLES:
            print("Switch has been requested from server")
            print("Press enter to continue...")
            global CLIENT_SWITCH_REQ_FROM_SERVER
            CLIENT_SWITCH_REQ_FROM_SERVER = True
            return

        if data_decoded == KEEP_ALIVE:
            pass
            # print("Keep alive message received from: ", server_ip)
        else:
            print("Keep alive message not received from: ", server_ip)
            print("Ending connection...")
            break
        time.sleep(KEEP_ALIVE_INTERVAL)

# pridane v doimplementacii
# ----------------------------
def cesar_cipher(message):
    new_message = ""
    # shift 5
    for letter in message:
        if letter.islower():
            new_message += chr((ord(letter) + 5 - 97) % 26 + 97)
        elif letter.isupper():
            new_message += chr((ord(letter) + 5 - 65) % 26 + 65)
        else:
            new_message += letter
    return new_message


def append_begin_end(message):
    message = "___" + message + "___"
    return message
# ----------------------------

def send_message(socket_client, server_ip):

    message = input("Enter your message: ")
    fragment = int(input("Enter fragment size (10-1464): "))

    while True:
        if fragment < MIN_FRAGMENT_SIZE or fragment > MAX_FRAGMENT_SIZE:
            print("Invalid fragment size")
            fragment = int(input("Enter fragment size (10-1464): "))
        else:
            break

    # presunute sem
    # ----------------------------
    message = cesar_cipher(message)
    message = append_begin_end(message)
    print("Cesar ciphered message: ", message)
    # ----------------------------

    number_of_fragments = math.ceil(len(message)/fragment)
    print("Number of fragments: ", number_of_fragments)

    message_to_send = None

    msg_type = SEND_MESSAGE # 1B
    msg_length = 0 # 2B
    frag_count = number_of_fragments # 2B
    frag_number = 0 # 2B
    checksum_value = 0 # 1B

    # ----------------------------
    # mal som to najprv tu v doimplementacii ale preto robilo chyby lebo to bolo pred tym ako som pocital fragment size
    # message = cesar_cipher(message)
    # message = append_begin_end(message)
    # print("Cesar ciphered message: ", message)
    # ----------------------------

    working_message = message

    # message_to_send = struct.pack("!sHHHB", msg_type.encode(), msg_length, frag_count, frag_number, checksum_value) + message.encode()

    error = input("Do you want to introduce an error? (y/n): ")

    while True:
        if len(working_message) == 0:
            break

        while True:
            if len(working_message) == 0:
                break

            working_message = working_message[:fragment]
            msg_length = len(working_message)

            checksum_value = checksum(working_message)

            if error == "y":
                if checksum_value > 250:
                    checksum_value -= 1
                else:
                    checksum_value += 1

            message_to_send = struct.pack("!sHHHB", msg_type.encode(), msg_length, frag_count, frag_number, checksum_value) + working_message.encode()
            socket_client.sendto(message_to_send, server_ip)

            while True:
                data, FILLER = socket_client.recvfrom(1526)
                data_decoded = str(data, encoding=FORMAT)
                if data_decoded[:1] == DELIVERY_OK:
                    print(f"Fragment {frag_number} delivered successfully")
                    break
                elif data_decoded[:1] == ERROR_IN_DELIVERY:
                    print("Error in delivery")
                    print("Resending fragment...")
                    # if intentional error
                    if error == "y":
                        error = "n"

                    checksum_value = checksum(working_message)
                    message_to_send = struct.pack("!sHHHB", msg_type.encode(), msg_length, frag_count, frag_number, checksum_value) + working_message.encode()
                    socket_client.sendto(message_to_send, server_ip)
                else:
                    print("Unknown error")
                    print("Resending fragment...")

                    checksum_value = checksum(working_message)
                    message_to_send = struct.pack("!sHHHB", msg_type.encode(), msg_length, frag_count, frag_number, checksum_value) + working_message.encode()
                    socket_client.sendto(message_to_send, server_ip)

            frag_number += 1
            working_message = message[frag_number*fragment:]


def send_file(socket_client, server_ip):

    print(f"Your current directory is: {os.getcwd()}")
    file_path = input("Enter absolute path to file (with file name): ")
    fragment = int(input("Enter fragment size (10-1464): "))

    while True:
        if fragment < MIN_FRAGMENT_SIZE or fragment > MAX_FRAGMENT_SIZE:
            print("Invalid fragment size")
            fragment = int(input("Enter fragment size (10-1464): "))
        else:
            break

    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    print("File name: ", file_name)
    print(f"File size: {file_size} B")
    print("Absolute file path: ", file_path)
    file = open(file_path, "rb")

    number_of_fragments = math.ceil(file_size/fragment)
    print("Number of fragments: ", number_of_fragments)

    if number_of_fragments > 65535:
        print("Fragment size is too low for this file size")
        fragment = 1464
        print("Fragment size changed to 1464")
        number_of_fragments = math.ceil(file_size/fragment)
        print("New number of fragments: ", number_of_fragments)

    # if file size is bigger than 2MB
    if file_size >= 2000000:
        while True:
            big_file_msg = struct.pack("!s", FILE_BIGGER_THAN_2MB.encode()) + file_name.encode()
            socket_client.sendto(big_file_msg, server_ip)
            data_here, FILLER = socket_client.recvfrom(1526)
            data_decoded_here = str(data_here, encoding=FORMAT)
            if data_decoded_here[:1] == FILE_BIGGER_THAN_2MB:
                print("Big file check PASSED")
                break
            else:
                print("Big file check FAILED")
                print("Resending big file check...")

    message = file.read()
    message_to_send = None

    msg_type = SEND_FILE # 1B
    msg_length = 0 # 2B
    frag_count = number_of_fragments # 2B
    frag_number = 0 # 2B
    checksum_value = 0 # 1B

    working_message = message

    # message_to_send = struct.pack("!sHHHB", msg_type.encode(), msg_length, frag_count, frag_number, checksum_value) + message.encode()

    error = input("Do you want to introduce an error? (y/n): ")

    while True:
        if len(working_message) == 0:
            break

        while True:
            if len(working_message) == 0:
                break

            working_message = working_message[:fragment]
            msg_length = len(working_message)

            checksum_value = checksum_binary(working_message)

            if error == "y":
                if checksum_value > 250:
                    checksum_value -= 1
                else:
                    checksum_value += 1

            # should not need to encode message cuz it is already in bytes
            message_to_send = struct.pack("!sHHHB", msg_type.encode(), msg_length, frag_count, frag_number, checksum_value) + working_message
            socket_client.sendto(message_to_send, server_ip)

            while True:
                data, FILLER = socket_client.recvfrom(1526)
                data_decoded = str(data, encoding=FORMAT)
                if data_decoded[:1] == DELIVERY_OK:
                    print(f"Fragment {frag_number} delivered successfully")
                    break
                elif data_decoded[:1] == ERROR_IN_DELIVERY:
                    print("Error in delivery")
                    print("Resending fragment...")
                    # if intentional error
                    if error == "y":
                        error = "n"

                    checksum_value = checksum_binary(working_message)
                    message_to_send = struct.pack("!sHHHB", msg_type.encode(), msg_length, frag_count, frag_number, checksum_value) + working_message
                    socket_client.sendto(message_to_send, server_ip)
                else:
                    print("Unknown error")
                    print("Resending fragment...")
                    checksum_value = checksum_binary(working_message)
                    message_to_send = struct.pack("!sHHHB", msg_type.encode(), msg_length, frag_count, frag_number, checksum_value) + working_message
                    socket_client.sendto(message_to_send, server_ip)

            frag_number += 1
            working_message = message[frag_number*fragment:]


def receive(socket_server):

    global SERVER_WANTS_TO_SWITCH

    received_fragment_count = 0
    damaged_fragment_count = 0
    FRAG_COUNT = 999 # random number, it will change in the loop, but would not work without it
    message_or_file = None
    received_fragments = []

    file_name = None

    while True:
        if received_fragment_count == FRAG_COUNT:
            break

        while True:
            if received_fragment_count == FRAG_COUNT:
                break

            data, client_ip = socket_server.recvfrom(1526)

            # if the message is only 1B
            if len(data) <= 1:
                data_decoded = str(data.decode())

                if data_decoded == KEEP_ALIVE:
                    if SERVER_WANTS_TO_SWITCH:
                        print("Server wants to switch")
                        switched = switch_roles("server", socket_server, client_ip[0], client_ip[1])
                        if switched == "NO SWITCHING":
                            print("Switching roles canceled")
                            print("Continuing...")
                            SERVER_WANTS_TO_SWITCH = False
                            continue
                    else:
                        # print("Keep alive message received from: ", client_ip)
                        socket_server.sendto(str.encode(KEEP_ALIVE), client_ip)
                        continue
                elif data_decoded == SWITCH_ROLES:
                    print("Switching roles message received from: ", client_ip)
                    socket_server.sendto(str.encode(SWITCH_ROLES), client_ip)
                    print("Closing server program...")
                    socket_server.close()
                    Client(client_ip[0], SERVER_SWITCHING_PORT)

                    return
                elif data_decoded == TERMINATE_CONNECTION:
                    socket_server.sendto(str.encode(TERMINATE_CONNECTION), client_ip)
                    print("All terminated, closing main program")
                    socket_server.close()
                    sys.exit(10)
                else:
                    data_decoded = None

            else:
                data_decoded = data[:1].decode()

                if data_decoded == FILE_BIGGER_THAN_2MB:
                    print("Big file check received from: ", client_ip)
                    file_name = data[1:].decode()
                    # Debug print
                    print("File name: ", file_name)
                    socket_server.sendto(str.encode(FILE_BIGGER_THAN_2MB), client_ip)
                    continue
                else:
                    data_decoded = None

            message_fragment = data[8:]
            msg_type, msg_length, FRAG_COUNT, frag_number, checksum_value = struct.unpack("!sHHHB", data[:8])
            msg_type = msg_type.decode()
            this_checksum_value = None
            if msg_type == SEND_MESSAGE:
                this_checksum_value = checksum(message_fragment.decode())
            elif msg_type == SEND_FILE:
                this_checksum_value = checksum_binary(message_fragment)

            if this_checksum_value == checksum_value:
                print(f"Fragment {frag_number} received successfully")
                received_fragment_count += 1
                # moved a bit down
                # received_fragments.append(message_fragment.decode())
                socket_server.sendto(str.encode(DELIVERY_OK), client_ip)

                if msg_type == SEND_MESSAGE:
                    message_or_file = SEND_MESSAGE
                    # for message decode to string
                    received_fragments.append(message_fragment.decode())
                elif msg_type == SEND_FILE:
                    message_or_file = SEND_FILE
                    # for file save as bytes
                    received_fragments.append(message_fragment)
            else:
                print(f"Error in fragment {frag_number}")
                damaged_fragment_count += 1
                socket_server.sendto(str.encode(ERROR_IN_DELIVERY), client_ip)

    print("Message received successfully")
    print(f"Received {received_fragment_count + damaged_fragment_count} fragments (damaged included)")
    print(f"Damaged was {damaged_fragment_count} fragments")

    if message_or_file == SEND_MESSAGE:
        received_msg = ''.join(received_fragments)
        print("Received message: ", received_msg)
        print(f"Message length: {len(received_msg)}")
    elif message_or_file == SEND_FILE:
        if file_name is None:
            file_name = input("Enter file name: ")
        file_path = input("Enter (absolute) file path (if you want current directory enter '.'): ")
        if file_path == ".":
            file_path = os.getcwd()

        file = open(os.path.join(file_path, file_name), "wb")
        file.write(b''.join(received_fragments))
        file.close()
        print("File received successfully")
        file_size = os.path.getsize(os.path.join(file_path, file_name))
        print(f"File size: {file_size}B")
        print(f"Absolute file path: {os.path.join(file_path, file_name)}")
    else:
        pass


def main():
    print("Starting program...")

    while True:
        choice = input("""Enter your option: 
1 - Server
2 - Client
3 - Quit
""")

        if choice == "1":
            Server(None)
        elif choice == "2":
            Client(None, None)
        elif choice == "3":
            print("Closing program...")
            sys.exit(20)
        else:
            print("Invalid input, try again")


if __name__ == "__main__":
    main()
