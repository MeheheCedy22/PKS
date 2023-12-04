# Implementing a simple reliable data transfer protocol over UDP
# Protocol name: Dzabede Nesta Protocol (DNP)
# Protocol server default: Port 18080
# Protocol client default: Port 18081

# Zmeny:
# zmena fragment number = fragement count
# zmena fragment offset = number of teh current fragment

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


import socket
import threading
import concurrent.futures
import os
import hashlib
import struct
import sys
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


def switch_roles():
    pass


def server_choice():
    print("Enter your option: ")
    print("1 - Switch roles")
    print("2 - Quit")
    print("Press whatever to continue")

    choice = input()
    return choice


def Server():
    # first connection
    socket_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    SERVER_IP = socket.gethostbyname(socket.gethostname())
    print("Server IP: ", SERVER_IP)
    port = int(input("Enter port: "))
    socket_server.bind(("", port))
    data, client_ip = socket_server.recvfrom(1526) # max eth frame size including preamble etc.
    socket_server.sendto(str.encode(ESTABLISH_CONNECTION), client_ip)
    print("Connection established with: ", client_ip)

    # server running
    while True:
        choice = server_choice()
        if choice == "1":
            print("Switching roles...")

        elif choice == "2":
            print("Closing server program...")
            return

        else:
            print("Nothing changed, continuing...")

        # while True:
        #     while True:
        #         data, client_ip = socket_server.recvfrom(1526)
        #         data_decoded = str(data.decode())
        #
        #         if data_decoded == KEEP_ALIVE:
        #             print("Keep alive message received from: ", client_ip)
        #             socket_server.sendto(str.encode(KEEP_ALIVE), client_ip)
        #             break
        #         else:
        #             break
        #
        #     msg_type = data_decoded[:1]
        #     if msg_type == SEND_MESSAGE:
        #         print(f"Message {data_decoded[8:]} received from: {client_ip}")
        #
        #         break
        #     if msg_type == SEND_FILE:
        #         print("File received from: ", client_ip)
        #
        #         socket_server.sendto(str.encode(DELIVERY_OK), client_ip)
        #         break

        receive(socket_server)


def client_choice():
    print("Enter your option: ")
    print("1 - Send message")
    print("2 - Send file")
    print("3 - Switch roles")
    print("4 - Quit")

    choice = input()
    return choice


def Client():

    while True:
        socket_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        CLIENT_IP = socket.gethostbyname(socket.gethostname())
        print("Client IP: ", CLIENT_IP)
        port = int(input("Enter port: "))
        SERVER_IP_FOR_CLIENT = input("Enter server IP: ")
        server_ip_and_port = (SERVER_IP_FOR_CLIENT, port)
        socket_client.sendto(str.encode(ESTABLISH_CONNECTION), server_ip_and_port)
        data, server_ip = socket_client.recvfrom(1526)
        data_decoded = str(data, encoding=FORMAT)

        if data_decoded == ESTABLISH_CONNECTION:
            print("Connection established with: ", server_ip)

            # turn on keep alive thread
            keep_alive_thread = threading.Thread(target=keep_alive, args=(socket_client, server_ip), daemon=True)
            keep_alive_thread.start()

            while True:
                choice = client_choice()

                if choice == "1": # send message
                    print("Sending message...")
                    send_message(socket_client, server_ip)

                elif choice == "2": # send file
                    print("Sending file...")
                    send_file(socket_client, server_ip)
                elif choice == "3": # switch roles
                    print("Switching roles...")

                elif choice == "4": # quit
                    print("Closing client program...")
                    if keep_alive_thread.is_alive():
                        keep_alive_thread.join()
                    return
                else:
                    print("Nothing changed, continuing...")


def keep_alive(socket_client, server_ip):

    while True:
        socket_client.sendto(str.encode(KEEP_ALIVE), server_ip)
        data, FILLER = socket_client.recvfrom(1526)
        data_decoded = str(data, encoding=FORMAT)

        if data_decoded == KEEP_ALIVE:
            print("Keep alive message received from: ", server_ip)
        else:
            print("Keep alive message not received from: ", server_ip)
            print("Ending connection...")
            break
        time.sleep(KEEP_ALIVE_INTERVAL)


def send_message(socket_client, server_ip):

    message = input("Enter your message: ")
    fragment = int(input("Enter fragment size (10-1464): "))

    while True:
        if fragment < MIN_FRAGMENT_SIZE or fragment > MAX_FRAGMENT_SIZE:
            print("Invalid fragment size")
            fragment = int(input("Enter fragment size (10-1464): "))
        else:
            break

    number_of_fragments = math.ceil(len(message)/fragment)
    print("Number of fragments: ", number_of_fragments)

    message_to_send = None

    msg_type = SEND_MESSAGE # 1B
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

            # decode to string only for checksum
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

    received_fragment_count = 0
    damaged_fragment_count = 0
    FRAG_COUNT = 999 # random number
    message_or_file = None
    received_fragments = []

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
                    print("Keep alive message received from: ", client_ip)
                    socket_server.sendto(str.encode(KEEP_ALIVE), client_ip)
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
            Server()
        elif choice == "2":
            Client()
        elif choice == "3":
            print("Closing program...")
            break
        else:
            print("Invalid input, try again")


if __name__ == "__main__":
    main()
