# Mahdi Rahbar
# ---------------------------------------------------------------------------------------------------
import sys
import time
import random
import select
import struct
import socket
import argparse

# ------------------------- Implementation of ICMP --------------------------------------------------

# Definition of variables and error descriptions related to ICMP request and module functions
ICMP_ECHO_REQUEST = 8
ICMP_CODE = socket.getprotobyname('icmp')
ERROR_DESCR = {
    1: ' - Note that ICMP messages can only be '
       'sent from processes running as root.',
    10013: ' - Note that ICMP messages can only be sent by'
           ' users or processes with administrator rights.'
    }
__all__ = ['create_packet', 'do_one', 'verbose_ping', 'PingQuery',
           'multi_ping_query']


# Checksum calculation for a source string in binary form using One's Complement algorithm
def calculate_checksum(data):
    checksum = 0
    length = (len(data) // 2) * 2
    index = 0

    while index < length:
        value = data[index + 1] * 256 + data[index]
        checksum += value
        index += 2

        checksum &= 0xffffffff

    if length < len(data):
        checksum += ord(data[len(data) - 1])
        checksum &= 0xffffffff

    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += (checksum >> 16)

    final_checksum = ~checksum
    final_checksum &= 0xffff
    final_checksum = (final_checksum >> 8) | ((final_checksum << 8) & 0xff00)

    return final_checksum


# Create an ICMP echo request packet with a specified ID, including header, data, and checksum calculation
def create_icmp_packet(packet_id):

    packet_header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, packet_id, 1)
    packet_data = 192 * 'Q'

    calculated_checksum = calculate_checksum(packet_header + packet_data.encode())

    packet_header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0,
                                socket.htons(calculated_checksum), packet_id, 1)

    return packet_header + packet_data.encode()


# Send a single ICMP ping to the specified destination address
# and return the delay in seconds or None on timeout or error
def send_ping(destination_address, timeout_duration=1):

    try:
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)

    except socket.error as error:
        if error.errno in ERROR_DESCR:
            raise socket.error(''.join((error.args[1], ERROR_DESCR[error.errno])))
        raise

    try:
        resolved_host = socket.gethostbyname(destination_address)
    except socket.gaierror:
        return None

    packet_id = int((id(timeout_duration) * random.random()) % 65535)
    packet = create_icmp_packet(packet_id)

    while packet:
        bytes_sent = icmp_socket.sendto(packet, (destination_address, 1))
        packet = packet[bytes_sent:]

    response_delay = receive_ping(icmp_socket, packet_id, time.time(), timeout_duration)
    icmp_socket.close()
    return response_delay



# Receive an ICMP ping response from the specified socket and return the delay if matching ID is found
def receive_ping(icmp_socket, packet_id, sent_time, timeout_duration):
    time_remaining = timeout_duration

    while True:
        select_start_time = time.time()
        ready = select.select([icmp_socket], [], [], time_remaining)
        time_spent_in_select = time.time() - select_start_time

        if ready[0] == []:
            return None

        receive_time = time.time()
        received_packet, address = icmp_socket.recvfrom(1024)
        icmp_header = received_packet[20:28]
        icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_sequence = struct.unpack('bbHHh', icmp_header)

        if icmp_id == packet_id:
            return receive_time - sent_time

        time_remaining -= receive_time - sent_time
        if time_remaining <= 0:
            return None
# -----------------------------------------------------------------------------------------------------------------

def check_host_status(host):
    delay = send_ping(host)
    if delay is not None:
        print(f"{host} is online")
    else:
        print(f"{host} is offline")

def main():


    parser = argparse.ArgumentParser(description="Ping a host to check if it's online or offline")
    parser.add_argument("host", type=str, help="IP address or hostname of the host to ping")
    args = parser.parse_args()
    
    check_host_status(args.host)

if __name__ == "__main__":
    main()