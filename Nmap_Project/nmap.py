# Mahdi Rahbar
# ---------------------------------------------------------------------------------------------------
import sys
import time
import random
import select
import struct
import socket
import argparse


COMMON_PORTS = {
    80: "http",
    443: "https",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    110: "pop3",
    143: "imap",
    194: "irc",
    3306: "mysql",
    8080: "http-proxy",
}

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
        checksum += data[len(data) - 1]
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
def send_ping(destination_address, timeout_duration=1, ttl=30):
    try:
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
        icmp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        icmp_socket.settimeout(timeout_duration)

    except socket.error:
        raise

    try:
        socket.gethostbyname(destination_address)

    except socket.gaierror:
        return None, None


    packet_id = int((id(timeout_duration) * random.random()) % 65535)
    packet = create_icmp_packet(packet_id)

    send_time = time.perf_counter()
    icmp_socket.sendto(packet, (destination_address, 1))

    response_delay, response_address = receive_ping(icmp_socket, send_time, timeout_duration)

    icmp_socket.close()

    return (response_delay, response_address) if response_delay is not None else (None, None)




# Receive an ICMP ping response from the specified socket and return the delay if matching ID is found
def receive_ping(icmp_socket, sent_time, timeout_duration):
    time_remaining = timeout_duration

    while True:
        select_start_time = time.perf_counter()
        ready = select.select([icmp_socket], [], [], time_remaining)
        time_spent_in_select = time.perf_counter() - select_start_time

        if ready[0] == []:
            return None, None

        receive_time = time.perf_counter()
        received_packet, address = icmp_socket.recvfrom(1024)


        icmp_header = received_packet[20:28]
        icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_sequence = struct.unpack('bbHHh', icmp_header)

        if icmp_type == 0 or icmp_type == 11:

            return (receive_time - sent_time) * 1000, address[0]


        time_remaining -= time_spent_in_select
        if time_remaining <= 0:

            return None, None

# -----------------------------------------------------------------------------------------------------------------

# Ping the host to check if it is online or offline.
def check_host_status(host):
    delay, response_address = send_ping(host)

    if delay is not None and response_address is not None:
        print(f"{host} is online")
        return True
    else:
        print(f"{host} is offline")
        return False


# Parse port input, supporting both individual ports and ranges.
def parse_ports(port_args):
    ports = set()
    for port_arg in port_args:
        if '-' in port_arg:
            start_port, end_port = map(int, port_arg.split('-'))
            ports.update(range(start_port, end_port + 1))
        else:
            ports.add(int(port_arg))
    return sorted(ports)


# Scan a list of ports on the specified host, print open ports and associated services,
# and calculate average response time for a specified number of requests.
def scan_ports(host, ports, requests=1):

    for port in ports:

        total_delay = 0
        successful_responses = 0

        for _ in range(requests):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            start_time = time.perf_counter()
            result = sock.connect_ex((host, port))
            end_time = time.perf_counter()
            sock.close()

            if result == 0:
                successful_responses += 1
                delay = end_time - start_time
                total_delay += delay
                service_name = COMMON_PORTS.get(port, "unknown")
                hostname = socket.getfqdn(host)
                print(f"open port detected: {host}      --port: {port}       --service: {service_name}        --hostname: {hostname}")


        if successful_responses > 0:
            average_delay = (total_delay / successful_responses) * 1000
            print(f"Average response time for port {port}: {average_delay:.2f} "
                  f"ms over {successful_responses} successful responses.")



# Performs a traceroute to the specified host
def traceroute(host, max_hops=30, timeout_duration=1):
    print(f"Traceroute to {host} with max {max_hops} hops:\n")

    try:
        destination_ip = socket.gethostbyname(host)
    except socket.gaierror:
        print("Unable to resolve host.")
        return

    timeouts = 0

    for ttl in range(1, max_hops + 1):
        delay, address = send_ping(destination_ip, timeout_duration, ttl)

        if address is None:
            print(f"{ttl}\t*")
            timeouts += 1

            if timeouts == 7:
                print("Host seems to be offline. Traceroute stopped.")
                break


        else:
            timeouts = 0
            print(f"{ttl}\t{address}\t{delay:.2f} ms")

            if address == destination_ip:
                print("Reached the destination!")
                break



# Constructs and sends a GET request for the specified user ID.
def send_get_request(user_id):
    request = f"GET /{user_id} HTTP/1.1\r\nHost: localhost\r\n\r\n"
    return send_request(request)


# Constructs and sends a POST request to add a new user with the specified name and age.
def send_post_request(name, age):
    request = f"POST / HTTP/1.1\r\nHost: localhost\r\n\r\n{name} {age}"
    return send_request(request)


# Sends a given HTTP request to the server and returns the response.
def send_request(request):
    host = 'localhost'
    port = 8080

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    client_socket.sendall(request.encode())

    response = client_socket.recv(1024).decode()
    client_socket.close()
    return response



# Handles user interaction with the server.
def server_interaction():

    while True:
        command = input("Enter 'GET user_id' or 'POST user_name user_age' to simulate a request: ")
        parts = command.strip().split()

        if len(parts) == 2 and parts[0].upper() == 'GET':
            user_id = parts[1]
            response = send_get_request(user_id)
            print(response)

        elif len(parts) == 3 and parts[0].upper() == 'POST':
            user_name = parts[1]
            try:
                user_age = int(parts[2])
                response = send_post_request(user_name, user_age)
                print(response)
            except ValueError:
                print("Invalid age. Please enter an integer for age.")
        else:
            print("Invalid command. Please try again.")


        if command.lower() in ['exit', 'quit']:
            print("Exiting server interaction...")
            break



def main():

    print("\n")


    parser = argparse.ArgumentParser(description="Ping a host and check open ports.")
    parser.add_argument("host", type=str, nargs='?', help="IP address or hostname of the host to ping.")
    parser.add_argument("ports", nargs="*", help="List of ports or ranges to scan, separated by space.")
    parser.add_argument("-r", "--requests", type=int, default=1,
                        help="Number of requests to send per port for calculating average response time")
    parser.add_argument("-rf", "--readfile", type=str, help="Input file containing list of hosts")
    parser.add_argument("-t", "--traceroute", action="store_true", help="Perform a traceroute to the specified host")
    parser.add_argument("-s", "--server", action="store_true",
                        help="Interact with server through GET/POST simulation")
    args = parser.parse_args()




    if args.server:
        server_interaction()
        return

    if args.traceroute and args.host:
        traceroute(args.host)

    elif args.readfile:

        with open(args.readfile, "r") as file:
            hosts = [line.strip() for line in file if line.strip()]
            for host in hosts:
                if check_host_status(host):
                    scan_ports(host, COMMON_PORTS.keys(), args.requests)
                print("-" * 120)
    else:

        if args.host and check_host_status(args.host):
            ports_to_scan = parse_ports(args.ports) if args.ports else COMMON_PORTS.keys()
            scan_ports(args.host, ports_to_scan, args.requests)


    print("\n")


if __name__ == "__main__":
    main()
