# Simple Nmap Implementation 

This project is a simplified implementation of some functionalities of the `nmap` tool, developed as part of a university **Computer Networks** course. The program allows users to perform **ping sweeps**, **port scanning**, **traceroute**, and **HTTP GET/POST requests** to interact with a simple server.

## Features

- **Ping a host** to check if it is online.
- **Port scanning** to detect open ports and associated services.
- **Traceroute** to determine the path packets take to a destination.
- **HTTP GET and POST requests** to interact with a simulated server.

## Requirements

- Python 3.x
- Administrator/root privileges (for sending ICMP packets)
- The `socket` and `argparse` modules (included in Python standard library)

## Installation

Clone this repository or download the `nmap.py` file.

```bash
git clone https://github.com/your-username/nmap-project.git
cd nmap-project
```

## Usage

### 1. Ping a Host

Check if a host is online by sending an ICMP echo request.

```bash
python nmap.py example.com
```

Example:

```bash
python nmap.py 8.8.8.8
```

### 2. Port Scanning

Scan a specific port or a range of ports.

```bash
python nmap.py example.com 22 80 443
python nmap.py example.com 20-25
```

Example:

```bash
python nmap.py 192.168.1.1 22 80 443
```

### 3. Traceroute

Perform a traceroute to see the network path to a host.

```bash
python nmap.py -t example.com
```

Example:

```bash
python nmap.py -t google.com
```

### 4. Reading Hosts from a File

Scan multiple hosts listed in a text file.

```bash
python nmap.py -rf hosts.txt
```

Example (`test.txt` contains):

```
8.8.8.8
1.1.1.1
example.com
```

### 5. Simulating HTTP GET and POST Requests

To interact with the simulated server, use the `-s` flag.

#### Start Server Interaction Mode

```bash
python nmap.py -s
```

#### GET Request Example

```
Enter 'GET user_id' or 'POST user_name user_age' to simulate a request: GET user1
```

#### POST Request Example

```
Enter 'GET user_id' or 'POST user_name user_age' to simulate a request: POST John 28
```

## Notes

- Running the script **requires administrator privileges** to send ICMP packets.
- The server must be running for HTTP GET/POST interactions.
