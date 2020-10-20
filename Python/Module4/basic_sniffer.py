import socket

# Init: Create the sniffer raw socket object
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

# Bind it o localhost
sniffer.bind(('0.0.0.0', 0))

# Ensure the IP header is included
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
print("Sniffer is listening for incoming connections")

# Get a single packet
print(sniffer.recvfrom(65535))

