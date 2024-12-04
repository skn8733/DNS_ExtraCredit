import argparse
import socket
import struct

# Useful resources to solve this lab:
# 1. https://datatracker.ietf.org/doc/html/rfc1034
# 2. https://datatracker.ietf.org/doc/html/rfc1035
# 3. Kurose/Ross Book!

def dns_query(type, name, server):
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (server, 53)  # DNS typically uses port 53 for UDP

    # DNS Header construction
    ID = 0x1234
    QR = 0
    OPCODE = 0
    AA = 0
    TC = 0
    RD = 1
    RA = 0
    Z = 0
    RCODE = 0
    QDCOUNT = 1
    ANCOUNT = 0
    NSCOUNT = 0
    ARCOUNT = 0
    
     # The DNS header is a fixed-size (12 bytes), containing several fields with information about the query. These fields are packed into a binary string in network byte order 
        # The values of these fields are combined using bitwise operations (<< for left shift and | for bitwise OR) to form a single 16-bit value, which is then packed into the binary string.
        
        # You are responsible for making sure each value is in the right location!
            
        # Each row in the diagram represents one byte (8 bits) of data, with the bit positions numbered along the top. 
        # The fields in the DNS header are labeled and their sizes and positions are indicated by the boxes.

        # DNS Header Format (12 bytes / 96 bits)
        #
        # 0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |                      MessageID                 |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # |QR|   Opcode    |AA|TC|RD|RA| Reserved | RCODE  |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+------+ 
        # |                    QDCount                     |
        # +------+-----+-----+-----+-----+-----+-----+-----+
        # |                    ANCount                     |
        # +------+-----+-----+-----+-----+-----+-----+-----+
        # |                    NSCount                     |
        # +------+-----+-----+-----+-----+-----+-----+-----+
        # |                    ARCount                     |
        # +------+-----+-----+-----+-----+-----+-----+-----+


        # Message ID: 16 bits
        # QR (Query/Response): 1 bit
        # Opcode: 4 bits
        # AA (Authoritative Answer): 1 bit
        # TC (Truncated): 1 bit
        # RD (Recursion Desired): 1 bit
        # RA (Recursion Available): 1 bit
        # Z: 3 bits
        # Rcode (Response Code): 4 bits
        # QDCount (Question Count): 16 bits
        # ANCount (Answer Count): 16 bits
        # NSCount (Authority Count): 16 bits
        # ARCount (Additional Count): 16 bits
        
        # Example: The QR field is located in the second byte of the DNS header, with its most significant bit being the leftmost bit of this byte. Since each byte contains 8 bits, shifting the value of the QR field left by 15 bits moves it to the correct position in the 16-bit value that represents the combination of several fields in the DNS header.

    # The DNS header is packed as follows:
    # struct.pack('!HHHHHH', ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)
    FLAGS = (QR << 15) | (OPCODE << 11) | (AA << 10) | (TC << 9) | (RD << 8) | (RA << 7) | (Z << 4) | RCODE
    header = struct.pack('!HHHHHH', ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

    # Encode the QNAME
    # Example: www.nyu.edu -> [b'\x03', b'www', b'\x03', b'nyu', b'\x03', b'edu', b'\x00']
    qname_parts = name.split('.')
    qname_encoded_parts = [struct.pack('B', len(part)) + part.encode('ascii') for part in qname_parts]
    qname_encoded = b''.join(qname_encoded_parts) + b'\x00'  # Null byte to end the QNAME

    # Lookup QTYPE and QCLASS for A and AAAA
    if type == 'A':
        qtype = 1  # Type A (IPv4 address)
    elif type == 'AAAA':
        qtype = 28  # Type AAAA (IPv6 address)
    else:
        raise ValueError('Invalid type')

    qclass = 1  # Class IN (Internet)

    # The question section is the QNAME followed by QTYPE and QCLASS
    question = qname_encoded + struct.pack('!HH', qtype, qclass)

    # Send the query to the server
    message = header + question
    sock.sendto(message, server_address)

    # Receive the response from the server
    data, _ = sock.recvfrom(4096)

    # Parse the response header (12 bytes)
    response_header = data[:12]
    ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT = struct.unpack('!HHHHHH', response_header)

    # Check if response matches the query
    response_question = data[12:12+len(question)]
    assert response_question == question, "Question section mismatch"

    # Parse the response answer section
    response_answer = data[12+len(question):]
    offset = 0
    for _ in range(ANCOUNT):
        # Parse the name
        name_parts = []
        while True:
            length = response_answer[offset]
            offset += 1
            if length == 0:
                break
            elif length & 0xc0 == 0xc0:
                # Pointer
                pointer = struct.unpack('!H', response_answer[offset-1:offset+1])[0] & 0x3fff
                offset += 1
                name_parts.append(parse_name(data, pointer))
                break
            else:
                # Label
                label = response_answer[offset:offset+length].decode('ascii')
                offset += length
                name_parts.append(label)
        name = '.'.join(name_parts)

        # Parse the type, class, TTL, and RDLENGTH
        type, cls, ttl, rdlength = struct.unpack('!HHIH', response_answer[offset:offset+10])
        offset += 10

        # Parse the RDATA (IPv4 or IPv6 address)
        rdata = response_answer[offset:offset+rdlength]
        offset += rdlength

        if type == 1:  # A record (IPv4 address)
            ipv4 = socket.inet_ntop(socket.AF_INET, rdata)
            print(f'{name} has IPv4 address {ipv4}')
            return ipv4
        elif type == 28:  # AAAA record (IPv6 address)
            ipv6 = socket.inet_ntop(socket.AF_INET6, rdata)
            print(f'{name} has IPv6 address {ipv6}')
            return ipv6

def parse_name(data, offset):
    name_parts = []
    while True:
        length = data[offset]
        offset += 1
        if length == 0:
            break
        elif length & 0xc0 == 0xc0:
            # Pointer
            pointer = struct.unpack('!H', data[offset-1:offset+1])[0] & 0x3fff
            offset += 1
            name_parts.append(parse_name(data, pointer))
            break
        else:
            # Label
            label = data[offset:offset+length].decode('ascii')
            offset += length
            name_parts.append(label)
    return '.'.join(name_parts)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Send a DNS query and parse the reply.')
    parser.add_argument('--type', choices=['A', 'AAAA'], required=True, help='the type of address requested')
    parser.add_argument('--name', required=True, help='the host name being queried')
    parser.add_argument('--server', required=True, help='the IP address of the DNS server to query')
    args = parser.parse_args()

    result = dns_query(args.type, args.name, args.server)
