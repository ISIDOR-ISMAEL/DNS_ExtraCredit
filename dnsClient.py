import argparse
import socket
import struct


# Useful resources to solve this lab:
# 1. https://datatracker.ietf.org/doc/html/rfc1034
# 2. https://datatracker.ietf.org/doc/html/rfc1035
# 3. Kurose/Ross Book!

def parse_name(data, offset):
    name_parts = []
    while True:
        length = data[offset]
        offset += 1
        if length == 0:
            break
        elif length & 0xc0 == 0xc0:
            pointer = struct.unpack('!H', data[offset - 1:offset + 1])[0] & 0x3fff
            name_parts.append(parse_name(data, pointer))
            break
        else:
            label = data[offset:offset + length].decode('ascii')
            offset += length
            name_parts.append(label)
    return '.'.join(name_parts)


def dns_query(type, name, server):
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (server, 53)  # Enter Port Number

    # Create the DNS query
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

    header = struct.pack('!HHHHHH', ID,
                         QR << 15 | OPCODE << 11 | AA << 10 | TC << 9 | RD << 8 | RA << 7 | Z << 4 | RCODE, QDCOUNT,
                         ANCOUNT, NSCOUNT, ARCOUNT)

    # Encode the QNAME
    qname_parts = name.split('.')
    qname_encoded_parts = [struct.pack('B', len(part)) + part.encode('ascii') for part in qname_parts]
    qname_encoded = b''.join(qname_encoded_parts) + b'\x00'

    # Encode the QTYPE and QCLASS
    if type == 'A':
        qtype = 1
    elif type == 'AAAA':
        qtype = 28
    else:
        raise ValueError('Invalid type')

    qclass = 1

    question = qname_encoded + struct.pack('!HH', qtype, qclass)

    # Send the query to the server
    message = header + question
    sent = sock.sendto(message, server_address)

    # Receive the response from the server
    data, _ = sock.recvfrom(4096)

    # Parse the response header
    response_header = data[:12]
    ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT = struct.unpack('!HHHHHH', response_header)

    # Parse the response question section (same as query)
    response_question = data[12:12 + len(question)]
    assert response_question == question

    # Parse the response answer section
    response_answer = data[12 + len(question):]
    offset = 0
    answers = []
    for _ in range(ANCOUNT):
        # Parse the name
        name_parts = []
        while True:
            length = response_answer[offset]
            offset += 1
            if length == 0:
                break
            elif length & 0xc0 == 0xc0:
                pointer = struct.unpack('!H', response_answer[offset - 1:offset + 1])[0] & 0x3fff
                name_parts.append(parse_name(data, pointer))
                break
            else:
                label = response_answer[offset:offset + length].decode('ascii')
                offset += length
                name_parts.append(label)
        name = '.'.join(name_parts)

        # Parse the type, class, TTL, and RDLENGTH
        type, cls, ttl, rdlength = struct.unpack('!HHIH', response_answer[offset:offset + 10])
        offset += 10

        # Parse the RDATA
        rdata = response_answer[offset:offset + rdlength]
        offset += rdlength

        if type == 1:  # A record (IPv4)
            ip_address = socket.inet_ntoa(rdata)
            answers.append(ip_address)
        elif type == 28:  # AAAA record (IPv6)
            ip_address = socket.inet_ntop(socket.AF_INET6, rdata)
            answers.append(ip_address)
        else:
            answers.append(rdata)

    return answers