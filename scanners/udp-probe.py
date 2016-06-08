#!/usr/bin/python
"""
UDP Service Scanner version 0.1 by dev_zzo

This work has largely been inspired by:
https://github.com/portcullislabs/udp-proto-scanner

As is, this is more like a prober than scanner;
it operates using predefined probes for each known protocol.

"""

import argparse
import socket
import struct
import time

__scan_spec = (
    # port, service name, probe
    (53,    'DNSStatusRequest', "\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    (53,    'DNSVersionBindReq', "\x00\x06\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x76\x65\x72\x73\x69\x6f\x6e\x04\x62\x69\x6e\x64\x00\x00\x10\x00\x03"),

    (69,    'tftp', "\x00\x01/etc/passwd\x00netascii\x00"),

    (111,   'rpc',      "\x03\x9b\x65\x42\x00\x00\x00\x00\x00\x00\x00\x02\x00\x0f\x42\x43\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    (111,   'RPCCheck', "\x72\xFE\x1D\x13\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xA0\x00\x01\x97\x7C\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),

    (123,   'ntp', "\xcb\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbf\xbe\x70\x99\xcd\xb3\x40\x00"),
    (123,   'NTPRequest', "\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc5\x4f\x23\x4b\x71\xb1\x52\xf3"),

    (137,   'NBTStat', "\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"),

    (161,   'snmp-public', "\x30\x82\x00\x2f\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x82\x00\x20\x02\x04\x4c\x33\xa7\x56\x02\x01\x00\x02\x01\x00\x30\x82\x00\x10\x30\x82\x00\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x05\x00\x05\x00"),
    (161,   'SNMPv3GetRequest', "\x30\x3a\x02\x01\x03\x30\x0f\x02\x02\x4a\x69\x02\x03\x00\xff\xe3\x04\x01\x04\x02\x01\x03\x04\x10\x30\x0e\x04\x00\x02\x01\x00\x02\x01\x00\x04\x00\x04\x00\x04\x00\x30\x12\x04\x00\x04\x00\xa0\x0c\x02\x02\x37\xf0\x02\x01\x00\x02\x01\x00\x30\x00"),

    (177,   'xdmcp', "\x00\x01\x00\x02\x00\x01\x00\x00"),
    (500,   'ike', "\x5b\x5e\x64\xc0\x3e\x99\xb5\x11\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x01\x50\x00\x00\x01\x34\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x01\x28\x01\x01\x00\x08\x03\x00\x00\x24\x01\x01"),

    (523,   'db2', "DB2GETADDR\x00SQL08020"),

    (1434,  'ms-sql', "\x02"),
    (1434,  'ms-sql-slam', "\x0A"),

    (1604,  'citrix', "\x1e\x00\x01\x30\x02\xfd\xa8\xe3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    (5405,  'net-support', "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    (6502,  'netop', "\xd6\x81\x81\x52\x00\x00\x00\xf3\x87\x4e\x01\x02\x32\x00\xa8\xc0\x00\x00\x01\x13\xc1\xd9\x04\xdd\x03\x7d\x00\x00\x0d\x00\x54\x48\x43\x54\x48\x43\x54\x48\x43\x54\x48\x43\x54\x48\x43\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x02\x32\x00\xa8\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
)

def ip2long(ipaddr):
    return long(struct.unpack('!L', socket.inet_aton(ipaddr))[0])
def long2ip(ipaddr):
    return socket.inet_ntoa(struct.pack('!L', ipaddr))

def __dump_bytes(data):
    return ' '.join([('%02X' % ord(x)) for x in data])
def __dump_chars(data):
    return ''.join([(x if 0x20 <= ord(x) < 0x80 else '.') for x in data])
def dump(data):
    i = 0
    lines = []
    while i < len(data):
        line = data[i:(i + 16)]
        p1 = __dump_bytes(line[:8])
        p2 = __dump_bytes(line[8:]) if len(line) > 8 else ''
        lines.append('%08X  %-24s %-24s %s' % (i, p1, p2, __dump_chars(line)))
        i += 16
    return "\n".join(lines)

def parse_targets(targets):
    "Parse the target specs provided by the user"

    results = []

    for target_spec in targets:
        if '/' in target_spec:
            # a.b.c.d/m ?
            net_addr, net_mask = target_spec.split('/')
            net_addr = ip2long(net_addr)
            net_mask = int(net_mask)
            dev_mask = (1 << (32 - net_mask)) - 1
            net_addr = net_addr & ~dev_mask

            # First address is not allocated, last address is broadcast
            for i in xrange(1, dev_mask):
                addr = long2ip(net_addr + i)
                results.append(addr)

        elif '-' in target_spec:
            # a.b.c.d-e.f.g.h ?
            start_addr, end_addr = target_spec.split('-')
            addr = ip2long(start_addr)
            end_addr = ip2long(end_addr)
            while addr <= end_addr:
                addr = long2ip(a)
                results.append(addr)
                addr += 1

        else:
            addr = ip2long(target_spec)
            results.append(target_spec)

    return results

def scan_main(args):
    "Main scanning routine"
    global __scan_spec

    targets = parse_targets(args.targets)
    responses = {}

    print("Starting scan.")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', 57022))

    try:
        for port, name, probe in __scan_spec:
            print("Running probe '%s'..." % name)

            s.settimeout(None)
            for target in targets:
                s.sendto(probe, (target, port))
            s.settimeout(0.0)

            # print("Waiting for replies...")
            time.sleep(args.delay)

            while True:
                try:
                    response, addr = s.recvfrom(16384)
                    # print("Response from %s:%d" % addr)
                    try:
                        target_responses = responses[addr]
                    except KeyError:
                        target_responses = responses[addr] = {}
                    target_responses[name] = response

                except socket.error as e:
                    # http://stackoverflow.com/a/2578794/1654774
                    # ICMP Port Unreachable can't be handled properly. :-(
                    if e.args[0] in (11, 10035):
                        break
                    if e.args[0] not in (10054):
                        raise
    finally:
        s.close()
    print("Scan completed.")

    for addr, target_responses in responses.iteritems():
        print('')
        print('=' * 76)
        print("Report for %s:" % addr[0])
        print('=' * 76)
        for name, response in target_responses.iteritems():
            print('')
            print("Probe: %s, port: %d" % (name, addr[1]))
            print(dump(response))

def __main():
    print('\nUDP Service Scanner version 0.1\n')

    parser = argparse.ArgumentParser(description='UDP Service Scanner')
    parser.add_argument('targets', metavar='target', nargs='+',
        help='IP address or range (ip/mask, ip-ip)')
    parser.add_argument('--delay',
        type=float,
        default=1.0,
        help='Time to wait (seconds) before moving on to the next probe')
    args = parser.parse_args()
    scan_main(args)

if __name__ == '__main__':
    __main()
