#
# Based on https://gist.github.com/andreif/6069838
# Requres: dnslib ( https://bitbucket.org/paulc/dnslib )
#

import argparse
import datetime
import sys
import time
import threading
import traceback
import SocketServer
from dnslib import *

#
# Begin of editable data
#

EVIL_SOA_RECORD = SOA(
    # primary name server
    mname="ns1.pwnage.local",
    # email of the domain administrator
    rname="pwner@pwnage.local",
    times=(
        6660666,  # serial number
        60 * 60 * 1,  # refresh
        60 * 60 * 3,  # retry
        60 * 60 * 24,  # expire
        60 * 60 * 1,  # minimum
    )
)

EVIL_DNS_RECORDS = {
    # MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
    'example.com.': [A('127.0.0.1'), AAAA((0,) * 16), MX('mail.example.com.')],
    'ns.example.com.': [A('127.0.0.2')],
    'mail.example.com.': [A('127.0.0.3')],
}

#
# End of editable data
#

TTL = 60 * 5

def log(text):
    "Logging function"

    ts = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    line = '[%s] %s' % (ts, text)
    print line

class BaseRequestHandler(SocketServer.BaseRequestHandler):
    "Base class for handling DNS requests"

    def get_proto(self):
        return self.__class__.__name__[:3]

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        try:
            data = self.get_data()
            reply_data = self._handle(data)
            if reply_data is not None:
                self.send_data(reply_data)
                log("Reply sent.")

        except Exception:
            traceback.print_exc(file=sys.stderr)

    def _handle(self, data):
        "Actually handles the DNS request"

        request = DNSRecord.parse(data)

        log("%s REQUEST (%s:%d):" % (self.get_proto(), self.client_address[0], self.client_address[1]))
        print "\n" + str(request) + "\n"

        q = request.q
        qname = str(q.qname)
        qtype = QTYPE[q.qtype]

        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=q)

        entry = EVIL_DNS_RECORDS.get(qname)
        if entry is not None:
            # Check the entry for any requested records
            for rdata in entry:
                # This is really ugly code...
                rtype = getattr(QTYPE, rdata.__class__.__name__)
                if qtype in ['*', QTYPE[rtype]]:
                    reply.add_answer(RR(rname=qname, rtype=rtype, rclass=1, ttl=TTL, rdata=rdata))
            # Add authority record
            reply.add_auth(RR(rname=qname, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=EVIL_SOA_RECORD))

        else:
            log("qname '%s' not found" % qname)

        log("%s REPLY:" % (self.get_proto()))
        print "\n" + str(reply) + "\n"

        return reply.pack()

class TCPRequestHandler(BaseRequestHandler):
    "Specializes the base request handler to use TCP transport"

    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = int(data[:2].encode('hex'), 16)
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = hex(len(data))[2:].zfill(4).decode('hex')
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):
    "Specializes the base request handler to use UDP transport"

    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


if __name__ == '__main__':
    log("Starting the DumbDNS -- fake nameserver...")

    bind_addr = ('', 5053)
    servers = [
        SocketServer.ThreadingUDPServer(bind_addr, UDPRequestHandler),
    ]

    for s in servers:
        # that thread will start one more thread for each request
        thread = threading.Thread(target=s.serve_forever)
        # exit the server thread when the main thread terminates
        thread.daemon = True
        thread.start()
        log("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass

    finally:
        print
        log("Terminating...")
        for s in servers:
            s.shutdown()
        log("Bye-bye.")
