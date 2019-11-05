"""
    FixedResolver - example resolver which responds with fixed response
                    to all requests
"""

from __future__ import print_function

import copy

from dnslib import RR
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger

class FixedResolver(BaseResolver):
    """
        Respond with fixed response to all requests
    """
    def __init__(self,zone):
        # Parse RRs
        self.rrs = RR.fromZone(zone)

    def resolve(self,request,handler):
        reply = request.reply()
        qname = request.q.qname
        # Replace labels with request label
        for rr in self.rrs:
            a = copy.copy(rr)
            a.rname = qname
            reply.add_answer(a)
        return reply

def run(zones):
    import argparse,sys,time

    p = argparse.ArgumentParser(description="Fixed DNS Resolver")
    p.add_argument("--response","-r",default=". 60 IN A 127.0.0.1",
                    metavar="<response>",
                    help="DNS response (zone format) (default: 127.0.0.1)")
    p.add_argument("--zonefile","-f",
                    metavar="<zonefile>",
                    help="DNS response (zone file, '-' for stdin)")
    p.add_argument("--port","-p",type=int,default=10053,
                    metavar="<port>",
                    help="Server port (default:53)")
    p.add_argument("--address","-a",default="",
                    metavar="<address>",
                    help="Listen address (default:all)")
    p.add_argument("--udplen","-u",type=int,default=0,
                    metavar="<udplen>",
                    help="Max UDP packet length (default:0)")
    p.add_argument("--tcp",action='store_true',default=False,
                    help="TCP server (default: UDP only)")

    
    responses = "\n".join(zones)
    resolver = FixedResolver(responses)
    logger = DNSLogger("request,reply,truncated,error", False)

    print("Starting Fixed Resolver (%s:%d) [%s]" % (
                        "*",
                        10053,
                        "UDP"))
    
    for rr in resolver.rrs:
        print("    | ",rr.toZone().strip(),sep="")
    print()

    if 0:
        DNSHandler.udplen = 0

    udp_server = DNSServer(resolver,
                           port=10053,
                           address="",
                           logger=logger)
    udp_server.start_thread()

    while udp_server.isAlive():
        time.sleep(1)

if __name__ == '__main__':
    run(['. 60 IN A 127.0.0.1'])