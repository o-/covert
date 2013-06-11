#!/usr/bin/env python

import random
import threading
import time
from impact import ImpactPacket
from impact import ImpactDecoder
from helpers import *

class PacketReceiver(threading.Thread):
    def __init__(this, server, icmp_type):
        threading.Thread.__init__(this)
        this.setDaemon(True)
        this.server = server
        this.icmp_type = icmp_type

    def run(this):
        while True:
            reply, addr = this.server.sock.recvfrom(1024)
        
            ip  = ImpactDecoder.IPDecoder().decode(reply)
            pkt = ImpactDecoder.ICMPDecoder().decode(ip.get_data_as_string())

            #only listen to the expected type
            if pkt.get_icmp_type() != this.icmp_type :
                continue
            
            this.server.receive(addr[0],pkt,ip)

class DelayedSender(threading.Thread):
    @staticmethod
    def send(sock, dst, pkt, delay):
        if delay == 0 :
            sock.sendto(pkt, (dst, 0))
        else :
            DelayedSender(sock, dst, pkt, delay).start()

    def __init__(this, sock, dst, pkt, delay):
        threading.Thread.__init__(this)
        this.setDaemon(True)
        this.sock  = sock
        this.pkt   = pkt
        this.delay = delay/1000.0
        this.dst   = dst

    def run(this):
        time.sleep(this.delay)
        this.sock.sendto(this.pkt, (this.dst, 0))
