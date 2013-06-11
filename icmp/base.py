#!/usr/bin/env python

import socket
import sys
import os
from helpers import *
from impact import ImpactPacket
from impact import ImpactDecoder
import threading
import random
import string
import math

class Icmp(object):
    def __init__(this):
        this.send_buffer = ''
        this.recv_buffer = ''
        this.send_word = 0
        this.recv_word = 0
        this.packets_received = 0
        this.delay = 40
        this.in_idn = None
        this.wordlen = 8
        this.parity  = 8
        this.preamble_size = 0
        this.lock = threading.RLock()
        this.error_free = -1
        this.error_interval = 1
        this.ppm_bits = 2
        this.measurement_packets = 4

        try:
            this.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            this.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            this.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except socket.error, (errno, msg):
            if errno == 1:
                raise socket.error(msg)
            raise
    
    def decode_delay(this,measured):
        return int(max(0.03+((0.0+measured)/this.delay),0))

    def build_icmp( this, ip_src, ip_dst, icmp_type=ImpactPacket.ICMP().ICMP_ECHOREPLY, 
                    code=0, id=0, seq_num=0, data=''):
    
        # create IP packet and set src and dst addresses
        ip = ImpactPacket.IP()
        ip.set_ip_src(ip_src)
        ip.set_ip_dst(ip_dst)
        ip.set_ip_ttl(64)
        
        # create a new ICMP packet and set its type
        icmp = ImpactPacket.ICMP()
        icmp.set_icmp_type(icmp_type)
        
        # include payload
        icmp.contains(ImpactPacket.Data(data))
        
        # have the IP packet contain the ICMP packet
        # (along with its payload)
        ip.contains(icmp) 
    
        # set ICMP id and seq_num
        icmp.set_icmp_id(id)
        icmp.set_icmp_seq(seq_num)
    
        # calculate its checksum.
        icmp.set_icmp_cksum(0)
        icmp.auto_checksum = 1
    
        # return the final rapresentation of the packet
        return ip.get_packet()

    def get_time(this,pkt):
        data = pkt.get_data_as_string()
        if len(data)<9:
            return 0
        else:
            return struct.unpack("<Q",data[:8])[0]

    def next_word(this):
        with this.lock:
            n = this.send_buffer[:this.wordlen]
            this.send_buffer = this.send_buffer[this.wordlen:]
            return n
    
    def create_time(this,ts):
        return struct.pack("<Q",ts)

    def flush(this,word):
        with this.lock:
            this.recv_buffer += word
            debug( "<----- received word to receive buffer '%s'" % word)
    
    def code_nr(this, seq):
        return seq-1-this.preamble_size

    def seq_nr(this, code):
        return code+1+this.preamble_size

    def decode(this,pkt,in_time, clock_offset=0, ack=False):
        with this.lock:
            if this.in_idn == None :
                debug('new packet id %s' % pkt.get_icmp_id() )
                this.in_idn = pkt.get_icmp_id()
            elif pkt.get_icmp_id() != this.in_idn :
                debug('dropping unexpected icmp id %s' % pkt.get_icmp_id() )
                return False

        trans = in_time - (this.get_time(pkt)+clock_offset)
        code  = this.code_nr(pkt.get_icmp_seq())

        if ack:
            if this.decode_delay(trans) > 0 :
                debug( "%s: got nack at pos %d (%d) (off:%s)" % (this.in_idn,code,trans,clock_offset) )
                return False
            else:
                debug( "%s: got ack at pos %d (%d) (off:%s)" % (this.in_idn,code,trans,clock_offset) )
                return True

        else:
            with this.lock:
                recv_code = this.decode_delay(trans)
                debug( "%s: got %d at pos %d (%d) (off:%s)" % (this.in_idn,recv_code,code,trans,clock_offset) )
                this.recv_word |= recv_code<<(code*this.ppm_bits)
       
    def encode_word(this,word):
        data = byte2int(word,this.wordlen)
        p    = get_parity(data,this.parity,this.wordlen)
        debug("adding parity %d to %d" % (p,data))
        return data<<this.parity | p

    def decode_word(this,word):
        data = word>>this.parity
        p    = ~(data<<this.parity) & word
        debug("recovered parity %d from %d" % (p,data))
        pr   = get_parity(data,this.parity,this.wordlen)
        if p == pr:
            return int2byte(data,this.wordlen)
        else:
            return False
   
    def start_transmission(this):
        this.transmission_succ()

    def transmission_succ(this):
        w = this.next_word()
        debug("-----> next word from send buffer '%s'" % w)
        this.send_word = this.encode_word(w)
        debug("raw snd_word %d" % this.send_word)

    def check_speed_up(this):
        this.error_free += 1
        if this.error_free == this.error_interval :
            this.error_free = 0
            this.error_interval *= 2
            return True
        return False
        
    def slow_down(this):
        return

    def retransmission(this):
        this.slow_down()
        debug("retransmitting")

    def transmission_len(this):
        return ((this.wordlen*8) + this.parity) / this.ppm_bits

