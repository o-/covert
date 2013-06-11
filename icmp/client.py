#!/usr/bin/env python

from base import Icmp
from transceive import *
from helpers import *
from impact import ImpactPacket
import threading
import time
import sys


class Client(Icmp):

    def __init__(this, src, dst):
        Icmp.__init__(this)
        this.src = src
        this.dst = dst
        this.dst = dst
        this.clock = 0.001
        this.word_wait = 0
        this.tx_done = threading.Condition(this.lock)
        this.sent_ack = None
        this.frame_replies = 0

    def start(this):
        PacketReceiver(this,ImpactPacket.ICMP.ICMP_ECHOREPLY).start()
    
        for i in xrange(this.measurement_packets):
            #exchange clock drift
            pkt = this.build_icmp(this.src, this.dst, icmp_type=ImpactPacket.ICMP().ICMP_ECHO, \
                    id=random.randint(0,1<<16), seq_num=1, data=this.create_time(now())+'/01234567')
            DelayedSender.send(this.sock, this.dst, pkt, 0)
            time.sleep(0.1)
       
        while True:
            this.send_buffer = raw_input("# ")
            this.send_buffer = this.send_buffer+'\n'
   
            this.start_transmission()

            while True:
                this.send_next()
                with this.lock:
                    if len(this.recv_buffer) != 0:
                        w = this.recv_buffer
                        this.recv_buffer = ''
                        sys.stdout.write(w)
                        if w[-1] == "\x00":
                            break
    
    def check_speed_up(this):
        if Icmp.check_speed_up(this) :
            this.clock = max(this.clock*0.9,0.0001)
            debug("#  clock speedup %s" % this.clock)

    def slow_down(this):
        Icmp.slow_down(this)
        this.clock = min(this.clock*1.1,0.4)
        debug("#  clock slowdown %s" % this.clock)
        time.sleep(this.clock+(this.delay/1000.0))

    def send_next(this):
        this.check_speed_up()

        this.frame_replies = 0
        seq = 1
        this.idn = this.in_idn = random.randint(0,1<<16)
        for b in n_bits(this.send_word, this.ppm_bits, this.transmission_len()):
            if(seq != 1):
                time.sleep(this.clock)

            debug("%s: sending %s at pos %s" % (this.idn, b, this.code_nr(seq)))
            pkt = this.build_icmp(this.src, this.dst, icmp_type=ImpactPacket.ICMP().ICMP_ECHO, \
                    id=this.idn, seq_num=seq, data=this.create_time(now())+'/01234567')
            seq += 1
            DelayedSender.send(this.sock, this.dst, pkt, this.delay*b)

        with this.lock:
            this.sent_ack = None
            debug("finished sending packets, waiting for ack")
            this.tx_done.wait(timeout=this.delay*this.ppm_bits*5/1000.0)

            if this.sent_ack == None :
                this.no_ack_reply()

        time.sleep(this.word_wait)

    def end_reception(this):
        with this.lock:
            w = this.decode_word(this.recv_word)
            debug("raw rcv_word %d" % this.recv_word)
            this.recv_word = 0

        if w != False :
            this.ack(True);
            debug("reception correct, sending ack")
            this.flush(w)
        else :
            if this.in_idn != None :
                this.ack(False);
                debug("error receiving packet, parity mismatch, sending nack")
                this.slow_down()

    def ack(this,ok):
        this.sent_ack = ok
        pkt = this.build_icmp(this.src, this.dst, icmp_type=ImpactPacket.ICMP().ICMP_ECHO, \
                    id=this.idn, seq_num=this.seq_nr(this.transmission_len()), \
                    data=this.create_time(now())+'/01234567')
        DelayedSender.send(this.sock, this.dst, pkt, 0 if ok else this.delay)

    def no_ack_reply(this):
        with this.lock :
            this.retransmission()
            this.in_idn = None

    def receive(this, addr, pkt, ip):
        with this.lock :
            in_time = now()

            this.frame_replies += 1

            #the ack
            if this.frame_replies == this.transmission_len()+1 :
                    off = (0 if this.sent_ack else this.delay)
                    if this.decode(pkt, in_time, clock_offset=off, ack=True) :
                        debug("got ack reply")
                        this.transmission_succ()
                    else :
                        debug("got nack reply")
                        this.retransmission()

                    this.in_idn = None
                    this.tx_done.notify()

            else :
                if this.in_idn != pkt.get_icmp_id():
                    debug("got ack from server, but was too late..")
                    this.frame_replies -= 1
                    return

                code = ppm_code(this.send_word, this.code_nr(pkt.get_icmp_seq()), this.ppm_bits)
                off = code * this.delay
                
                this.decode(pkt, in_time, clock_offset=off)

                #last bit received, sending ack
                if this.frame_replies == this.transmission_len() :
                    # make sure we do not change sent_ack before main thread is ready
                    # to wait for the ack
                    this.end_reception()

    def __str__(this):
        return 'client'
