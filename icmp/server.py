#!/usr/bin/env python

import os
from base import Icmp
from transceive import *
from helpers import *
from impact import ImpactPacket
from shell_thread import ShellThread

class Server(Icmp):

    def __init__(this,addr):
        Icmp.__init__(this)
        this.error_free = 0
        this.clock_drift = None
        this.client_addr = addr
        this.clock_drift_measurement= []

    def start(this):
        os.system("echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all")

        PacketReceiver(this, ImpactPacket.ICMP.ICMP_ECHO).start()

        this.start_transmission()

        try :
            while True:
                time.sleep(1)

        except (KeyboardInterrupt) :
            os.system("echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all")

    def end_reception(this, addr, pkt):
        with this.lock:
            w = this.decode_word(this.recv_word)
            this.recv_word = 0

        if w != False :
            debug("reception ok, sending ack")
            DelayedSender.send(this.sock, addr, pkt, 0)
            this.flush(w)
        else :
            if this.in_idn != None :
                debug("error receiving packet, parity mismatch, sending nack")
                DelayedSender.send(this.sock, addr, pkt, 2*this.delay)
                this.slow_down()
        
        with this.lock:
            if len(this.recv_buffer) != 0 and this.recv_buffer[-1] == "\n":
                w = this.recv_buffer
                ShellThread(this, w).start()
                this.recv_buffer = ''
        
        #prepare to accept a new packet
        this.in_idn = None

    def receive(this, addr, pkt, ip):
        in_time = now()

        if this.code_nr(pkt.get_icmp_seq()) < 0:
            return

        if this.clock_drift == None :
            # we are still in measurement phase
            cd = in_time - this.get_time(pkt)
            debug("client probe from %s with clock drift: %s" % (addr,cd))
            this.clock_drift_measurement.append(cd)
            if len(this.clock_drift_measurement) == this.measurement_packets:
                # we have 3 measurements, the minimum is the clock drift
                this.clock_drift = min(this.clock_drift_measurement)
                print "client has clock drift: %s" % this.clock_drift
            return

        if this.client_addr != addr:
            #normal ping reply
            pkt = this.build_icmp(ip.get_ip_dst(), addr, id=pkt.get_icmp_id(), \
                        seq_num=pkt.get_icmp_seq(), data=pkt.get_data_as_string())
            DelayedSender.send(this.sock, addr, pkt, 0)
            return

        with this.lock:
            if pkt.get_icmp_id() != this.in_idn and this.in_idn != None :
                debug('packet id changed to %s, somehow we missed an ack...'%pkt.get_icmp_id())
                this.in_idn = pkt.get_icmp_id()
                this.recv_word = 0
                this.retransmission()

        #the ack
        if this.code_nr(pkt.get_icmp_seq()) == this.transmission_len():
            with this.lock :
                reply = this.build_icmp(ip.get_ip_dst(), addr, id=pkt.get_icmp_id(), \
                   seq_num=pkt.get_icmp_seq(), data=pkt.get_data_as_string())
                
                if this.decode(pkt, in_time, clock_offset=this.clock_drift, ack=True) :
                    debug("got ack packet")
                    this.end_reception(addr, reply)
                    this.transmission_succ()
                    this.check_speed_up()
                else :
                    debug("got nack packet")
                    this.end_reception(addr, reply)
                    this.retransmission()

        else:
            code = ppm_code(this.send_word, this.code_nr(pkt.get_icmp_seq()), this.ppm_bits)
            d = code * this.delay
            
            reply = this.build_icmp(ip.get_ip_dst(), addr, id=pkt.get_icmp_id(), \
                    seq_num=pkt.get_icmp_seq(), data=pkt.get_data_as_string())
   
            DelayedSender.send(this.sock, addr, reply, d)
            this.decode(pkt, in_time, clock_offset=this.clock_drift)
            debug("%s: sending %s at pos %s" % \
                    (this.in_idn, d, this.code_nr(pkt.get_icmp_seq())))


    
    def __str__(this):
        return 'server'
