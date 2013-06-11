#!/usr/bin/env python

import random
import threading
import time
import subprocess
from impact import ImpactPacket
from impact import ImpactDecoder
from helpers import *

class ShellThread(threading.Thread):
    def __init__(this, server, cmd):
        threading.Thread.__init__(this)
        this.setDaemon(True)
        this.server = server
        this.cmd    = cmd

    def run(this):
        print this.cmd
        p = subprocess.Popen(this.cmd, stdout=subprocess.PIPE,stderr=subprocess.STDOUT,shell=True)
        try:
            while(True):
                retcode = p.poll() #returns None while subprocess is running
                line = p.stdout.readline()
                with this.server.lock:
                    this.server.send_buffer += line
                if(retcode is not None) and line == '':
                    break
        finally:
            with this.server.lock:
                this.server.send_buffer += "\n\x00"
