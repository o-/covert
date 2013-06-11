#!/usr/bin/env python

import os, sys
from icmp import server

if len(sys.argv) == 2:
    server.Server(sys.argv[1]).start()
else:
    server.Server('127.0.0.1').start()
