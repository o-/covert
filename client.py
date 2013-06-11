#!/usr/bin/env python

import os, sys
from icmp import client

if not os.geteuid()==0:
    sys.exit("\nThe client requires root privileges to run.\n")

if len(sys.argv) == 3:
    client.Client(sys.argv[1], sys.argv[2]).start()
else:
    client.Client('127.0.0.1', '127.0.0.1').start()
