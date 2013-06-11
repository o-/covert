#!/usr/bin/env python

import struct
import binascii
import time

DEBUG = False

def now():
    return int(round(time.time() * 1000))

def n_bits(n,m,l):
    for i in range(l):
        yield n>>(i*m) & ((1<<m) - 1)

def ppm_code(n,b,m):
    return n>>(b*m) & ((1<<m) - 1)

def int2byte(m,length):
    if m==0:
        return ''
    s = '%x' % m
    if len(s) % 2 != 0:
        s = '0%s' % s
    s = binascii.unhexlify(s)
    return s

def byte2int(m,length):
    if len(m) == 0:
        return 0
    ret = int(binascii.hexlify(bytes(m)),16)
    if(byteLen(ret)>length):
        print "error, word to big"
#    if(int2byte(ret,length)!=m):
#        print "err"
    return ret

def debug(string):
    if DEBUG:
        print string

def get_parity(data,parity_bits,length):
    length *= 8
    sum = 0
    for b in xrange(0,length):
        if data & (1<<b) != 0:
            sum += 1
    
    return sum % (1<<parity_bits)

def byteLen(i):
     length = 0
     while i:
         i >>= 8
         length += 1
     return length
