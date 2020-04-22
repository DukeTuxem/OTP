#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import sys
import hmac
import time
import struct
import base64

from hashlib import sha1

usg = "Usage : " + sys.argv[0] + " Key\n\n"
usg += "With \"Key\" in range ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

def get_TOTP(K, digits, window):
    counter = int(time.time() // window)
    try:
        K = base64.b32decode(K, True)        
    except:
        sys.stderr.write("Error:\nToo short key value, non 8 multiple length string\n"
                         + "or illegal chars detected. Please refer to RFC 3548\n")
        sys.exit(1)
    signature = HOTP(K, counter, digits)
    return signature

def HOTP(key, counter, digits):
    counter_bytes = struct.pack(b"!Q", counter)
    hmac_sha1 = hmac.new(key, counter_bytes, sha1).hexdigest()
    signature = truncate(hmac_sha1)[-digits:]
    return signature

def truncate(hmac_sha1):
    offset = int(hmac_sha1[-1], 16)
    binary = int(hmac_sha1[(offset * 2):((offset * 2) + 8)], 16) & 0x7fffffff
    return str(binary)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print usg
        sys.exit(1)
    print get_TOTP(sys.argv[1], 6, 30)

    
