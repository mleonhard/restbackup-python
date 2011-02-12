#!/usr/bin/env python
"""
Command-line tool for encrypting and decrypting files.  Uses the AES
algorithm in CBC mode.  Passphrase is converted to a key using the
PBKDF2 algorithm (rfc2898), HMAC, and SHA-256.

Tested under Python 2.7.

For faster operation, install the PyCrypto library:
http://www.dlitz.net/software/pycrypto/
http://www.voidspace.org.uk/python/modules.shtml#pycrypto
"""

__author__ = 'Michael Leonhard'
__license__ = 'Copyright (C) 2011 Rest Backup LLC.  Use of this software is subject to the RestBackup.com Terms of Use, http://www.restbackup.com/terms'
__version__ = '1.1'

import getpass
import hmac
import hashlib
import os
import re
import struct
import sys

try:
    from Crypto.Cipher import AES
except ImportError:
    print >>sys.stderr, "Using pyaes. Install PyCrypto for better performance."
    import pyaes as AES

def pbkdf2_256bit(passphrase, salt):
    """Converts a unicode passphrase into a 32-byte key using
    HMAC-SHA-256 and PBKDF2 as defined in rfc2898"""
    passphrase_bytes = passphrase.encode('utf-8')
    prf = lambda key, msg: hmac.new(key, msg, digestmod=hashlib.sha256).digest()
    block = prf(passphrase_bytes, salt + '\x00\x00\x00\x01')
    (a,b,c,d,e,f,g,h) = struct.unpack('LLLLLLLL', block)
    for x in xrange(1, 1000):
        block = prf(passphrase_bytes, block)
        (i,j,k,l,m,n,o,p) = struct.unpack('LLLLLLLL', block)
        a = a^i
        b = b^j
        c = c^k
        d = d^l
        e = e^m
        f = f^n
        g = g^o
        h = h^p
    return struct.pack('LLLLLLLL', a, b, c, d, e, f, g, h)

def main(args):
    args.extend([None,None,None,None])
    (cmd, infilename, outfilename, passphrasefilename) = args[:4]
    if cmd in ('-e', '-d'):
        if passphrasefilename == '-':
            passphrase = sys.stdin.readline().rstrip('\r\n').decode('utf-8')
        elif passphrasefilename:
            passphrase = open(passphrasefilename, 'rb').read().decode('utf-8')
        else:
            passphrase = getpass.getpass('Passphrase: ').decode('utf-8')
        infile = sys.stdin
        outfile = sys.stdout
        if infilename and infilename != '-':
            infile = open(infilename, 'rb')
        if outfilename and outfile != '-':
            outfile = open(outfilename, 'wb')
        try:
            if cmd == '-e':
                return encrypt(passphrase, infile, outfile)
            else:
                return decrypt(passphrase, infile, outfile)
        finally:
            outfile.close()
    else:
        print "AES CBC-mode encryption tool with HMAC-SHA256-PBKDF2"
        print "Usage: aescbc -e|-d [INFILE [OUTFILE [PASSPHRASEFILE]]]"
        return 1

def encrypt(passphrase, infile, outfile):
    aes_key_salt = os.urandom(16)
    outfile.write(aes_key_salt)
    aes_key = pbkdf2_256bit(passphrase, aes_key_salt)
    
    # For a discussion of CBC mode and how to choose IVs, see
    # NIST Special Publication 800-38A, 2001 Edition
    # Recommendation for Block Cipher Modes of Operation
    # http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
    iv = os.urandom(16)
    outfile.write(iv)
    aes = AES.new(aes_key, AES.MODE_CBC, iv)

    mac_key_salt = os.urandom(16)
    outfile.write(aes.encrypt(mac_key_salt))
    mac_key = pbkdf2_256bit(passphrase, mac_key_salt)
    mac = hmac.new(mac_key, digestmod=hashlib.sha256)
    
    CHUNK_SIZE = 1024
    while True:
        chunk = infile.read(CHUNK_SIZE)
        print >>sys.stderr, "Read %r bytes" % len(chunk)
        if len(chunk):
            mac.update(chunk)
        if len(chunk) != CHUNK_SIZE:
            chunk = chunk + mac.digest()
            # Pad file with 0x80 and enough 0x00 to fill the last block
            bytes_in_last_block = len(chunk) % 16
            padding_needed = 16 - bytes_in_last_block
            print >>sys.stderr, "Need %r bytes of padding" % padding_needed
            chunk = chunk + '\x80' + '\x00' * (padding_needed - 1)
            assert(len(chunk) % 16 == 0)
            outfile.write(aes.encrypt(chunk))
            break
        else:
            assert(len(chunk) % 16 == 0)
            outfile.write(aes.encrypt(chunk))
    return 0

def decrypt(passphrase, infile, outfile):
    header = infile.read(48)
    if len(header) != 48:
        print >>sys.stderr, "ERROR: Failed to read header from file."
        return 1
    aes_key_salt = header[0:16]
    iv = header[16:32]
    aes_key = pbkdf2_256bit(passphrase, aes_key_salt)
    aes = AES.new(aes_key, AES.MODE_CBC, iv)
    
    mac_key_salt = aes.decrypt(header[32:48])
    mac_key = pbkdf2_256bit(passphrase, mac_key_salt)
    mac = hmac.new(mac_key, digestmod=hashlib.sha256)
    
    CHUNK_SIZE = 1024
    olderchunk = ''
    oldchunk = ''
    while True:
        newchunk = infile.read(CHUNK_SIZE)
        if len(newchunk):
            cleartext = aes.decrypt(olderchunk)
            mac.update(cleartext)
            outfile.write(cleartext)
            olderchunk = oldchunk
            oldchunk = newchunk
        if len(newchunk) != CHUNK_SIZE:
            break
    
    result = 0
    lastchunk = olderchunk + oldchunk
    if len(lastchunk) % 16 != 0:
        bytes_needed = 16 - (len(lastchunk) % 16)
        print >>sys.stderr, "ERROR: File is damaged.  It does not end on a 16-byte boundary."
        lastchunk = lastchunk + '\x00' * bytes_needed
        assert(len(lastchunk) % 16 == 0)
        cleartext = aes.decrypt(lastchunk)[:-bytes_needed]
        result = 1
    else:
        cleartext = aes.decrypt(lastchunk)
    
    # strip padding
    n = len(cleartext) - 1
    padding_bytes = 0
    while padding_bytes < 16 and n > 0 and cleartext[n] == '\x00':
        n -= 1
        padding_bytes += 1
    if padding_bytes <= 16 and n >= 0 and cleartext[n] == '\x80':
        cleartext = cleartext[:n]
    else:
        print >>sys.stderr, "ERROR: File ends with no padding.  Passphrase is incorrect or file is damaged."
        result = 1
    
    if len(cleartext) >= 32:
        mac_digest = cleartext[-32:]
        cleartext = cleartext[:-32]
    else:
        print >>sys.stderr, "ERROR: MAC not found.  File is truncated, damaged, or passphrase is incorrect."
        result = 1
        mac_digest = ''
    
    mac.update(cleartext)
    outfile.write(cleartext)
    mac_digest2 = mac.digest()
    if mac_digest != mac_digest2:
        print >>sys.stderr, "ERROR: MAC mismatch.  File is damaged or passphrase is incorrect."
        result = 1
    return result

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
