#!/usr/bin/env python
"""
Command-line tool and library for encrypting and decrypting files.
Uses AES in CBC mode for confidentiality.  The passphrase is converted
to a key using the PBKDF2 algorithm (rfc2898) and HMAC-SHA-256.  File
integrity is verified with SHA-256 HMAC.

Tested under Python 2.7.

For faster operation, install the PyCrypto library:
http://www.dlitz.net/software/pycrypto/
http://www.voidspace.org.uk/python/modules.shtml#pycrypto
"""

__author__ = 'Michael Leonhard'
__license__ = 'Copyright (C) 2011 Rest Backup LLC.  Use of this software is subject to the RestBackup.com Terms of Use, http://www.restbackup.com/terms'
__version__ = '1.3'

import getpass
import hmac
import hashlib
import os
from restbackup import FileObjectReader
from restbackup import FileReader
from restbackup import RestBackupException
from restbackup import RewindableSizedInputStream
from restbackup import SizedInputStream
import struct
import sys
import unittest

try:
    from Crypto.Cipher import AES
except ImportError:
    print >>sys.stderr, "Using pyaes. Install PyCrypto for better performance."
    import pyaes as AES

class DataDamagedException(IOError): pass

class DataTruncatedException(DataDamagedException): pass

class BadMacException(DataDamagedException): pass

class WrongPassphraseException(RestBackupException): pass

class MacAddingReader(RewindableSizedInputStream):
    """Adds a SHA-256 HMAC to the stream to authenticate the data and
    prevent tampering.
    
    Prefixes the stream with a 16-byte salt.  Generates a 256-bit key
    using PBKDF2 with 1000 rounds of HMAC-SHA-256.  Appends a 32-byte
    SHA-256 HMAC to the stream.  Verify the MAC with
    MacCheckingReader.
    """
    def __init__(self, stream, passphrase, salt=None, key=None):
        """Stream must be a RewindableSizedInputStream object.
        Passphrase is a byte stream."""
        stream_length = 16 + len(stream) + 32
        RewindableSizedInputStream.__init__(self, stream_length)
        self.stream = stream
        if not salt:
            salt = os.urandom(16)
        self.salt = salt
        if not key:
            key = pbkdf2_256bit(passphrase, salt)
        self.key = key
        self.rewind()
    
    def read_once(self, size):
        if size < 1:
            raise ValueError("size must be greater than zero")
        if self.prefix:
            chunk = self.prefix[:size]
            self.prefix = self.prefix[size:]
            return chunk
        if self.stream:
            chunk = self.stream.read(size)
            if len(chunk) != 0:
                self.mac.update(chunk)
                return chunk
            else:
                self.stream = None
                self.suffix = self.mac.digest()
                self.mac = None
        if self.suffix:
            chunk = self.suffix[:size]
            self.suffix = self.suffix[size:]
            return chunk
        return ''
    
    def rewind(self):
        self.prefix = self.salt
        self.suffix = None
        self.mac = hmac.new(self.key, digestmod=hashlib.sha256)
        self.stream.rewind()
    
    def close(self):
        self.salt = None
        self.key = None
        self.mac = None
        self.prefix = None
        self.stream.close()
        self.stream = None
        self.suffix = None


class MacCheckingReader(SizedInputStream):
    """Verifies the SHA-256 HMAC on the stream, to authenticate the
    data and detect tampering.
    
    Raises BadMacException at EOF if the HMAC does not match.  Raises
    DataTruncatedException if file is too short to contain expected
    header and footer.
    
    Removes the 16-byte salt prefix and verifies the 32-byte SHA-256
    HMAC at the end of the stream.  Create such a stream with
    MacAddingReader.
    """
    def __init__(self, stream, passphrase, key=None):
        """Stream must be a SizedInputStream object.  Passphrase must
        be a byte string."""
        stream_length = len(stream) - 48
        SizedInputStream.__init__(self, stream_length)
        self.stream = stream
        salt = stream.read(16)
        if len(salt) != 16:
            raise DataTruncatedException("File does not contain full MAC salt.")
        if not key:
            key = pbkdf2_256bit(passphrase, salt)
        self.mac = hmac.new(key, digestmod=hashlib.sha256)
        self.buffer = ''
    
    def read_once(self, size):
        if size < 1:
            raise ValueError("size must be greater than zero")
        if len(self.buffer) >= size + 32:
            chunk = self.buffer[:size]
            self.buffer = self.buffer[size:]
            if self.mac:
                self.mac.update(chunk)
            return chunk
        if self.stream:
            bytes_needed = size + 32 - len(self.buffer)
            chunk = self.stream.read(bytes_needed)
            self.buffer = self.buffer + chunk
            if len(chunk) != bytes_needed: # EOF
                self.stream = None
                if len(self.buffer) < 32:
                    raise DataTruncatedException("File does not contain MAC.")
                digest1 = self.buffer[-32:]
                self.buffer = self.buffer[:-32]
                self.mac.update(self.buffer)
                digest2 = self.mac.digest()
                self.mac = None
                if digest1 != digest2:
                    raise BadMacException("The file has been damaged or the"
                                          " passphrase is incorrect.")
            return self.read_once(size)
        if self.buffer:
            chunk = self.buffer[:size]
            self.buffer = self.buffer[size:]
            return chunk
        return ''
    
    def close(self):
        self.mac = None
        self.stream.close()
        self.stream = None
        self.buffer = None


class PaddingAddingReader(RewindableSizedInputStream):
    """Adds padding so the resulting stream size is a multiple of 16
    bytes."""
    def __init__(self, stream):
        """Stream must be a RewindableSizedInputStream."""
        data_bytes = len(stream)
        # Pad with 0x80 and enough nulls to fill last block
        self.padding = '\x80' + '\x00' * (15 - data_bytes % 16)
        stream_length = data_bytes + len(self.padding)
        assert(stream_length % 16 == 0)
        RewindableSizedInputStream.__init__(self, stream_length)
        self.stream = stream
        self.rewind()
    
    def read_once(self, size):
        if size < 1:
            raise ValueError("size must be greater than zero")
        if self.stream:
            chunk = self.stream.read(size)
            if len(chunk) == size:
                return chunk
            else: # EOF
                self.stream = None
                self.suffix = chunk + self.suffix
                return self.read_once(size)
        else:
            chunk = self.suffix[:size]
            self.suffix = self.suffix[size:]
            return chunk

    def rewind(self):
        self.suffix = self.padding
        self.stream.rewind()
    
    def close(self):
        self.suffix = None
        self.stream.close()
        self.stream = None


class PaddingStrippingReader(SizedInputStream):
    """Removes padding from the end of the stream.  The resulting
    stream may be up to 16 bytes shorter than the value of
    len(stream_obj).
    
    Raises DataDamagedException if no padding is found at end of
    stream.
    """
    def __init__(self, stream):
        """Stream must be a SizedInputStream."""
        SizedInputStream.__init__(self, len(stream))
        self.stream = stream
        self.buffer = ''
    
    def read_once(self, size):
        if size < 1:
            raise ValueError("size must be greater than zero")
        
        if len(self.buffer) >= size + 16:
            chunk = self.buffer[:size]
            self.buffer = self.buffer[size:]
            return chunk
        if self.stream:
            bytes_needed = size + 16 - len(self.buffer)
            chunk = self.stream.read(bytes_needed)
            if len(chunk) == bytes_needed:
                self.buffer = self.buffer + chunk
                result = self.buffer[:size]
                self.buffer = self.buffer[size:]
                assert(len(self.buffer) == 16)
                return result
            else: # EOF
                self.stream = None
                self.buffer = self.buffer + chunk
                # strip padding
                n = len(self.buffer) - 1
                padding_bytes = 0
                while padding_bytes < 16 and n > 0 and self.buffer[n] == '\x00':
                    n -= 1
                    padding_bytes += 1
                if padding_bytes <= 16 and n >= 0 and self.buffer[n] == '\x80':
                    self.buffer = self.buffer[:n]
                    return self.read_once(size)
                else:
                    raise DataDamagedException("Did not find padding at end of "
                                               "file.  Passphrase is incorrect "
                                               "or file is damaged.")
        if self.buffer:
            chunk = self.buffer[:size]
            self.buffer = self.buffer[size:]
            return chunk
        return ''
    
    def close(self):
        self.buffer = None
        self.stream.close()
        self.stream = None

class EncryptingReader(RewindableSizedInputStream):
    """Encrypts the stream with AES in CBC mode.
    
    Prefixes the stream with a 16-byte salt, a 16-byte IV, and a
    16-byte block of nulls.  Generates a 256-bit key using PBKDF2 with
    1000 rounds of HMAC-SHA-256.  Decrypt with DecryptingReader.
    
    Raises ValueError if input stream does not end on a 16-byte block
    boundary.  Use PaddingAddingReader to ensure stream ends on a
    16-byte block boundary.
    """
    def __init__(self, stream, passphrase, salt=None, iv=None, key=None):
        """Stream must be a RewindableSizedInputStream.  Passphrase
        must be a byte string."""
        if len(stream) % 16:
            raise ValueError("Stream length must be a multiple of 16")
        stream_length = 16 + 16 + 16 + len(stream)
        RewindableSizedInputStream.__init__(self, stream_length)
        self.stream = stream
        if not salt:
            salt = os.urandom(16)
        if not iv:
            # For a discussion of CBC mode and how to choose IVs, see
            # NIST Special Publication 800-38A, 2001 Edition
            # Recommendation for Block Cipher Modes of Operation
            # http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
            iv = os.urandom(16)
        if not key:
            key = pbkdf2_256bit(passphrase, salt)
        self.salt = salt
        self.iv = iv
        self.key = key
        self.rewind()
    
    def read_once(self, size):
        if size < 1:
            raise ValueError("size must be greater than zero")
        elif self.buffer:
            chunk = self.buffer[:size]
            self.buffer = self.buffer[size:]
            return chunk
        elif self.stream:
            bytes_needed = size
            if bytes_needed % 16:
                bytes_needed += 16 - bytes_needed % 16 # round up
            chunk = self.stream.read(bytes_needed)
            if len(chunk) != bytes_needed:
                self.stream = None
            if len(chunk) % 16:
                raise DataDamagedException("Data ended in middle of block.")
            self.buffer = self.aes.encrypt(chunk)
            return self.read_once(size)
        else:
            return ''
    
    def rewind(self):
        self.aes = AES.new(self.key, AES.MODE_CBC, self.iv)
        self.buffer = self.salt + self.iv + self.aes.encrypt('\x00' * 16)
        self.stream.rewind()
    
    def close(self):
        self.buffer = None
        self.aes = None
        self.stream.close()
        self.stream = None

class DecryptingReader(SizedInputStream):
    """Decrypts a stream that was encrypted with EncryptingReader.
    
    Removes the 16-byte salt, 16-byte IV, and 16-byte block of nulls
    from the beginning of the stream.  Generates a 256-bit key using
    PBKDF2 with 1000 rounds of HMAC-SHA-256.  Decrypts the stream
    using AES in CBC mode.  Raises DataTruncatedException if file is
    too short to contain expected header or the file ends in the
    middle of a block.
    """
    def __init__(self, stream, passphrase, key=None):
        """Stream must be a SizedInputStream.  Passphrase must be a
        byte string."""
        if len(stream) < 32:
            raise DataTruncatedException("File is too short to contain a "
                                         "32-byte header.")
        stream_length = -16 - 16 - 16 + len(stream)
        SizedInputStream.__init__(self, stream_length)
        self.stream = stream
        header = stream.read(48)
        if len(header) != 48:
            raise DataTruncatedException("File is missing 48-byte header.")
        salt = header[:16]
        iv = header[16:32]
        if not key:
            key = pbkdf2_256bit(passphrase, salt)
        self.aes = AES.new(key, AES.MODE_CBC, iv)
        null_block = self.aes.decrypt(header[32:])
        if any([ord(c) for c in null_block]):
            raise WrongPassphraseException("The passphrase is incorrect or "
                                           "the file header was damaged.")
        self.buffer = ''
    
    def read_once(self, size):
        if size < 1:
            raise ValueError("size must be greater than zero")
        if self.buffer:
            chunk = self.buffer[:size]
            self.buffer = self.buffer[size:]
            return chunk
        if self.stream:
            bytes_needed = size - len(self.buffer)
            if bytes_needed % 16:
                bytes_needed += 16 - bytes_needed % 16 # round up
            chunk = self.stream.read(bytes_needed)
            if len(chunk) != bytes_needed: # EOF
                self.stream = None
            if len(chunk) % 16:
                raise DataDamagedException("Data ended in middle of block.")
            self.buffer = self.buffer + self.aes.decrypt(chunk)
            return self.read_once(size)
        return ''
    
    def close(self):
        self.buffer = None
        self.aes = None
        self.stream.close()
        self.stream = None

def pbkdf2_256bit(passphrase, salt):
    """Converts a unicode passphrase into a 32-byte key using RFC2898
    PBKDF2 with 1000 rounds of HMAC-SHA-256.  Passphrase and salt must
    be byte strings."""
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
            passphrase = sys.stdin.readline().rstrip('\r\n')
        elif passphrasefilename:
            passphrase = open(passphrasefilename, 'rb').read()
        else:
            passphrase = getpass.getpass('Passphrase: ')
        infile_reader = FileObjectReader(sys.stdin, 1024)
        outfile = sys.stdout
        if infilename and infilename != '-':
            infile_reader = FileReader(infilename)
        if outfilename and outfile != '-':
            outfile = open(outfilename, 'wb')
        try:
            if cmd == '-e':
                return encrypt(passphrase, infile_reader, outfile)
            else:
                return decrypt(passphrase, infile_reader, outfile)
        finally:
            outfile.close()
    else:
        print "AES CBC-mode encryption tool with HMAC-SHA256-PBKDF2"
        print "Usage: chlorocrypt -e|-d [INFILE [OUTFILE [PASSPHRASEFILE]]]"
        return 1

def encrypt(passphrase, infile_reader, outfile):
    mac = MacAddingReader(infile_reader, passphrase)
    pad = PaddingAddingReader(mac)
    enc = EncryptingReader(pad, passphrase)
    while True:
        chunk = enc.read(1024)
        if not chunk:
            break
        outfile.write(chunk)
    return 0

def decrypt(passphrase, infile_reader, outfile):
    dec = DecryptingReader(infile_reader, passphrase)
    pad = PaddingStrippingReader(dec)
    mac = MacCheckingReader(pad, passphrase)
    while True:
        chunk = mac.read(1024)
        if not chunk:
            break
        outfile.write(chunk)
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
