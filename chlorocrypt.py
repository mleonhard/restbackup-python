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
__version__ = '1.7'

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

MAC_BLOCK_SIZE = 64 * 1024

class MacAddingReader(RewindableSizedInputStream):
    """Adds a SHA-256 HMAC to the stream to authenticate the data and
    prevent tampering.
    
    Prefixes the stream with a 16-byte salt.  Generates a 256-bit key
    using PBKDF2 with 4096 rounds of HMAC-SHA-256.  Inserts 32-byte
    SHA-256 MACs into the stream every 64 KB.  Verify the MACs with
    MacCheckingReader.
    
    Production code should not provide values for the
    testing_only_salt or test_only_key parameters.  These are for
    testing purposes only.
    """
    def __init__(self, stream, passphrase,
                 testing_only_salt=None, testing_only_key=None):
        """Stream must be a RewindableSizedInputStream object.
        Passphrase is a byte stream."""
        num_full_blocks = len(stream) / MAC_BLOCK_SIZE
        num_partial_blocks = 0 if len(stream) % MAC_BLOCK_SIZE == 0 else 1
        num_blocks = num_full_blocks + num_partial_blocks
        num_macs = max(1, num_blocks)
        stream_length = 16 + len(stream) + 32 * num_macs
        RewindableSizedInputStream.__init__(self, stream_length)
        self.stream = stream
        self.salt = testing_only_salt or os.urandom(16)
        self.key = testing_only_key or pbkdf2_256bit(passphrase, self.salt)
        self.rewind()
    
    def read_once(self, size):
        if not self.stream:
            raise IOError("The stream is closed")
        if size < 1:
            raise ValueError("size must be greater than zero")
        if self.prefix:
            chunk = self.prefix[:size]
            self.prefix = self.prefix[size:]
            return chunk
        if not self.stream_at_eof:
            chunk = self.stream.read(MAC_BLOCK_SIZE)
            if len(chunk) != MAC_BLOCK_SIZE:
                self.stream_at_eof = True
            if len(chunk) == 0 and self.stream_at_start:
                self.prefix = self.mac.digest()
            if len(chunk) != 0:
                self.stream_at_start = False
                self.mac.update(chunk)
                self.prefix = chunk + self.mac.digest()
            return self.read_once(size)
        return ''
    
    def rewind(self):
        self.prefix = self.salt
        self.mac = hmac.new(self.key, digestmod=hashlib.sha256)
        self.stream.rewind()
        self.stream_at_start = True
        self.stream_at_eof = False
    
    def close(self):
        self.salt = None
        self.key = None
        self.mac = None
        self.prefix = None
        self.stream.close()
        self.stream = None
        self.stream_at_start = False
        self.stream_at_eof = True


class MacCheckingReader(SizedInputStream):
    """Verifies the SHA-256 MACs in the stream, to authenticate the
    data and detect tampering.
    
    Raises BadMacException when a MAC does not match.  This happens
    when the passphrase is incorrect or the file was damaged.  Raises
    DataTruncatedException if file is too short to contain the
    expected header and MACs.
    
    Removes the 16-byte salt prefix and verifies the 32-byte SHA-256
    HMACs which appear in the stream every 64 KB.  Verifies data
    before returning it.  Create such a stream with MacAddingReader.
    
    Production code should not provide a value for the
    testing_only_key parameter.  This is for testing purposes only.
    """
    def __init__(self, stream, passphrase, testing_only_key=None):
        """Stream must be a SizedInputStream object.  Passphrase must
        be a byte string."""
        blocks_len = len(stream) - 16
        num_full_blocks = blocks_len / (MAC_BLOCK_SIZE + 32)
        num_partial_blocks = 0 if blocks_len % (MAC_BLOCK_SIZE + 32) == 0 else 1
        num_blocks = num_full_blocks + num_partial_blocks
        num_macs = max(1, num_blocks)
        stream_length = blocks_len - 32 * num_macs
        SizedInputStream.__init__(self, stream_length)
        self.stream = stream
        salt = stream.read(16)
        if len(salt) != 16:
            raise DataTruncatedException("File does not contain full MAC salt.")
        key = testing_only_key or pbkdf2_256bit(passphrase, salt)
        self.mac = hmac.new(key, digestmod=hashlib.sha256)
        self.buffer = ''
        self.stream_at_start = True
        self.stream_at_eof = False
    
    def read_once(self, size):
        if not self.stream:
            raise IOError("The stream is closed")
        if size < 1:
            raise ValueError("size must be greater than zero")
        if self.buffer:
            chunk = self.buffer[:size]
            self.buffer = self.buffer[size:]
            return chunk
        if self.stream_at_eof:
            return ''
        chunk = self.stream.read(MAC_BLOCK_SIZE + 32)
        if len(chunk) == 0:
            if self.stream_at_start:
                raise DataTruncatedException("Found no data and no MAC")
            else:
                return ''
        if len(chunk) > 0:
            self.stream_at_start = False
        if len(chunk) < 32:
            raise DataTruncatedException("File is missing MAC at end of file")
        if len(chunk) != MAC_BLOCK_SIZE + 32:
            self.stream_at_eof = True
        self.buffer = chunk[:-32]
        self.mac.update(self.buffer)
        expected_digest = chunk[-32:]
        calculated_digest = self.mac.digest()
        # Avoid timing attacks when comparing MAC
        # http://seb.dbzteam.org/crypto/python-oauth-timing-hmac.pdf
        diff = 0
        for n in xrange(32):
            diff |= ord(expected_digest[n]) ^ ord(calculated_digest[n])
        if diff != 0:
            raise BadMacException("The passphrase is incorrect or the file is damaged.")
        return self.read_once(size)
    
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
        # Always add padding to make sure that last block has 16
        # bytes.  Use the PKCS#5 format: '\x01', '\x02\x02',
        # '\x03\x03\x03', etc.  See section 6.3 of
        # http://www.ietf.org/rfc/rfc3852.txt
        padding_bytes_needed = 16 - len(stream) % 16 or 16
        self.padding = chr(padding_bytes_needed) * padding_bytes_needed
        stream_length = len(stream) + len(self.padding)
        assert(stream_length % 16 == 0)
        RewindableSizedInputStream.__init__(self, stream_length)
        self.stream = stream
        self.stream_keep = stream
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
        self.stream = self.stream_keep
        self.stream.rewind()
    
    def close(self):
        self.suffix = None
        self.stream_keep.close()
        self.stream_keep = None
        self.stream = None


class PaddingStrippingReader(SizedInputStream):
    """Removes padding from the end of the stream.  The resulting
    stream may be up to 16 bytes shorter than the value of
    len(stream_obj).
    
    Raises DataDamagedException if no padding is found at end of
    stream.
    
    Be sure to use MacCheckingReader to authenticate your data before
    decrypting and checking padding.  When used with
    AesCbcDecryptingReader alone, this class can make your software
    vulnerable to a padding oracle attack.  When in doubt, just use
    DecryptingReader.
    """
    def __init__(self, stream):
        """Stream must be a SizedInputStream."""
        SizedInputStream.__init__(self, len(stream))
        self.stream = stream
        self.stream_keep = stream
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
                # strip padding, leaks timing info for Padding Oracle
                # attacks
                if len(self.buffer) < 1:
                    raise DataDamagedException("Did not find valid padding at end of file")
                num_bytes = ord(self.buffer[-1])
                if num_bytes > 16 or len(self.buffer) < num_bytes:
                    raise DataDamagedException("Did not find valid padding at end of file")
                padding_bytes = self.buffer[-num_bytes:]
                if not all([ord(byte) == num_bytes for byte in padding_bytes]):
                    raise DataDamagedException("Did not find valid padding at end of file")
                self.buffer = self.buffer[:-num_bytes]
                return self.read_once(size)
        if self.buffer:
            chunk = self.buffer[:size]
            self.buffer = self.buffer[size:]
            return chunk
        return ''
    
    def close(self):
        self.buffer = None
        self.stream_keep.close()
        self.stream_keep = None
        self.stream = None


class AesCbcEncryptingReader(RewindableSizedInputStream):
    """Encrypts the stream with AES in CBC mode.
    
    Prefixes the ciphertext with a 16-byte salt and 16-byte IV.
    Generates a 256-bit key using PBKDF2 with 4096 rounds of
    HMAC-SHA-256.  Decrypt with DecryptingReader.
    
    Raises ValueError if input stream does not end on a 16-byte block
    boundary.  Use PaddingAddingReader to ensure stream ends on a
    16-byte block boundary.
    
    Production code should not provide values for the
    testing_only_salt, testing_only_iv, or test_only_key parameters.
    These are for testing purposes only.
    """
    def __init__(self, stream, passphrase, 
                 testing_only_salt=None, testing_only_iv=None, testing_only_key=None):
        """Stream must be a RewindableSizedInputStream.  Passphrase
        must be a byte string."""
        if len(stream) % 16:
            raise ValueError("Stream length must be a multiple of 16")
        stream_length = 16 + 16 + len(stream)
        RewindableSizedInputStream.__init__(self, stream_length)
        self.stream = stream
        self.stream_keep = stream
        self.salt = testing_only_salt or os.urandom(16)
        # For a discussion of CBC mode and how to choose IVs, see
        # NIST Special Publication 800-38A, 2001 Edition
        # Recommendation for Block Cipher Modes of Operation
        # http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
        self.iv = testing_only_iv or os.urandom(16)
        self.key = testing_only_key or pbkdf2_256bit(passphrase, self.salt)
        self.rewind()
    
    def read_once(self, size):
        if size < 1:
            raise ValueError("size must be greater than zero")
        if self.buffer:
            chunk = self.buffer[:size]
            self.buffer = self.buffer[size:]
            return chunk
        if self.stream:
            bytes_needed = size
            if bytes_needed % 16:
                bytes_needed += 16 - bytes_needed % 16 # round up
            chunk = self.stream.read(bytes_needed)
            if len(chunk) != bytes_needed:
                self.stream = None
            if len(chunk) % 16:
                raise ValueError("Data ended in middle of block.")
            self.buffer = self.aes.encrypt(chunk)
            return self.read_once(size)
        return ''
    
    def rewind(self):
        self.aes = AES.new(self.key, AES.MODE_CBC, self.iv)
        self.buffer = self.salt + self.iv
        self.stream = self.stream_keep
        self.stream.rewind()
    
    def close(self):
        self.buffer = None
        self.aes = None
        self.stream_keep.close()
        self.stream_keep = None
        self.stream = None


class AesCbcDecryptingReader(SizedInputStream):
    """Decrypts a stream that was encrypted with EncryptingReader.
    
    Removes the 16-byte salt and 16-byte IV from the beginning of the
    ciphertext.  Generates a 256-bit key using PBKDF2 with 4096 rounds
    of HMAC-SHA-256.  Decrypts the stream using AES in CBC mode.
    Raises DataTruncatedException if file is too short to contain
    expected header or the file ends in the middle of a block.
    
    Production code should not provide a value for the
    testing_only_key parameter.  This is for testing purposes only.
    """
    def __init__(self, stream, passphrase, testing_only_key=None):
        """Stream must be a SizedInputStream.  Passphrase must be a
        byte string."""
        if len(stream) < 32:
            raise DataTruncatedException("File too short to contain header")
        stream_length = -16 - 16 + len(stream)
        SizedInputStream.__init__(self, stream_length)
        self.stream = stream
        self.stream_keep = stream
        header = stream.read(32)
        if len(header) != 32:
            raise DataTruncatedException("Unable to read header")
        salt = header[:16]
        iv = header[16:]
        key = testing_only_key or pbkdf2_256bit(passphrase, salt)
        self.aes = AES.new(key, AES.MODE_CBC, iv)
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
                raise DataTruncatedException("Data ended in middle of block.")
            self.buffer = self.buffer + self.aes.decrypt(chunk)
            return self.read_once(size)
        return ''
    
    def close(self):
        self.buffer = None
        self.aes = None
        self.stream_keep.close()
        self.stream_keep = None
        self.stream = None


class EncryptingReader(RewindableSizedInputStream):
    """Encrypts the stream with AES in CBC mode.
    
    This is a convenience class that transforms the plaintext into
    ciphertext using a pipeline of PaddingAddingReader,
    AesCbcEncryptingReader, and MacAddingReader.
    
    Production code should not provide values for the
    testing_only_salt, testing_only_iv, or test_only_key parameters.
    These are for testing purposes only.
    """
    def __init__(self, stream, passphrase,
                 testing_only_salt=None, testing_only_iv=None, testing_only_key=None):
        s1 = PaddingAddingReader(stream)
        s2 = AesCbcEncryptingReader(s1, passphrase, testing_only_salt, testing_only_iv, testing_only_key)
        s3 = MacAddingReader(s2, passphrase, testing_only_salt, testing_only_key)
        RewindableSizedInputStream.__init__(self, len(s3))
        self.stream = s3
    
    def read_once(self, size):
        return self.stream.read_once(size)
    
    def rewind(self):
        self.stream.rewind()
    
    def close(self):
        self.stream.close()
        self.stream = None


class DecryptingReader(SizedInputStream):
    """Decrypts the stream with AES in CBC mode.
    
    This is a convenience class that transforms the ciphertext into
    plaintext using a pipeline of MacCheckingReader,
    AesCbcDecryptingReader, and PaddingStrippingReader.  Due to
    padding, the stream may yield up to 16 bytes less than the value
    of len(stream).
    
    Production code should not provide a value for the
    testing_only_key parameter.  This is for testing purposes only.
    """
    def __init__(self, stream, passphrase, testing_only_key=None):
        s1 = MacCheckingReader(stream, passphrase, testing_only_key)
        s2 = AesCbcDecryptingReader(s1, passphrase, testing_only_key)
        s3 = PaddingStrippingReader(s2)
        SizedInputStream.__init__(self, len(s3))
        self.stream = s3
    
    def read_once(self, size):
        return self.stream.read_once(size)
    
    def rewind(self):
        self.stream.rewind()
    
    def close(self):
        self.stream.close()
        self.stream = None


def pbkdf2_256bit(passphrase, salt, rounds=4096):
    """Converts a unicode passphrase into a 32-byte key using RFC2898
    PBKDF2 with 4096 rounds of HMAC-SHA-256.  Passphrase and salt must
    be byte strings."""
    passphrase_bytes = passphrase.encode('utf-8')
    prf = lambda p, data: hmac.new(p, data, digestmod=hashlib.sha256).digest()
    block = prf(passphrase_bytes, salt + '\x00\x00\x00\x01')
    (a,b,c,d,e,f,g,h) = struct.unpack('LLLLLLLL', block)
    for x in xrange(1, rounds):
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
            passphrase = open(passphrasefilename, 'rb').read().strip()
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
        print "AES CBC-mode encryption tool with HMAC-SHA256-PBKDF2, v" + __version__
        print "Usage: chlorocrypt -e|-d [INFILE [OUTFILE [PASSPHRASEFILE]]]"
        return 1

def encrypt(passphrase, infile_reader, outfile):
    encrypted = EncryptingReader(infile_reader, passphrase)
    while True:
        chunk = encrypted.read(65536)
        if not chunk:
            break
        outfile.write(chunk)
    return 0

def decrypt(passphrase, infile_reader, outfile):
    decrypted = DecryptingReader(infile_reader, passphrase)
    while True:
        chunk = decrypted.read(65536)
        if not chunk:
            break
        outfile.write(chunk)
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
