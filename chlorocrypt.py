#!/usr/bin/env python
"""
Command-line tool for encrypting and decrypting files.  Uses AES in
CBC mode for confidentiality.  The passphrase is converted to a key
using the PBKDF2 algorithm (rfc2898) and SHA-256 HMAC.  File integrity
is verified with an SHA-256 HMAC.

Tested under Python 2.7.

For faster operation, install the PyCrypto library:
http://www.dlitz.net/software/pycrypto/
http://www.voidspace.org.uk/python/modules.shtml#pycrypto
"""

__author__ = 'Michael Leonhard'
__license__ = 'Copyright (C) 2011 Rest Backup LLC.  Use of this software is subject to the RestBackup.com Terms of Use, http://www.restbackup.com/terms'
__version__ = '1.2'

import getpass
import hmac
import hashlib
import os
import os.path
import re
import struct
import sys
import unittest

try:
    from Crypto.Cipher import AES
except ImportError:
    print >>sys.stderr, "Using pyaes. Install PyCrypto for better performance."
    import pyaes as AES

class DataDamagedException(Exception): pass

class DataTruncatedException(DataDamagedException): pass

class BadMacException(DataDamagedException): pass

class SizedStreamReaderInterface():
    def __init__(self, total_bytes):
        self.total_bytes = total_bytes
        self.read_buffer = ''
    
    def read(self, size):
        """Reads the stream's data source and returns a non-unicode
        string up to size bytes.  Returns less than size bytes only on
        EOF.  Returns '' on EOF.  Size must be an integer greater than
        zero.  Raises IOError on error."""
        if not isinstance(size, int) or size < 1:
            raise ValueError("size must be an integer greater than zero")
        while(len(self.read_buffer) < size):
            bytes_needed = size - len(self.read_buffer)
            chunk = self.read_once(bytes_needed)
            if not chunk:
                break
            self.read_buffer = self.read_buffer + chunk
        
        chunk = self.read_buffer[:size]
        self.read_buffer = self.read_buffer[size:]
        return chunk
    
    def read_once(self, size):
        """Reads the stream's data source and returns a non-unicode
        string up to size bytes.  May return less than size bytes.
        Returns '' on EOF.  Size must be an integer greater than zero.
        Raises IOError on error."""
        pass
    
    def get_total_bytes(self):
        """Returns the total number of bytes that may be read from the stream"""
        return self.total_bytes
    
class StringReader():
    def __init__(self, data):
        if not isinstance(data, str):
            raise TypeError('StringReader supports only str data')
        self.data = data
        self.total_bytes = len(data)
    
    def read(self, size):
        if self.data:
            chunk = self.data[:size]
            self.data = self.data[size:]
            if not self.data:
                self.data = None
            return chunk
        else:
            return ''
    
    def read_once(self, size):
        return self.read(size)
    
    def get_total_bytes(self):
        return self.total_bytes

class FileObjectReader():
    def __init__(self, f, size=1024):
        self.file = f
        self.total_bytes = size
    
    def read(self, size):
        if self.file == None:
            return ''
        chunk = self.file.read(size)
        if len(chunk) == 0:
            self.file.close()
            self.file = None
        return chunk
    
    def read_once(self, size):
        return self.read(size)
    
    def get_total_bytes(self):
        return self.total_bytes
    
    def close(self):
        self.file.close()
        self.file = None

class FileReader(FileObjectReader):
    def __init__(self, filename):
        f = open(filename, 'rb')
        size = os.path.getsize(filename)
        FileObjectReader.__init__(self, f, size)

class MacAddingReader(SizedStreamReaderInterface):
    """Adds a SHA-256 HMAC to the provided stream.
    
    Prefixes the stream with a 16-byte salt.  Generates a 256-bit key
    using PBKDF2 with 1000 rounds of HMAC-SHA-256.  Appends a 32-byte
    SHA-256 HMAC to the stream.  Check it with MacCheckingReader.
    """
    def __init__(self, reader, passphrase, salt=None, key=None):
        total_bytes = 16 + reader.get_total_bytes() + 32
        SizedStreamReaderInterface.__init__(self, total_bytes)
        self.reader = reader
        if not salt:
            salt = os.urandom(16)
        self.prefix = salt
        if not key:
            key = pbkdf2_256bit(passphrase, salt)
        self.mac = hmac.new(key, digestmod=hashlib.sha256)
    
    def read_once(self, size):
        if self.prefix:
            chunk = self.prefix[:size]
            self.prefix = self.prefix[size:]
            return chunk
        if self.reader:
            chunk = self.reader.read(size)
            if len(chunk) != 0:
                self.mac.update(chunk)
                return chunk
            else:
                self.reader = None
                self.suffix = self.mac.digest()
                self.mac = None
        if self.suffix:
            chunk = self.suffix[:size]
            self.suffix = self.suffix[size:]
            return chunk
        return ''

class MacCheckingReader(SizedStreamReaderInterface):
    """Checks the SHA-256 HMAC on the stream.
    
    Removes the 16-byte salt prefix and verifies the 32-byte SHA-256
    HMAC appended on the stream.  Create such a stream with
    MacAddingReader.
    
    Raises DataTruncatedException if file is too short to contain
    expected header and footer.  Raises BadMacException at EOF if data
    has been damaged or passphrase is incorrect.
    """
    def __init__(self, reader, passphrase, key=None):
        total_bytes = reader.get_total_bytes() - 48
        SizedStreamReaderInterface.__init__(self, total_bytes)
        self.reader = reader
        salt = reader.read(16)
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
        if self.reader:
            bytes_needed = size + 32 - len(self.buffer)
            chunk = self.reader.read(bytes_needed)
            self.buffer = self.buffer + chunk
            if len(chunk) != bytes_needed: # EOF
                self.reader = None
                if len(self.buffer) < 32:
                    raise DataTruncatedException("File does not contain MAC.")
                digest1 = self.buffer[-32:]
                self.buffer = self.buffer[:-32]
                self.mac.update(self.buffer)
                digest2 = self.mac.digest()
                self.mac = None
                if digest1 != digest2:
                    raise BadMacException("The file has been damaged or the passphrase is incorrect.")
            return self.read_once(size)
        if self.buffer:
            chunk = self.buffer[:size]
            self.buffer = self.buffer[size:]
            return chunk
        return ''

class PaddingAddingReader(SizedStreamReaderInterface):
    """Adds padding so the resulting stream size is a multiple of 16
    bytes."""
    def __init__(self, reader):
        data_bytes = reader.get_total_bytes()
        # Pad with 0x80 and enough nulls to fill last block
        padding = '\x80' + '\x00' * (15 - data_bytes % 16)
        total_bytes = data_bytes + len(padding)
        assert(total_bytes % 16 == 0)
        SizedStreamReaderInterface.__init__(self, total_bytes)
        self.reader = reader
        self.suffix = padding
    
    def read_once(self, size):
        if self.reader:
            chunk = self.reader.read(size)
            if len(chunk) == size:
                return chunk
            else: # EOF
                self.reader = None
                self.suffix = chunk + self.suffix
                return self.read_once(size)
        else:
            chunk = self.suffix[:size]
            self.suffix = self.suffix[size:]
            return chunk

class PaddingStrippingReader(SizedStreamReaderInterface):
    """Removes padding from the end of the stream.  The resulting
    stream may be up to 16 bytes shorter than the number returned by
    get_total_bytes().
    
    Raises DataDamagedException if no padding is found at end of
    stream.
    """
    def __init__(self, reader):
        total_bytes = reader.get_total_bytes()
        SizedStreamReaderInterface.__init__(self, total_bytes)
        self.reader = reader
        self.buffer = ''
    
    def read_once(self, size):
        if size < 1:
            raise ValueError("size must be greater than zero")
        
        if len(self.buffer) >= size + 16:
            chunk = self.buffer[:size]
            self.buffer = self.buffer[size:]
            return chunk
        if self.reader:
            bytes_needed = size + 16 - len(self.buffer)
            chunk = self.reader.read(bytes_needed)
            if len(chunk) == bytes_needed:
                self.buffer = self.buffer + chunk
                result = self.buffer[:size]
                self.buffer = self.buffer[size:]
                assert(len(self.buffer) == 16)
                return result
            else: # EOF
                self.reader = None
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
                    raise DataDamagedException("Did not find padding at end of file.  Passphrase is incorrect or file is damaged.")
        if self.buffer:
            chunk = self.buffer[:size]
            self.buffer = self.buffer[size:]
            return chunk
        return ''

class EncryptingReader(SizedStreamReaderInterface):
    """Encrypts the stream with AES in CBC mode.
    
    Prefixes the stream with a 16-byte salt and a 16-byte IV.
    Generates a 256-bit key using PBKDF2 with 1000 rounds of
    HMAC-SHA-256.  Decrypt with DecryptingReader.
    
    Raises ValueError if input stream does not end on a 16-byte block
    boundary.
    """
    def __init__(self, reader, passphrase, salt=None, iv=None, key=None):
        data_bytes = reader.get_total_bytes()
        if data_bytes % 16:
            raise ValueError("Total bytes in data stream must be a multiple of 16.")
        total_bytes = 16 + 16 + data_bytes
        SizedStreamReaderInterface.__init__(self, total_bytes)
        self.reader = reader
        if not salt:
            salt = os.urandom(16)
        if not iv:
            # For a discussion of CBC mode and how to choose IVs, see
            # NIST Special Publication 800-38A, 2001 Edition
            # Recommendation for Block Cipher Modes of Operation
            # http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
            iv = os.urandom(16)
        self.buffer = salt + iv
        if not key:
            key = pbkdf2_256bit(passphrase, salt)
        self.aes = AES.new(key, AES.MODE_CBC, iv)
    
    def read_once(self, size):
        if size < 1:
            raise ValueError("size must be greater than zero")
        elif self.buffer:
            chunk = self.buffer[:size]
            self.buffer = self.buffer[size:]
            return chunk
        elif self.reader:
            bytes_needed = size
            if bytes_needed % 16:
                bytes_needed += 16 - bytes_needed % 16 # round up to multiple of 16
            chunk = self.reader.read(bytes_needed)
            if len(chunk) != bytes_needed:
                self.reader = None
            if len(chunk) % 16:
                raise DataDamagedException("Stream ended in middle of 16-byte block.")
            self.buffer = self.aes.encrypt(chunk)
            return self.read_once(size)
        else:
            return ''

class DecryptingReader(SizedStreamReaderInterface):
    """Decrypts the stream with AES in CBC mode.
    
    Removes 16-byte salt and a 16-byte IV prefixes.  Generates a
    256-bit key using PBKDF2 with 1000 rounds of HMAC-SHA-256.
    Encrypt with EncryptingReader.  Raises DataTruncatedException if
    file is too short to contain expected header or the file ends in
    the middle of a block.
    """
    def __init__(self, reader, passphrase, key=None):
        if reader.get_total_bytes() < 32:
            raise DataTruncatedException("File is too short to contain 32-byte header.")
        total_bytes = reader.get_total_bytes() - 32
        SizedStreamReaderInterface.__init__(self, total_bytes)
        self.reader = reader
        salt = reader.read(16)
        assert(len(salt) == 16)
        iv = reader.read(16)
        assert(len(iv) == 16)
        if not key:
            key = pbkdf2_256bit(passphrase, salt)
        self.aes = AES.new(key, AES.MODE_CBC, iv)
        self.buffer = ''
    
    def read_once(self, size):
        if size < 1:
            raise ValueError("size must be greater than zero")
        if self.buffer:
            chunk = self.buffer[:size]
            self.buffer = self.buffer[size:]
            return chunk
        if self.reader:
            bytes_needed = size - len(self.buffer)
            if bytes_needed % 16:
                bytes_needed += 16 - bytes_needed % 16 # round up to multiple of 16
            chunk = self.reader.read(bytes_needed)
            if len(chunk) != bytes_needed: # EOF
                self.reader = None
            if len(chunk) % 16:
                raise DataDamagedException("File is damaged and ends prematurely, in the middle of a block.")
            self.buffer = self.buffer + self.aes.decrypt(chunk)
            return self.read_once(size)
        return ''

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
        infile_reader = FileObjectReader(sys.stdin)
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
        print "Usage: aescbc -e|-d [INFILE [OUTFILE [PASSPHRASEFILE]]]"
        return 1

def encrypt(passphrase, infile_reader, outfile):
    mac_adding_reader = MacAddingReader(infile_reader, passphrase)
    padding_adding_reader = PaddingAddingReader(mac_adding_reader)
    encrypting_reader = EncryptingReader(padding_adding_reader, passphrase)
    while True:
        chunk = encrypting_reader.read(1024)
        if not chunk:
            break
        outfile.write(chunk)
    return 0

def decrypt(passphrase, infile_reader, outfile):
    decrypting_reader = DecryptingReader(infile_reader, passphrase)
    padding_stripping_reader = PaddingStrippingReader(decrypting_reader)
    mac_checking_reader = MacCheckingReader(padding_stripping_reader, passphrase)
    while True:
        chunk = mac_checking_reader.read(1024)
        if not chunk:
            break
        outfile.write(chunk)
    return 0

class TestStringReader(unittest.TestCase):
    def runTest(self):
        # non-string
        self.assertRaises(TypeError, StringReader, 123)
        # unicode string
        self.assertRaises(TypeError, StringReader, u'abc')
        # empty string
        reader = StringReader('')
        self.assertEqual(reader.get_total_bytes(), 0)
        self.assertEqual(reader.read(1024), '')
        # one byte
        reader = StringReader('a')
        self.assertEqual(reader.get_total_bytes(), 1)
        self.assertEqual(reader.read(1024), 'a')
        self.assertEqual(reader.read(1024), '')
        # seven bytes
        reader = StringReader('1234567')
        self.assertEqual(reader.get_total_bytes(), 7)
        self.assertEqual(reader.read(1), '1')
        self.assertEqual(reader.read(3), '234')
        self.assertEqual(reader.read(1024), '567')
        self.assertEqual(reader.read(1024), '')
        # 1 MB
        reader = StringReader('a' * 1024*1024)
        self.assertEqual(reader.get_total_bytes(), 1024*1024)
        self.assertEqual(reader.read(1), 'a')
        self.assertEqual(reader.read(1023), 'a'*1023)
        self.assertEqual(reader.read(1023*1024), 'a'*1023*1024)
        self.assertEqual(reader.read(1), '')

class TestFileReader(unittest.TestCase):
    def setUp(self):
        # This is os.tempnam() without the RuntimeWarning
        import tempfile
        file = tempfile.NamedTemporaryFile()
        self.filename = file.name
        file.close()
    def runTest(self):
        # missing file
        self.assertRaises(IOError, FileReader, self.filename)
        # empty file
        open(self.filename, 'wb').close()
        reader = FileReader(self.filename)
        self.assertEqual(reader.get_total_bytes(), 0)
        self.assertEqual(reader.read(1024), '')
        # one byte
        file = open(self.filename, 'wb')
        file.write('a')
        file.close()
        reader = FileReader(self.filename)
        self.assertEqual(reader.get_total_bytes(), 1)
        self.assertEqual(reader.read(1024), 'a')
        self.assertEqual(reader.read(1024), '')
        # seven bytes
        file = open(self.filename, 'wb')
        file.write('1234567')
        file.close()
        reader = FileReader(self.filename)
        self.assertEqual(reader.get_total_bytes(), 7)
        self.assertEqual(reader.read(1), '1')
        self.assertEqual(reader.read(3), '234')
        self.assertEqual(reader.read(1024), '567')
        self.assertEqual(reader.read(1024), '')
        # 1 MB
        file = open(self.filename, 'wb')
        file.write('a' * 1024*1024)
        file.close()
        reader = FileReader(self.filename)
        self.assertEqual(reader.get_total_bytes(), 1024*1024)
        self.assertEqual(reader.read(1), 'a')
        self.assertEqual(reader.read(1023), 'a'*1023)
        self.assertEqual(reader.read(1023*1024), 'a'*1023*1024)
        self.assertEqual(reader.read(1), '')
    def tearDown(self):
        os.remove(self.filename)

class TestMacAddingReader(unittest.TestCase):
    def runTest(self):
        passphrase = 'passphrase'
        salt = 's' * 16
        key = 'k' * 32
        # no bytes
        data = ''
        mac = 'pK2ONA4yvx2RYAXLHcknlRSIl5ZeNq5WwK3DV0dLU3I='.decode('base64')
        reader = MacAddingReader(StringReader(data), passphrase, salt, key)
        self.assertEqual(reader.get_total_bytes(), 16 + 32)
        self.assertEqual(reader.read(16 + 32), salt + mac)
        self.assertEqual(reader.read(1), '')
        # one byte
        data = 'a'
        mac = '2L0VNypDtMX/4XKb7E7WTMnXn2gPaPzaQJULnlmfeQY='.decode('base64')
        reader = MacAddingReader(StringReader(data), passphrase, salt, key)
        self.assertEqual(reader.get_total_bytes(), 16 + 1 + 32)
        self.assertEqual(reader.read(16 + 1 + 32), salt + 'a' + mac)
        self.assertEqual(reader.read(1), '')
        # seven bytes
        data = '1234567'
        mac = 'Bx8mtVIWmT4OcNnbzI0X58fFrCxxPfFss8WLq9iqNjo='.decode('base64')
        reader = MacAddingReader(StringReader(data), passphrase, salt, key)
        self.assertEqual(reader.get_total_bytes(), 16 + 7 + 32)
        self.assertEqual(reader.read(16), salt)
        self.assertEqual(reader.read(1), '1')
        self.assertEqual(reader.read(2), '23')
        self.assertEqual(reader.read(4), '4567')
        self.assertEqual(reader.read(32), mac)
        self.assertEqual(reader.read(1), '')
        # 1 MB
        data = 'a' * 1024*1024
        mac = 'YQpcosYIuPVCQkP7gRXBwhCe0HYXXymYoCyKU162wmY='.decode('base64')
        reader = MacAddingReader(StringReader(data), passphrase, salt, key)
        self.assertEqual(reader.get_total_bytes(), 16 + 1024*1024 + 32)
        self.assertEqual(reader.read(16), salt)
        self.assertEqual(reader.read(1), 'a')
        self.assertEqual(reader.read(1023), 'a'*1023)
        self.assertEqual(reader.read(1023*1024), 'a'*1023*1024)
        self.assertEqual(reader.read(32), mac)
        self.assertEqual(reader.read(1), '')
        # seven bytes with real key
        data = '1234567'
        mac = 'pjhdkY3tLUUFuc3Yy7XNGv9OnNcRrvIdePDfsTwC5Jc='.decode('base64')
        reader = MacAddingReader(StringReader(data), passphrase, salt)
        self.assertEqual(reader.get_total_bytes(), 16 + 7 + 32)
        self.assertEqual(reader.read(16), salt)
        self.assertEqual(reader.read(7), '1234567')
        self.assertEqual(reader.read(32), mac)
        self.assertEqual(reader.read(1), '')
        # salt is random
        salt1 = MacAddingReader(StringReader(data), passphrase).read(16)
        salt2 = MacAddingReader(StringReader(data), passphrase).read(16)
        self.assertNotEqual(salt1, salt2)

class TestMacCheckingReader(unittest.TestCase):
    def runTest(self):
        passphrase = 'passphrase'
        salt = 's' * 16
        key = 'k' * 32
        # no salt
        self.assertRaises(DataTruncatedException, MacCheckingReader, StringReader(''), passphrase, key)
        # no mac
        reader = MacCheckingReader(StringReader(salt), passphrase, key)
        self.assertRaises(DataTruncatedException, reader.read, 1)
        # no bytes
        data = ''
        mac = 'pK2ONA4yvx2RYAXLHcknlRSIl5ZeNq5WwK3DV0dLU3I='.decode('base64')
        reader = MacCheckingReader(StringReader(salt + data + mac), passphrase, key)
        self.assertEqual(reader.get_total_bytes(), 0)
        self.assertEqual(reader.read(1), '')
        # one byte
        data = 'a'
        mac = '2L0VNypDtMX/4XKb7E7WTMnXn2gPaPzaQJULnlmfeQY='.decode('base64')
        reader = MacCheckingReader(StringReader(salt + data + mac), passphrase, key)
        self.assertEqual(reader.get_total_bytes(), 1)
        self.assertRaises(ValueError, reader.read, 0)
        self.assertRaises(ValueError, reader.read, -1)
        self.assertEqual(reader.read(1024), 'a')
        self.assertEqual(reader.read(1), '')
        self.assertEqual(reader.read(1), '')
        # seven bytes
        data = '1234567'
        mac = 'Bx8mtVIWmT4OcNnbzI0X58fFrCxxPfFss8WLq9iqNjo='.decode('base64')
        reader = MacCheckingReader(StringReader(salt + data + mac), passphrase, key)
        self.assertEqual(reader.get_total_bytes(), 7)
        self.assertEqual(reader.read(1), '1')
        self.assertEqual(reader.read(2), '23')
        self.assertEqual(reader.read(4), '4567')
        self.assertEqual(reader.read(1), '')
        self.assertEqual(reader.read(1), '')
        # 1 MB
        data = 'a' * 1024*1024
        mac = 'YQpcosYIuPVCQkP7gRXBwhCe0HYXXymYoCyKU162wmY='.decode('base64')
        reader = MacCheckingReader(StringReader(salt + data + mac), passphrase, key)
        self.assertEqual(reader.get_total_bytes(), 1024*1024)
        self.assertEqual(reader.read(1), 'a')
        self.assertEqual(reader.read(1023), 'a'*1023)
        self.assertEqual(reader.read(1024*1024), 'a'*1023*1024)
        self.assertEqual(reader.read(1), '')
        self.assertEqual(reader.read(1), '')
        # seven bytes with real key
        data = '1234567'
        mac = 'pjhdkY3tLUUFuc3Yy7XNGv9OnNcRrvIdePDfsTwC5Jc='.decode('base64')
        reader = MacCheckingReader(StringReader(salt + data + mac), passphrase)
        self.assertEqual(reader.get_total_bytes(), 7)
        self.assertEqual(reader.read(7), '1234567')
        self.assertEqual(reader.read(1), '')
        self.assertEqual(reader.read(1), '')

class TestPaddingAddingReader(unittest.TestCase):
    def runTest(self):
        # no bytes
        data = ''
        reader = PaddingAddingReader(StringReader(data))
        self.assertEqual(reader.get_total_bytes(), 16)
        self.assertEqual(reader.read(100), '\x80' + '\x00' * 15)
        self.assertEqual(reader.read(1), '')
        # one byte
        data = 'a'
        reader = PaddingAddingReader(StringReader(data))
        self.assertEqual(reader.get_total_bytes(), 16)
        self.assertEqual(reader.read(100), data + '\x80' + '\x00' * 14)
        self.assertEqual(reader.read(1), '')
        # seven bytes
        data = '1234567'
        reader = PaddingAddingReader(StringReader(data))
        self.assertEqual(reader.get_total_bytes(), 16)
        self.assertEqual(reader.read(100), data + '\x80' + '\x00' * 8)
        self.assertEqual(reader.read(1), '')
        # fifteen bytes
        data = '0123456789abcde'
        reader = PaddingAddingReader(StringReader(data))
        self.assertEqual(reader.get_total_bytes(), 16)
        self.assertEqual(reader.read(100), data + '\x80')
        self.assertEqual(reader.read(1), '')
        # sixteen bytes
        data = '0123456789abcdef'
        reader = PaddingAddingReader(StringReader(data))
        self.assertEqual(reader.get_total_bytes(), 32)
        self.assertEqual(reader.read(2), '01')
        self.assertEqual(reader.read(17), '23456789abcdef' + '\x80' + '\x00' * 2)
        self.assertEqual(reader.read(100), '\x00' * 13)
        self.assertEqual(reader.read(1), '')
        # 1 MB
        data = 'a' * 1024*1024
        reader = PaddingAddingReader(StringReader(data))
        self.assertEqual(reader.get_total_bytes(), 1024*1024 + 16)
        self.assertEqual(reader.read(1), 'a')
        self.assertEqual(reader.read(1023), 'a'*1023)
        self.assertEqual(reader.read(1024*1024), 'a'*1023*1024 + '\x80' + '\x00' * 15)
        self.assertEqual(reader.read(1), '')

class TestPaddingStrippingReader(unittest.TestCase):
    def runTest(self):
        # no padding
        reader = PaddingStrippingReader(StringReader(''))
        self.assertRaises(DataDamagedException, reader.read, 1)
        # minimal padding
        reader = PaddingStrippingReader(StringReader('\x80'))
        self.assertEqual(reader.read(1), '')
        # no bytes
        data = ''
        padded_data = '\x80' + '\x00' * 15
        reader = PaddingStrippingReader(StringReader(padded_data))
        self.assertEqual(reader.get_total_bytes(), 16)
        self.assertEqual(reader.read(100), data)
        self.assertEqual(reader.read(1), '')
        # one byte
        data = 'a'
        padded_data = 'a\x80' + '\x00' * 14
        reader = PaddingStrippingReader(StringReader(padded_data))
        self.assertEqual(reader.get_total_bytes(), 16)
        self.assertEqual(reader.read(100), data)
        self.assertEqual(reader.read(1), '')
        # seven bytes
        data = '1234567'
        padded_data = '1234567\x80' + '\x00' * 8
        reader = PaddingStrippingReader(StringReader(padded_data))
        self.assertEqual(reader.get_total_bytes(), 16)
        self.assertEqual(reader.read(100), data)
        self.assertEqual(reader.read(1), '')
        # seven bytes, not aligned
        data = '1234567'
        padded_data = '1234567\x80\x00'
        reader = PaddingStrippingReader(StringReader(padded_data))
        self.assertEqual(reader.get_total_bytes(), 9)
        self.assertEqual(reader.read(1), '1')
        self.assertEqual(reader.read(2), '23')
        self.assertEqual(reader.read(4), '4567')
        self.assertEqual(reader.read(1), '')
        # fifteen bytes
        data = '0123456789abcde'
        padded_data = '0123456789abcde\x80'
        reader = PaddingStrippingReader(StringReader(padded_data))
        self.assertEqual(reader.get_total_bytes(), 16)
        self.assertEqual(reader.read(100), data)
        self.assertEqual(reader.read(1), '')
        # sixteen bytes
        data = '0123456789abcdef'
        padded_data = '0123456789abcdef\x80' + '\x00' * 15
        reader = PaddingStrippingReader(StringReader(padded_data))
        self.assertEqual(reader.get_total_bytes(), 32)
        self.assertEqual(reader.read(2), '01')
        self.assertEqual(reader.read(17), '23456789abcdef')
        self.assertEqual(reader.read(1), '')
        # seventeen bytes
        data = '0123456789abcdefx'
        padded_data = '0123456789abcdefx\x80' + '\x00' * 14
        reader = PaddingStrippingReader(StringReader(padded_data))
        self.assertEqual(reader.get_total_bytes(), 32)
        self.assertEqual(reader.read(2), '01')
        self.assertEqual(reader.read(17), '23456789abcdefx')
        self.assertEqual(reader.read(1), '')
        # 1 MB
        data = 'a' * 1024*1024
        padded_data = data +'\x80' + '\x00' * 15
        reader = PaddingStrippingReader(StringReader(padded_data))
        self.assertEqual(reader.get_total_bytes(), 1024*1024 + 16)
        self.assertEqual(reader.read(1), 'a')
        self.assertEqual(reader.read(1023), 'a'*1023)
        self.assertEqual(reader.read(1024*1024), 'a'*1023*1024)
        self.assertEqual(reader.read(1), '')
        # seventeen bytes, minimal padding
        data = '0123456789abcdefx'
        padded_data = '0123456789abcdefx\x80'
        reader = PaddingStrippingReader(StringReader(padded_data))
        self.assertEqual(reader.get_total_bytes(), 18)
        self.assertEqual(reader.read(2), '01')
        self.assertEqual(reader.read(100), '23456789abcdefx')
        self.assertEqual(reader.read(1), '')
        # seventeen bytes, missing padding
        data = '0123456789abcdefx'
        padded_data = '0123456789abcdefx'
        reader = PaddingStrippingReader(StringReader(padded_data))
        self.assertEqual(reader.get_total_bytes(), 17)
        self.assertEqual(reader.read(1), '0')
        self.assertRaises(DataDamagedException, reader.read, 1)

class TestEncryptingReader(unittest.TestCase):
    def runTest(self):
        passphrase = 'passphrase'
        salt = 's' * 16
        iv = 'i' * 16
        key = 'k' * 32
        # no bytes
        data = ''
        ciphertext = ''
        reader = EncryptingReader(StringReader(data), passphrase, salt, iv, key)
        self.assertEqual(reader.get_total_bytes(), 16 + 16)
        self.assertEqual(reader.read(16 + 16), salt + iv + ciphertext)
        self.assertEqual(reader.read(1), '')
        # one byte
        data = 'a'
        self.assertRaises(ValueError, EncryptingReader, StringReader(data), passphrase)
        # sixteen bytes
        data = '0123456789abcdef'
        ciphertext = 'Rx5kzFEEgumDBeMJG3j9vQ=='.decode('base64')
        reader = EncryptingReader(StringReader(data), passphrase, salt, iv, key)
        self.assertEqual(reader.get_total_bytes(), 16 + 16 + 16)
        self.assertEqual(reader.read(16 + 16), salt + iv)
        self.assertEqual(reader.read(1024), ciphertext)
        self.assertEqual(reader.read(1), '')
        # 32 bytes
        data = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
        ciphertext = ('J5+ATEVX9bnkx4xhMf88LJq4iEwEgIV+Z/AW0h+fA8Y=').decode('base64')
        reader = EncryptingReader(StringReader(data), passphrase, salt, iv, key)
        self.assertEqual(reader.get_total_bytes(), 16 + 16 + 32)
        self.assertEqual(reader.read(16 + 16), salt + iv)
        self.assertEqual(reader.read(1024), ciphertext)
        self.assertEqual(reader.read(1), '')
        # sixteen bytes with real key
        data = '0123456789abcdef'
        ciphertext = 'u2VlDewnDNd+6AzfKDCb+g=='.decode('base64')
        reader = EncryptingReader(StringReader(data), passphrase, salt, iv)
        self.assertEqual(reader.get_total_bytes(), 16 + 16 + 16)
        self.assertEqual(reader.read(16 + 16), salt + iv)
        self.assertEqual(reader.read(1024), ciphertext)
        self.assertEqual(reader.read(1), '')
        # random
        reader1 = EncryptingReader(StringReader(data), passphrase)
        reader2 = EncryptingReader(StringReader(data), passphrase)
        self.assertNotEqual(reader1.read(16), reader2.read(16)) # salt
        self.assertNotEqual(reader1.read(16), reader2.read(16)) # iv
        self.assertNotEqual(reader1.read(16), reader2.read(16)) # ciphertext
        self.assertEqual(reader1.read(16), '')
        self.assertEqual(reader2.read(16), '')

class TestDecryptingReader(unittest.TestCase):
    def runTest(self):
        passphrase = 'passphrase'
        salt = 's' * 16
        iv = 'i' * 16
        key = 'k' * 32
        # no bytes
        reader = DecryptingReader(StringReader(salt + iv), passphrase, key)
        self.assertEqual(reader.get_total_bytes(), 0)
        self.assertEqual(reader.read(1), '')
        # partial block
        ciphertext = 'x'
        reader = DecryptingReader(StringReader(salt + iv + ciphertext), passphrase, key)
        self.assertEqual(reader.get_total_bytes(), 1)
        self.assertRaises(DataDamagedException, reader.read, 1)
        # sixteen bytes
        data = '0123456789abcdef'
        ciphertext = 'Rx5kzFEEgumDBeMJG3j9vQ=='.decode('base64')
        reader = DecryptingReader(StringReader(salt + iv + ciphertext), passphrase, key)
        self.assertEqual(reader.get_total_bytes(), 16)
        self.assertEqual(reader.read(1), '0')
        self.assertEqual(reader.read(100), '123456789abcdef')
        self.assertEqual(reader.read(1), '')
        # sixteen bytes, plus partial block
        data = '0123456789abcdef'
        ciphertext = 'Rx5kzFEEgumDBeMJG3j9vQ=='.decode('base64') + 'x'
        reader = DecryptingReader(StringReader(salt + iv + ciphertext), passphrase, key)
        self.assertEqual(reader.get_total_bytes(), 17)
        self.assertEqual(reader.read(1), '0')
        self.assertEqual(reader.read(15), '123456789abcdef')
        self.assertRaises(DataDamagedException, reader.read, 1)
        # 32 bytes
        data = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
        ciphertext = ('J5+ATEVX9bnkx4xhMf88LJq4iEwEgIV+Z/AW0h+fA8Y=').decode('base64')
        reader = DecryptingReader(StringReader(salt + iv + ciphertext), passphrase, key)
        self.assertEqual(reader.get_total_bytes(), 32)
        self.assertEqual(reader.read(1024), data)
        self.assertEqual(reader.read(1), '')
        # sixteen bytes with real key
        data = '0123456789abcdef'
        ciphertext = 'u2VlDewnDNd+6AzfKDCb+g=='.decode('base64')
        reader = DecryptingReader(StringReader(salt + iv + ciphertext), passphrase)
        self.assertEqual(reader.get_total_bytes(), 16)
        self.assertEqual(reader.read(1024), data)
        self.assertEqual(reader.read(1), '')


if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '--test':
        del sys.argv[1]
        unittest.main()
    else:
        sys.exit(main(sys.argv[1:]))
