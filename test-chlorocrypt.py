from restbackup import StringReader
from chlorocrypt import BadMacException
from chlorocrypt import DataDamagedException
from chlorocrypt import DataTruncatedException
from chlorocrypt import MacAddingReader
from chlorocrypt import MacCheckingReader
from chlorocrypt import PaddingAddingReader
from chlorocrypt import PaddingStrippingReader
from chlorocrypt import AesCbcEncryptingReader
from chlorocrypt import AesCbcDecryptingReader
from chlorocrypt import EncryptingReader
from chlorocrypt import DecryptingReader
from chlorocrypt import pbkdf2_256bit
import os
import unittest


class TestMacAddingReader(unittest.TestCase):
    def setUp(self):
        self.passphrase = 'passphrase'
        self.salt = 's' * 16
        self.key = 'k' * 32
        a_macs = ['lYfXRyLeGZ1f3TAwZcwXyd9u4YiFipS/tCKCzKa+as8=',
                  '0ZpdKMDXgcInldwIU5aR3b2zYaTTiSZkIAivDi9ZYTo=',
                  'mNf6xviWmLSIprpZSZjCDV6eMPvbLBf3yGufhVfn2xA=',
                  'xNl0cxGM+bgIcebN708B26zw2/cVUWauPuYN+cDgkX0=',
                  'DotXYegR3qdJ9pCFIjIGZ0JG5XgHG/rx8W3K+vvJiko=',
                  '1wbw90zUNYr1YR02JZR1igGEb7lmpLWRdPZm1BsQYpI=',
                  'KKyHoN2uNQ/sKOOD+aa4AMRf6wlHzrobU4xqrzgdXbg=',
                  '2boWTspGiLPqRIwqcqO0BWrqByZn/n5yrkhWmoBkUxk=',
                  'PVOuWYZjaHxSyqDgOs25D9TWVOBXa/twINsofuHt2s8=',
                  'Rf2YRH6Apa7V+sf2qa/JRWNh9DLFHnDPbMYxHelpCo0=',
                  'VDFlncTsT1hOPsWmJcpjsgdUOiRzWOLU3Jj3ifPUCPc=',
                  'DYXTYqPgYJF/yKfin2AwYJ49rtbSORUarUF4YLfwdCU=',
                  'bptfyfb+pL8TP+AngOUA6LjjPKJZJYY5ElSD9yaHFaY=',
                  'zn3HBIZUvvt2puvY0diJ2RmumaE9Mfyrx2HWfryzADE=',
                  'RhnMGzrsi+498DwF/LbTL9QblyohJ5M97mKCvm+jIr0=',
                  'YQpcosYIuPVCQkP7gRXBwhCe0HYXXymYoCyKU162wmY=',
                  'Pv8VoC3Y5DGZPcI3CNWgTUwm3GNRsmX1k163BFPXZjQ=']
        self.a_macs = [mac.decode('base64') for mac in a_macs]
    
    def test_no_bytes(self):
        data = StringReader('')
        mac = 'pK2ONA4yvx2RYAXLHcknlRSIl5ZeNq5WwK3DV0dLU3I='.decode('base64')
        reader = MacAddingReader(data, self.passphrase, self.salt, self.key)
        self.assertEqual(len(reader), 16 + 32)
        self.assertEqual(reader.read(16 + 32), self.salt + mac)
        self.assertEqual(reader.read(1), '')
    
    def test_one_byte(self):
        data = StringReader('a')
        mac = '2L0VNypDtMX/4XKb7E7WTMnXn2gPaPzaQJULnlmfeQY='.decode('base64')
        reader = MacAddingReader(data, self.passphrase, self.salt, self.key)
        self.assertEqual(len(reader), 16 + 1 + 32)
        self.assertEqual(reader.read(16), self.salt)
        self.assertEqual(reader.read(0), '')
        self.assertEqual(reader.read(1 + 32), 'a' + mac)
        self.assertEqual(reader.read(1), '')
    
    def test_seven_bytes(self):
        data = StringReader('1234567')
        mac = 'Bx8mtVIWmT4OcNnbzI0X58fFrCxxPfFss8WLq9iqNjo='.decode('base64')
        reader = MacAddingReader(data, self.passphrase, self.salt, self.key)
        self.assertEqual(len(reader), 16 + 7 + 32)
        self.assertEqual(reader.read(16), self.salt)
        self.assertEqual(reader.read(1), '1')
        self.assertEqual(reader.read(2), '23')
        self.assertEqual(reader.read(4), '4567')
        self.assertEqual(reader.read(32), mac)
        self.assertEqual(reader.read(1), '')
    
    def test_one_mb(self):
        data = StringReader('a' * 1024*1024)
        reader = MacAddingReader(data, self.passphrase, self.salt, self.key)
        self.assertEqual(len(reader), 16 + 1024*1024 + 32*16)
        self.assertEqual(reader.read(16), self.salt)
        self.assertEqual(reader.read(1), 'a')
        self.assertEqual(reader.read(65535), 'a'*65535)
        self.assertEqual(reader.read(32), self.a_macs.pop(0))
        for n in xrange(0, 14):
            self.assertEqual(reader.read(65536), 'a'*65536)
            self.assertEqual(reader.read(32), self.a_macs.pop(0))
        self.assertEqual(reader.read(65536), 'a'*65536)
        self.assertEqual(reader.read(32), self.a_macs.pop(0))
        self.assertEqual(len(self.a_macs), 1)
        self.assertEqual(reader.read(1), '')
    
    def test_one_mb_plus(self):
        data = StringReader('a' * (1024*1024 + 42))
        reader = MacAddingReader(data, self.passphrase, self.salt, self.key)
        self.assertEqual(len(reader), 16 + 1024*1024 + 42 + 32*17)
        self.assertEqual(reader.read(16), self.salt)
        self.assertEqual(reader.read(1), 'a')
        self.assertEqual(reader.read(65535), 'a'*65535)
        self.assertEqual(reader.read(32), self.a_macs.pop(0))
        for n in xrange(0, 14):
            self.assertEqual(reader.read(65536), 'a'*65536)
            self.assertEqual(reader.read(32), self.a_macs.pop(0))
        self.assertEqual(reader.read(65536), 'a'*65536)
        self.assertEqual(reader.read(32), self.a_macs.pop(0))
        block = reader.read(1024*1024)
        self.assertEqual(block[:42], 'a'*42)
        self.assertEqual(block[42:], self.a_macs.pop(0))
        self.assertEqual(len(self.a_macs), 0)
        self.assertEqual(reader.read(1), '')
    
    def test_real_key(self):
        data = StringReader('1234567')
        mac = '+6ZSbYn460hpoowKHZkwTbxQFWkUAjlpXsbKByZGA+4='.decode('base64')
        reader = MacAddingReader(data, self.passphrase, self.salt)
        self.assertEqual(len(reader), 16 + 7 + 32)
        self.assertEqual(reader.read(16), self.salt)
        self.assertEqual(reader.read(7), '1234567')
        self.assertEqual(reader.read(32), mac)
        self.assertEqual(reader.read(1), '')
    
    def test_random_salt(self):
        data = '1234567'
        salt1 = MacAddingReader(StringReader(data), self.passphrase).read(16)
        salt2 = MacAddingReader(StringReader(data), self.passphrase).read(16)
        self.assertNotEqual(salt1, salt2)

    def test_read_all(self):
        mac = 'Bx8mtVIWmT4OcNnbzI0X58fFrCxxPfFss8WLq9iqNjo='.decode('base64')
        input = StringReader('1234567')
        reader = MacAddingReader(input, self.passphrase, self.salt, self.key)
        self.assertEqual(reader.read(), self.salt + '1234567' + mac)
        self.assertEqual(reader.read(), '')
        input = StringReader('1234567')
        reader = MacAddingReader(input, self.passphrase, self.salt, self.key)
        self.assertEqual(reader.read(16 + 2), self.salt + '12')
        self.assertEqual(reader.read(), '34567' + mac)
        self.assertEqual(reader.read(), '')
        input = StringReader('1234567')
        reader = MacAddingReader(input, self.passphrase, self.salt, self.key)
        self.assertEqual(reader.read(16 + 7 + 32), self.salt + '1234567' + mac)
        self.assertEqual(reader.read(), '')

    def test_read_all_neg(self):
        mac = 'Bx8mtVIWmT4OcNnbzI0X58fFrCxxPfFss8WLq9iqNjo='.decode('base64')
        input = StringReader('1234567')
        reader = MacAddingReader(input, self.passphrase, self.salt, self.key)
        self.assertEqual(reader.read(-1), self.salt + '1234567' + mac)
        self.assertEqual(reader.read(-1), '')
        input = StringReader('1234567')
        reader = MacAddingReader(input, self.passphrase, self.salt, self.key)
        self.assertEqual(reader.read(16 + 2), self.salt + '12')
        self.assertEqual(reader.read(-1), '34567' + mac)
        self.assertEqual(reader.read(-1), '')
        input = StringReader('1234567')
        reader = MacAddingReader(input, self.passphrase, self.salt, self.key)
        self.assertEqual(reader.read(16 + 7 + 32), self.salt + '1234567' + mac)
        self.assertEqual(reader.read(-1), '')

    def test_rewind(self):
        mac = 'Bx8mtVIWmT4OcNnbzI0X58fFrCxxPfFss8WLq9iqNjo='.decode('base64')
        input = StringReader('1234567')
        reader = MacAddingReader(input, self.passphrase, self.salt, self.key)
        self.assertEqual(len(reader), 16 + 7 + 32)
        self.assertEqual(reader.read(16 + 1), self.salt + '1')
        reader.rewind()
        self.assertEqual(len(reader), 16 + 7 + 32)
        self.assertEqual(reader.read(16 + 1), self.salt + '1')
        self.assertEqual(reader.read(3), '234')
        self.assertEqual(reader.read(1024), '567' + mac)
        self.assertEqual(reader.read(1024), '')
        reader.rewind()
        self.assertEqual(len(reader), 16 + 7 + 32)
        self.assertEqual(reader.read(16 + 1), self.salt + '1')
        self.assertEqual(reader.read(3), '234')
        self.assertEqual(reader.read(1024), '567' + mac)
        self.assertEqual(reader.read(1024), '')
    
    def test_close(self):
        input = StringReader('1234567')
        reader = MacAddingReader(input, self.passphrase, self.salt, self.key)
        reader.read()
        reader.close()
        self.assertRaises(Exception, reader.read, 1)


class TestMacCheckingReader(unittest.TestCase):
    def setUp(self):
        self.passphrase = 'passphrase'
        self.salt = 's' * 16
        self.key = 'k' * 32
        a_macs = ['lYfXRyLeGZ1f3TAwZcwXyd9u4YiFipS/tCKCzKa+as8=',
                  '0ZpdKMDXgcInldwIU5aR3b2zYaTTiSZkIAivDi9ZYTo=',
                  'mNf6xviWmLSIprpZSZjCDV6eMPvbLBf3yGufhVfn2xA=',
                  'xNl0cxGM+bgIcebN708B26zw2/cVUWauPuYN+cDgkX0=',
                  'DotXYegR3qdJ9pCFIjIGZ0JG5XgHG/rx8W3K+vvJiko=',
                  '1wbw90zUNYr1YR02JZR1igGEb7lmpLWRdPZm1BsQYpI=',
                  'KKyHoN2uNQ/sKOOD+aa4AMRf6wlHzrobU4xqrzgdXbg=',
                  '2boWTspGiLPqRIwqcqO0BWrqByZn/n5yrkhWmoBkUxk=',
                  'PVOuWYZjaHxSyqDgOs25D9TWVOBXa/twINsofuHt2s8=',
                  'Rf2YRH6Apa7V+sf2qa/JRWNh9DLFHnDPbMYxHelpCo0=',
                  'VDFlncTsT1hOPsWmJcpjsgdUOiRzWOLU3Jj3ifPUCPc=',
                  'DYXTYqPgYJF/yKfin2AwYJ49rtbSORUarUF4YLfwdCU=',
                  'bptfyfb+pL8TP+AngOUA6LjjPKJZJYY5ElSD9yaHFaY=',
                  'zn3HBIZUvvt2puvY0diJ2RmumaE9Mfyrx2HWfryzADE=',
                  'RhnMGzrsi+498DwF/LbTL9QblyohJ5M97mKCvm+jIr0=',
                  'YQpcosYIuPVCQkP7gRXBwhCe0HYXXymYoCyKU162wmY=',
                  'Pv8VoC3Y5DGZPcI3CNWgTUwm3GNRsmX1k163BFPXZjQ=']
        self.a_macs = [mac.decode('base64') for mac in a_macs]
    
    def test_no_salt(self):
        self.assertRaises(DataTruncatedException, MacCheckingReader, 
                          StringReader(''), self.passphrase, self.key)
    
    def test_no_mac(self):
        input = StringReader(self.salt)
        reader = MacCheckingReader(input, self.passphrase, self.key)
        self.assertRaises(DataTruncatedException, reader.read, 1)
    
    def test_no_bytes(self):
        mac = 'pK2ONA4yvx2RYAXLHcknlRSIl5ZeNq5WwK3DV0dLU3I='.decode('base64')
        input = StringReader(self.salt + '' + mac)
        reader = MacCheckingReader(input, self.passphrase, self.key)
        self.assertEqual(len(reader), 0)
        self.assertEqual(reader.read(1), '')
    
    def test_no_bytes_bad_mac(self):
        mac = 'XK2ONA4yvx2RYAXLHcknlRSIl5ZeNq5WwK3DV0dLU3I='.decode('base64')
        input = StringReader(self.salt + '' + mac)
        reader = MacCheckingReader(input, self.passphrase, self.key)
        self.assertEqual(len(reader), 0)
        self.assertRaises(BadMacException, reader.read, 1)
    
    def test_one_byte(self):
        mac = '2L0VNypDtMX/4XKb7E7WTMnXn2gPaPzaQJULnlmfeQY='.decode('base64')
        input = StringReader(self.salt + 'a' + mac)
        reader = MacCheckingReader(input, self.passphrase, self.key)
        self.assertEqual(len(reader), 1)
        self.assertEqual(reader.read(1024), 'a')
        self.assertEqual(reader.read(1), '')
        self.assertEqual(reader.read(1), '')
    
    def test_one_byte_bad_mac(self):
        mac = 'XL0VNypDtMX/4XKb7E7WTMnXn2gPaPzaQJULnlmfeQY='.decode('base64')
        input = StringReader(self.salt + 'a' + mac)
        reader = MacCheckingReader(input, self.passphrase, self.key)
        self.assertRaises(BadMacException, reader.read, 2)
    
    def test_seven_bytes(self):
        mac = 'Bx8mtVIWmT4OcNnbzI0X58fFrCxxPfFss8WLq9iqNjo='.decode('base64')
        input = StringReader(self.salt + '1234567' + mac)
        reader = MacCheckingReader(input, self.passphrase, self.key)
        self.assertEqual(len(reader), 7)
        self.assertEqual(reader.read(1), '1')
        self.assertEqual(reader.read(2), '23')
        self.assertEqual(reader.read(4), '4567')
        self.assertEqual(reader.read(1), '')
        self.assertEqual(reader.read(1), '')
    
    def test_read_all(self):
        mac = 'Bx8mtVIWmT4OcNnbzI0X58fFrCxxPfFss8WLq9iqNjo='.decode('base64')
        input = StringReader(self.salt + '1234567' + mac)
        reader = MacCheckingReader(input, self.passphrase, self.key)
        self.assertEqual(reader.read(), '1234567')
        self.assertEqual(reader.read(), '')
        input = StringReader(self.salt + '1234567' + mac)
        reader = MacCheckingReader(input, self.passphrase, self.key)
        self.assertEqual(reader.read(2), '12')
        self.assertEqual(reader.read(), '34567')
        self.assertEqual(reader.read(), '')
        input = StringReader(self.salt + '1234567' + mac)
        reader = MacCheckingReader(input, self.passphrase, self.key)
        self.assertEqual(reader.read(7), '1234567')
        self.assertEqual(reader.read(), '')
    
    def test_read_all_neg(self):
        mac = 'Bx8mtVIWmT4OcNnbzI0X58fFrCxxPfFss8WLq9iqNjo='.decode('base64')
        input = StringReader(self.salt + '1234567' + mac)
        reader = MacCheckingReader(input, self.passphrase, self.key)
        self.assertEqual(reader.read(-1), '1234567')
        self.assertEqual(reader.read(-1), '')
        input = StringReader(self.salt + '1234567' + mac)
        reader = MacCheckingReader(input, self.passphrase, self.key)
        self.assertEqual(reader.read(2), '12')
        self.assertEqual(reader.read(-1), '34567')
        self.assertEqual(reader.read(-1), '')
        input = StringReader(self.salt + '1234567' + mac)
        reader = MacCheckingReader(input, self.passphrase, self.key)
        self.assertEqual(reader.read(7), '1234567')
        self.assertEqual(reader.read(-1), '')
    
    def test_seven_bytes_bad_mac(self):
        mac = 'Xx8mtVIWmT4OcNnbzI0X58fFrCxxPfFss8WLq9iqNjo='.decode('base64')
        input = StringReader(self.salt + '1234567' + mac)
        reader = MacCheckingReader(input, self.passphrase, self.key)
        self.assertRaises(BadMacException, reader.read, 8)
    
    def test_1mb(self):
        data = ''.join(['a'*64*1024 + self.a_macs.pop(0) for x in xrange(16)])
        input = StringReader(self.salt + data)
        reader = MacCheckingReader(input, self.passphrase, self.key)
        self.assertEqual(len(reader), 1024*1024)
        self.assertEqual(reader.read(1), 'a')
        self.assertEqual(reader.read(1023), 'a'*1023)
        self.assertEqual(reader.read(1024*1024), 'a'*1023*1024)
        self.assertEqual(reader.read(1), '')
        self.assertEqual(reader.read(1), '')
    
    def test_1mb_plus_42(self):
        data = ['a'*64*1024 + self.a_macs.pop(0) for x in xrange(16)]
        data.append('a'*42 + self.a_macs.pop(0))
        self.assertEqual([], self.a_macs)
        input = StringReader(self.salt + ''.join(data))
        reader = MacCheckingReader(input, self.passphrase, self.key)
        self.assertEqual(len(reader), 1024*1024 + 42)
        self.assertEqual(reader.read(1), 'a')
        self.assertEqual(reader.read(1023), 'a'*1023)
        self.assertEqual(reader.read(1024*1024), 'a'*(1023*1024 + 42))
        self.assertEqual(reader.read(1), '')
        self.assertEqual(reader.read(1), '')
    
    def test_1mb_bad_mac(self):
        self.a_macs[3] = 'X' + self.a_macs[3][1:]
        data = ['a'*64*1024 + self.a_macs.pop(0) for x in xrange(16)]
        data.append('a'*42 + self.a_macs.pop(0))
        self.assertEqual([], self.a_macs)
        input = StringReader(self.salt + ''.join(data))
        reader = MacCheckingReader(input, self.passphrase, self.key)
        self.assertEqual(reader.read(128*1024), 'a'*128*1024)
        self.assertRaises(BadMacException, reader.read, 1024*1024 + 1)
    
    def test_real_key(self):
        mac = '+6ZSbYn460hpoowKHZkwTbxQFWkUAjlpXsbKByZGA+4='.decode('base64')
        input = StringReader(self.salt + '1234567' + mac)
        reader = MacCheckingReader(input, self.passphrase)
        self.assertEqual(len(reader), 7)
        self.assertEqual(reader.read(7), '1234567')
        self.assertEqual(reader.read(1), '')
        self.assertEqual(reader.read(1), '')
    
    def test_real_key_bad_mac(self):
        mac = 'XjhdkY3tLUUFuc3Yy7XNGv9OnNcRrvIdePDfsTwC5Jc='.decode('base64')
        input = StringReader(self.salt + '1234567' + mac)
        reader = MacCheckingReader(input, self.passphrase)
        self.assertRaises(BadMacException, reader.read, 8)

    def test_close(self):
        mac = 'Bx8mtVIWmT4OcNnbzI0X58fFrCxxPfFss8WLq9iqNjo='.decode('base64')
        input = StringReader(self.salt + '1234567' + mac)
        reader = MacCheckingReader(input, self.passphrase, self.key)
        reader.read()
        reader.close()
        self.assertRaises(Exception, reader.read, 1)


class TestMacReaders(unittest.TestCase):
    def setUp(self):
        self.passphrase = 'passphrase'
        self.salt = 's' * 16
        self.key = 'k' * 32
    
    def test_1mb(self):
        data = os.urandom(1024*1024)
        input = StringReader(data)
        adding_reader = MacAddingReader(input, self.passphrase)
        checking_reader = MacCheckingReader(adding_reader, self.passphrase)
        self.assertEqual(len(checking_reader), 1024*1024)
        self.assertEqual(checking_reader.read(1024*1024), data)
        self.assertEqual(checking_reader.read(1), '')
        self.assertEqual(checking_reader.read(1), '')
    
    def test_1mb_plus_some(self):
        data = os.urandom(1024*1024 + 42)
        input = StringReader(data)
        adding_reader = MacAddingReader(input, self.passphrase)
        checking_reader = MacCheckingReader(adding_reader, self.passphrase)
        self.assertEqual(len(checking_reader), 1024*1024 + 42)
        self.assertEqual(checking_reader.read(42), data[:42])
        self.assertEqual(checking_reader.read(1024*1024), data[42:])
        self.assertEqual(checking_reader.read(1), '')
        self.assertEqual(checking_reader.read(1), '')
    

class TestPaddingAddingReader(unittest.TestCase):
    def test_no_bytes(self):
        reader = PaddingAddingReader(StringReader(''))
        self.assertEqual(len(reader), 16)
        self.assertEqual(reader.read(100), '\x80' + '\x00' * 15)
        self.assertEqual(reader.read(1), '')
    
    def test_1_byte(self):
        data = 'a'
        reader = PaddingAddingReader(StringReader(data))
        self.assertEqual(len(reader), 16)
        self.assertEqual(reader.read(0), '')
        self.assertEqual(reader.read(100), data + '\x80' + '\x00' * 14)
        self.assertEqual(reader.read(1), '')
    
    def test_7_bytes(self):
        data = '1234567'
        reader = PaddingAddingReader(StringReader(data))
        self.assertEqual(len(reader), 16)
        self.assertEqual(reader.read(100), data + '\x80' + '\x00' * 8)
        self.assertEqual(reader.read(1), '')
    
    def test_15_bytes(self):
        data = '0123456789abcde'
        reader = PaddingAddingReader(StringReader(data))
        self.assertEqual(len(reader), 16)
        self.assertEqual(reader.read(100), data + '\x80')
        self.assertEqual(reader.read(1), '')
    
    def test_16_bytes(self):
        data = '0123456789abcdef'
        reader = PaddingAddingReader(StringReader(data))
        self.assertEqual(len(reader), 32)
        self.assertEqual(reader.read(2), '01')
        self.assertEqual(reader.read(17),
                         '23456789abcdef' + '\x80' + '\x00' * 2)
        self.assertEqual(reader.read(100), '\x00' * 13)
        self.assertEqual(reader.read(1), '')
    
    def test_1mb(self):
        data = 'a' * 1024*1024
        reader = PaddingAddingReader(StringReader(data))
        self.assertEqual(len(reader), 1024*1024 + 16)
        self.assertEqual(reader.read(1), 'a')
        self.assertEqual(reader.read(1023), 'a'*1023)
        self.assertEqual(reader.read(1024*1024),
                         'a'*1023*1024 + '\x80' + '\x00' * 15)
        self.assertEqual(reader.read(1), '')

    def test_read_all(self):
        reader = PaddingAddingReader(StringReader('1234567'))
        self.assertEqual(reader.read(), '1234567' + '\x80' + '\x00' * 8)
        self.assertEqual(reader.read(), '')
        reader = PaddingAddingReader(StringReader('1234567'))
        self.assertEqual(reader.read(2), '12')
        self.assertEqual(reader.read(), '34567' + '\x80' + '\x00' * 8)
        self.assertEqual(reader.read(), '')
        reader = PaddingAddingReader(StringReader('1234567'))
        self.assertEqual(reader.read(16), '1234567' + '\x80' + '\x00' * 8)
        self.assertEqual(reader.read(), '')

    def test_read_all_neg(self):
        reader = PaddingAddingReader(StringReader('1234567'))
        self.assertEqual(reader.read(-1), '1234567' + '\x80' + '\x00' * 8)
        self.assertEqual(reader.read(-1), '')
        reader = PaddingAddingReader(StringReader('1234567'))
        self.assertEqual(reader.read(2), '12')
        self.assertEqual(reader.read(-1), '34567' + '\x80' + '\x00' * 8)
        self.assertEqual(reader.read(-1), '')
        reader = PaddingAddingReader(StringReader('1234567'))
        self.assertEqual(reader.read(16), '1234567' + '\x80' + '\x00' * 8)
        self.assertEqual(reader.read(-1), '')

    def test_rewind(self):
        reader = PaddingAddingReader(StringReader('1234567'))
        self.assertEqual(len(reader), 7 + 9)
        self.assertEqual(reader.read(1), '1')
        reader.rewind()
        self.assertEqual(len(reader), 7 + 9)
        self.assertEqual(reader.read(1), '1')
        self.assertEqual(reader.read(3), '234')
        self.assertEqual(reader.read(1024), '567' + '\x80' + '\x00' * 8)
        self.assertEqual(reader.read(1024), '')
        reader.rewind()
        self.assertEqual(len(reader), 7 + 9)
        self.assertEqual(reader.read(1), '1')
        self.assertEqual(reader.read(3), '234')
        self.assertEqual(reader.read(1024), '567' + '\x80' + '\x00' * 8)
        self.assertEqual(reader.read(1024), '')
    
    def test_close(self):
        reader = PaddingAddingReader(StringReader('1234567'))
        reader.read()
        reader.close()
        self.assertRaises(Exception, reader.read, 1)


class TestPaddingStrippingReader(unittest.TestCase):
    def test_no_padding(self):
        reader = PaddingStrippingReader(StringReader(''))
        self.assertRaises(DataDamagedException, reader.read, 1)
    
    def test_minimal_padding(self):
        reader = PaddingStrippingReader(StringReader('\x80'))
        self.assertEqual(reader.read(1), '')
    
    def test_no_bytes(self):
        padded_data = '\x80' + '\x00' * 15
        reader = PaddingStrippingReader(StringReader(padded_data))
        self.assertEqual(len(reader), 16)
        self.assertEqual(reader.read(100), '')
        self.assertEqual(reader.read(1), '')
    
    def test_1_byte(self):
        data = 'a'
        padded_data = 'a\x80' + '\x00' * 14
        reader = PaddingStrippingReader(StringReader(padded_data))
        self.assertEqual(len(reader), 16)
        self.assertEqual(reader.read(100), data)
        self.assertEqual(reader.read(1), '')
    
    def test_7_bytes(self):
        data = '1234567'
        padded_data = '1234567\x80' + '\x00' * 8
        reader = PaddingStrippingReader(StringReader(padded_data))
        self.assertEqual(len(reader), 16)
        self.assertEqual(reader.read(100), data)
        self.assertEqual(reader.read(1), '')
    
    def test_7_bytes_not_aligned(self):
        data = '1234567'
        padded_data = '1234567\x80\x00'
        reader = PaddingStrippingReader(StringReader(padded_data))
        self.assertEqual(len(reader), 9)
        self.assertEqual(reader.read(1), '1')
        self.assertEqual(reader.read(2), '23')
        self.assertEqual(reader.read(4), '4567')
        self.assertEqual(reader.read(1), '')
    
    def test_15_bytes(self):
        data = '0123456789abcde'
        padded_data = '0123456789abcde\x80'
        reader = PaddingStrippingReader(StringReader(padded_data))
        self.assertEqual(len(reader), 16)
        self.assertEqual(reader.read(100), data)
        self.assertEqual(reader.read(1), '')
    
    def test_16_bytes(self):
        data = '0123456789abcdef'
        padded_data = '0123456789abcdef\x80' + '\x00' * 15
        reader = PaddingStrippingReader(StringReader(padded_data))
        self.assertEqual(len(reader), 32)
        self.assertEqual(reader.read(2), '01')
        self.assertEqual(reader.read(17), '23456789abcdef')
        self.assertEqual(reader.read(1), '')
    
    def test_17_bytes(self):
        data = '0123456789abcdefx'
        padded_data = '0123456789abcdefx\x80' + '\x00' * 14
        reader = PaddingStrippingReader(StringReader(padded_data))
        self.assertEqual(len(reader), 32)
        self.assertEqual(reader.read(2), '01')
        self.assertEqual(reader.read(17), '23456789abcdefx')
        self.assertEqual(reader.read(1), '')
    
    def test_1mb(self):
        data = 'a' * 1024*1024
        padded_data = data +'\x80' + '\x00' * 15
        reader = PaddingStrippingReader(StringReader(padded_data))
        self.assertEqual(len(reader), 1024*1024 + 16)
        self.assertEqual(reader.read(1), 'a')
        self.assertEqual(reader.read(1023), 'a'*1023)
        self.assertEqual(reader.read(1024*1024), 'a'*1023*1024)
        self.assertEqual(reader.read(1), '')
    
    def test_17_bytes_minimal_padding(self):
        data = '0123456789abcdefx'
        padded_data = '0123456789abcdefx\x80'
        reader = PaddingStrippingReader(StringReader(padded_data))
        self.assertEqual(len(reader), 18)
        self.assertEqual(reader.read(2), '01')
        self.assertEqual(reader.read(100), '23456789abcdefx')
        self.assertEqual(reader.read(1), '')
    
    def test_17_bytes_missing_padding(self):
        data = '0123456789abcdefx'
        padded_data = '0123456789abcdefx'
        reader = PaddingStrippingReader(StringReader(padded_data))
        self.assertEqual(len(reader), 17)
        self.assertEqual(reader.read(1), '0')
        self.assertRaises(DataDamagedException, reader.read, 1)

    def test_test_read_all(self):
        reader = PaddingStrippingReader(StringReader('1234567\x80' + '\x00'*8))
        self.assertEqual(reader.read(), '1234567')
        self.assertEqual(reader.read(), '')
        reader = PaddingStrippingReader(StringReader('1234567\x80' + '\x00'*8))
        self.assertEqual(reader.read(2), '12')
        self.assertEqual(reader.read(), '34567')
        self.assertEqual(reader.read(), '')
        reader = PaddingStrippingReader(StringReader('1234567\x80' + '\x00'*8))
        self.assertEqual(reader.read(7), '1234567')
        self.assertEqual(reader.read(), '')
    
    def test_test_read_all_neg(self):
        reader = PaddingStrippingReader(StringReader('1234567\x80' + '\x00'*8))
        self.assertEqual(reader.read(-1), '1234567')
        self.assertEqual(reader.read(-1), '')
        reader = PaddingStrippingReader(StringReader('1234567\x80' + '\x00'*8))
        self.assertEqual(reader.read(2), '12')
        self.assertEqual(reader.read(-1), '34567')
        self.assertEqual(reader.read(-1), '')
        reader = PaddingStrippingReader(StringReader('1234567\x80' + '\x00'*8))
        self.assertEqual(reader.read(7), '1234567')
        self.assertEqual(reader.read(-1), '')

    def test_close(self):
        reader = PaddingStrippingReader(StringReader('1234567\x80' + '\x00'*8))
        reader.read()
        reader.close()
        self.assertRaises(Exception, reader.read, 1)


class TestPaddingReaders(unittest.TestCase):
    def test_1mb(self):
        data = os.urandom(1024*1024)
        input = StringReader(data)
        adding_reader = PaddingAddingReader(input)
        stripping_reader = PaddingStrippingReader(adding_reader)
        self.assertEqual(len(stripping_reader), 1024*1024 + 16)
        self.assertEqual(stripping_reader.read(1024*1024), data)
        self.assertEqual(stripping_reader.read(1), '')
        self.assertEqual(stripping_reader.read(1), '')
    
    def test_1mb_plus_some(self):
        data = os.urandom(1024*1024 + 42)
        input = StringReader(data)
        adding_reader = PaddingAddingReader(input)
        stripping_reader = PaddingStrippingReader(adding_reader)
        self.assertEqual(len(stripping_reader), 1024*1024 + 48)
        self.assertEqual(stripping_reader.read(42), data[:42])
        self.assertEqual(stripping_reader.read(1024*1024), data[42:])
        self.assertEqual(stripping_reader.read(1), '')
        self.assertEqual(stripping_reader.read(1), '')
    

class TestAesCbcEncryptingReader(unittest.TestCase):
    def setUp(self):
        self.passphrase = 'passphrase'
        self.salt = 's' * 16
        self.iv = 'i' * 16
        self.key = 'k' * 32
    
    def test_no_bytes(self):
        data = ''
        ciphertext = ''
        reader = AesCbcEncryptingReader(StringReader(data), self.passphrase,
                                        self.salt, self.iv, self.key)
        self.assertEqual(len(reader), 16 + 16)
        self.assertEqual(reader.read(16 + 16),
                         self.salt + self.iv + ciphertext)
        self.assertEqual(reader.read(1), '')
    
    def test_1_byte(self):
        data = 'a'
        self.assertRaises(ValueError, AesCbcEncryptingReader,
                          StringReader(data), self.passphrase)
    
    def test_16_bytes(self):
        data = '0123456789abcdef'
        ciphertext = 'Rx5kzFEEgumDBeMJG3j9vQ=='.decode('base64')
        reader = AesCbcEncryptingReader(StringReader(data), self.passphrase,
                                        self.salt, self.iv, self.key)
        self.assertEqual(len(reader), 16 + 16 + 16)
        self.assertEqual(reader.read(16 + 16), self.salt + self.iv)
        self.assertEqual(reader.read(1024), ciphertext)
        self.assertEqual(reader.read(1), '')
    
    def test_32_bytes(self):
        data = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
        ciphertext = 'J5+ATEVX9bnkx4xhMf88LJq4iE' \
            'wEgIV+Z/AW0h+fA8Y='.decode('base64')
        reader = AesCbcEncryptingReader(StringReader(data), self.passphrase,
                                        self.salt, self.iv, self.key)
        self.assertEqual(len(reader), 16 + 16 + 32)
        self.assertEqual(reader.read(16 + 16), self.salt + self.iv)
        self.assertEqual(reader.read(1024), ciphertext)
        self.assertEqual(reader.read(1), '')
    
    def test_16_bytes_with_real_key(self):
        data = '0123456789abcdef'
        ciphertext = '3poinep3R7LRLIfd+uSZfw=='.decode('base64')
        reader = AesCbcEncryptingReader(StringReader(data), self.passphrase,
                                        self.salt, self.iv)
        self.assertEqual(len(reader), 16 + 16 + 16)
        self.assertEqual(reader.read(16 + 16), self.salt + self.iv)
        self.assertEqual(reader.read(1024), ciphertext)
        self.assertEqual(reader.read(1), '')
    
    def test_random_values(self):
        data = '0123456789abcdef'
        reader1 = AesCbcEncryptingReader(StringReader(data), self.passphrase)
        reader2 = AesCbcEncryptingReader(StringReader(data), self.passphrase)
        self.assertNotEqual(reader1.read(16), reader2.read(16)) # salt
        self.assertNotEqual(reader1.read(16), reader2.read(16)) # iv
        self.assertNotEqual(reader1.read(16), reader2.read(16)) # ciphertext
        self.assertEqual(reader1.read(16), '')
        self.assertEqual(reader2.read(16), '')

    def test_read_all(self):
        data = '0123456789abcdef'
        ciphertext = 'Rx5kzFEEgumDBeMJG3j9vQ=='.decode('base64')
        reader = AesCbcEncryptingReader(StringReader(data), self.passphrase,
                                        self.salt, self.iv, self.key)
        self.assertEqual(reader.read(), self.salt + self.iv + ciphertext)
        self.assertEqual(reader.read(), '')
        reader = AesCbcEncryptingReader(StringReader(data), self.passphrase,
                                        self.salt, self.iv, self.key)
        self.assertEqual(reader.read(2), self.salt[:2])
        self.assertEqual(reader.read(), self.salt[2:] + self.iv + ciphertext)
        self.assertEqual(reader.read(), '')
        reader = AesCbcEncryptingReader(StringReader(data), self.passphrase,
                                        self.salt, self.iv, self.key)
        self.assertEqual(reader.read(48), self.salt + self.iv + ciphertext)
        self.assertEqual(reader.read(), '')
    
    def test_read_all_neg(self):
        data = '0123456789abcdef'
        ciphertext = 'Rx5kzFEEgumDBeMJG3j9vQ=='.decode('base64')
        reader = AesCbcEncryptingReader(StringReader(data), self.passphrase,
                                        self.salt, self.iv, self.key)
        self.assertEqual(reader.read(-1), self.salt + self.iv + ciphertext)
        self.assertEqual(reader.read(-1), '')
        reader = AesCbcEncryptingReader(StringReader(data), self.passphrase,
                                        self.salt, self.iv, self.key)
        self.assertEqual(reader.read(2), self.salt[:2])
        self.assertEqual(reader.read(-1), self.salt[2:] + self.iv + ciphertext)
        self.assertEqual(reader.read(-1), '')
        reader = AesCbcEncryptingReader(StringReader(data), self.passphrase,
                                        self.salt, self.iv, self.key)
        self.assertEqual(reader.read(48), self.salt + self.iv + ciphertext)
        self.assertEqual(reader.read(-1), '')
    
    def test_rewind(self):
        data = '0123456789abcdef'
        ciphertext = 'Rx5kzFEEgumDBeMJG3j9vQ=='.decode('base64')
        reader = AesCbcEncryptingReader(StringReader(data), self.passphrase,
                                        self.salt, self.iv, self.key)
        self.assertEqual(len(reader), 16 + 16 + 16)
        self.assertEqual(reader.read(16 + 16 + 1),
                         self.salt + self.iv + ciphertext[:1])
        reader.rewind()
        self.assertEqual(len(reader), 16 + 16 + 16)
        self.assertEqual(reader.read(16 + 16 + 1),
                         self.salt + self.iv + ciphertext[:1])
        self.assertEqual(reader.read(3), ciphertext[1:4])
        self.assertEqual(reader.read(1024), ciphertext[4:])
        self.assertEqual(reader.read(1024), '')
        reader.rewind()
        self.assertEqual(len(reader), 16 + 16 + 16)
        self.assertEqual(reader.read(16 + 16 + 1),
                         self.salt + self.iv + ciphertext[:1])
        self.assertEqual(reader.read(3), ciphertext[1:4])
        self.assertEqual(reader.read(1024), ciphertext[4:])
    
    def test_close(self):
        data = '0123456789abcdef'
        ciphertext = 'Rx5kzFEEgumDBeMJG3j9vQ=='.decode('base64')
        reader = AesCbcEncryptingReader(StringReader(data), self.passphrase,
                                        self.salt, self.iv, self.key)
        reader.read()
        reader.close()
        #self.assertRaises(Exception, reader.read, 1)


class TestAesCbcDecryptingReader(unittest.TestCase):
    def setUp(self):
        self.passphrase = 'passphrase'
        self.salt = 's' * 16
        self.iv = 'i' * 16
        self.key = 'k' * 32
    
    def test_no_bytes(self):
        ciphertext = ''
        input = StringReader(self.salt + self.iv + ciphertext)
        reader = AesCbcDecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(len(reader), 0)
        self.assertEqual(reader.read(1), '')
    
    def test_partial_block(self):
        ciphertext = 'x'
        input = StringReader(self.salt + self.iv + ciphertext)
        reader = AesCbcDecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(len(reader), 1)
        self.assertRaises(DataDamagedException, reader.read, 1)
    
    def test_16_bytes(self):
        data = '0123456789abcdef'
        ciphertext = 'Rx5kzFEEgumDBeMJG3j9vQ=='.decode('base64')
        input = StringReader(self.salt + self.iv + ciphertext)
        reader = AesCbcDecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(len(reader), 16)
        self.assertEqual(reader.read(1), '0')
        self.assertEqual(reader.read(100), '123456789abcdef')
        self.assertEqual(reader.read(1), '')
    
    def test_16_bytes_plus_partial_block(self):
        data = '0123456789abcdef'
        ciphertext = 'Rx5kzFEEgumDBeMJG3j9vQ=='.decode('base64') + 'x'
        input = StringReader(self.salt + self.iv + ciphertext)
        reader = AesCbcDecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(len(reader), 17)
        self.assertEqual(reader.read(1), '0')
        self.assertEqual(reader.read(15), '123456789abcdef')
        self.assertRaises(DataDamagedException, reader.read, 1)
    
    def test_32_bytes(self):
        data = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
        ciphertext = 'J5+ATEVX9bnkx4xhMf88LJq4iE' \
            'wEgIV+Z/AW0h+fA8Y='.decode('base64')
        input = StringReader(self.salt + self.iv + ciphertext)
        reader = AesCbcDecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(len(reader), 32)
        self.assertEqual(reader.read(1024), data)
        self.assertEqual(reader.read(1), '')
    
    def test_16_bytes_with_real_key(self):
        data = '0123456789abcdef'
        ciphertext = '3poinep3R7LRLIfd+uSZfw=='.decode('base64')
        input = StringReader(self.salt + self.iv + ciphertext)
        reader = AesCbcDecryptingReader(input, self.passphrase)
        self.assertEqual(len(reader), 16)
        self.assertEqual(reader.read(1024), data)
        self.assertEqual(reader.read(1), '')
    
    def test_read_all(self):
        data = '0123456789abcdef'
        ciphertext = 'Rx5kzFEEgumDBeMJG3j9vQ=='.decode('base64')
        input = StringReader(self.salt + self.iv + ciphertext)
        reader = AesCbcDecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(reader.read(), '0123456789abcdef')
        self.assertEqual(reader.read(), '')
        input = StringReader(self.salt + self.iv + ciphertext)
        reader = AesCbcDecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(reader.read(2), '01')
        self.assertEqual(reader.read(), '23456789abcdef')
        self.assertEqual(reader.read(), '')
        input = StringReader(self.salt + self.iv + ciphertext)
        reader = AesCbcDecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(reader.read(16), '0123456789abcdef')
        self.assertEqual(reader.read(), '')
    
    def test_read_all_neg(self):
        data = '0123456789abcdef'
        ciphertext = 'Rx5kzFEEgumDBeMJG3j9vQ=='.decode('base64')
        input = StringReader(self.salt + self.iv + ciphertext)
        reader = AesCbcDecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(reader.read(-1), '0123456789abcdef')
        self.assertEqual(reader.read(-1), '')
        input = StringReader(self.salt + self.iv + ciphertext)
        reader = AesCbcDecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(reader.read(2), '01')
        self.assertEqual(reader.read(-1), '23456789abcdef')
        self.assertEqual(reader.read(-1), '')
        input = StringReader(self.salt + self.iv + ciphertext)
        reader = AesCbcDecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(reader.read(16), '0123456789abcdef')
        self.assertEqual(reader.read(-1), '')
    
    def test_close(self):
        data = '0123456789abcdef'
        ciphertext = 'Rx5kzFEEgumDBeMJG3j9vQ=='.decode('base64')
        input = StringReader(self.salt + self.iv + ciphertext)
        reader = AesCbcDecryptingReader(input, self.passphrase, self.key)
        reader.read()
        reader.close()
        #self.assertRaises(Exception, reader.read, 1)


class TestAesCbcReaders(unittest.TestCase):
    def setUp(self):
        self.passphrase = 'passphrase'
        self.salt = 's' * 16
        self.iv = 'i' * 16
        self.key = 'k' * 32
    
    def test_1mb(self):
        data = os.urandom(1024*1024)
        input = StringReader(data)
        encrypting_reader = AesCbcEncryptingReader(input, self.passphrase,
                                                   self.salt, self.iv, self.key)
        decrypting_reader = AesCbcDecryptingReader(encrypting_reader, self.passphrase, self.key)
        self.assertEqual(len(decrypting_reader), 1024*1024)
        self.assertEqual(decrypting_reader.read(1024*1024), data)
        self.assertEqual(decrypting_reader.read(1), '')
        self.assertEqual(decrypting_reader.read(1), '')
    
    def test_1mb_plus_some(self):
        data = os.urandom(1024*1024 + 48)
        input = StringReader(data)
        encrypting_reader = AesCbcEncryptingReader(input, self.passphrase,
                                                   self.salt, self.iv, self.key)
        decrypting_reader = AesCbcDecryptingReader(encrypting_reader, self.passphrase, self.key)
        self.assertEqual(len(decrypting_reader), 1024*1024 + 48)
        self.assertEqual(decrypting_reader.read(42), data[:42])
        self.assertEqual(decrypting_reader.read(1024*1024 + 6), data[42:])
        self.assertEqual(decrypting_reader.read(1), '')
        self.assertEqual(decrypting_reader.read(1), '')
    

class TestEncryptingReader(unittest.TestCase):
    def setUp(self):
        self.passphrase = 'passphrase'
        self.salt = 's' * 16
        self.iv = 'i' * 16
        self.key = 'k' * 32
    
    def test_no_bytes(self):
        data = ''
        ciphertext = 'XdwcsHWSePqdnGOXLtXopA=='.decode('base64')
        mac = 'MZH3egS1YJG0I9DrMMFFVi/JvnGCu5ipmGY82vSveoA='.decode('base64')
        reader = EncryptingReader(StringReader(data), self.passphrase,
                                  self.salt, self.iv, self.key)
        self.assertEqual(len(reader), 16 + (16 + 16 + (0 + 16)) + 32)
        self.assertEqual(reader.read(16 + (16 + 16 + (0 + 16)) + 32),
                         self.salt + self.salt + self.iv + ciphertext + mac)
        self.assertEqual(reader.read(1), '')
    
    def test_1_byte(self):
        data = 'a'
        ciphertext = 'wmCwhQl9IPU8KvuF1rZhWw=='.decode('base64')
        mac = 'Dk4tWUE1drYdtZ/6zPJXAxVw58sEuDbAQVrQNx3+rBs='.decode('base64')
        reader = EncryptingReader(StringReader(data), self.passphrase,
                                  self.salt, self.iv, self.key)
        self.assertEqual(len(reader), 16 + (16 + 16 + (1 + 15)) + 32)
        self.assertEqual(reader.read(16 + (16 + 16 + (1 + 15)) + 32),
                         self.salt + self.salt + self.iv + ciphertext + mac)
        self.assertEqual(reader.read(1), '')
    
    def test_16_bytes(self):
        data = '0123456789abcdef'
        ciphertext = 'Rx5kzFEEgumDBeMJG3j9vVNG+c5XlOK/yZ3QttnWgpw='.decode('base64')
        mac = 'ksbanXkR4IN9fqyxvHAFNnROan78ntbNpNju3ATZ8Ys='.decode('base64')
        reader = EncryptingReader(StringReader(data), self.passphrase,
                                  self.salt, self.iv, self.key)
        self.assertEqual(len(reader), 16 + (16 + 16 + (16 + 16)) + 32)
        self.assertEqual(reader.read(16), self.salt)
        self.assertEqual(reader.read(16 + 16), self.salt + self.iv)
        self.assertEqual(reader.read(16 + 16), ciphertext)
        self.assertEqual(reader.read(32), mac)
        self.assertEqual(reader.read(1), '')
    
    def test_32_bytes(self):
        data = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
        ciphertext = 'J5+ATEVX9bnkx4xhMf88LJq4iEwEgIV+Z/AW0h+' \
            'fA8a5iqiAxgJBqlNiLbTzCib/'.decode('base64')
        mac = 'Zj4rhjIoI97LWoglO9TUcWHrEIP8yBh3ygzpRRINTWk='.decode('base64')
        reader = EncryptingReader(StringReader(data), self.passphrase,
                                  self.salt, self.iv, self.key)
        self.assertEqual(len(reader), 16 + (16 + 16 + (32 + 16)) + 32)
        self.assertEqual(reader.read(16), self.salt)
        self.assertEqual(reader.read(16 + 16), self.salt + self.iv)
        self.assertEqual(reader.read(1024), ciphertext + mac)
        self.assertEqual(reader.read(1), '')
    
    def test_16_bytes_with_real_key(self):
        data = '0123456789abcdef'
        ciphertext = '3poinep3R7LRLIfd+uSZf47+1N3S97MsxOx97k4rX9c='.decode('base64')
        mac = 'ImYdegy8QLCggXd9n0YrQY3eeYejMS5SWEPUv3XUOd4='.decode('base64')
        reader = EncryptingReader(StringReader(data), self.passphrase,
                                  self.salt, self.iv)
        self.assertEqual(len(reader), 16 + (16 + 16 + (16 + 16)) + 32)
        self.assertEqual(reader.read(16), self.salt)
        self.assertEqual(reader.read(16 + 16), self.salt + self.iv)
        self.assertEqual(reader.read(1024), ciphertext + mac)
        self.assertEqual(reader.read(1), '')
    
    def test_random_values(self):
        data = '0123456789abcdef'
        reader1 = EncryptingReader(StringReader(data), self.passphrase)
        reader2 = EncryptingReader(StringReader(data), self.passphrase)
        self.assertNotEqual(reader1.read(16), reader2.read(16)) # mac salt
        self.assertNotEqual(reader1.read(16), reader2.read(16)) # aes salt
        self.assertNotEqual(reader1.read(16), reader2.read(16)) # aes iv
        self.assertNotEqual(reader1.read(48), reader2.read(48)) # ciphertext
        self.assertNotEqual(reader1.read(32), reader2.read(32)) # mac
        self.assertEqual(reader1.read(16), '')
        self.assertEqual(reader2.read(16), '')

    def test_read_all(self):
        data = '0123456789abcdef'
        ciphertext = 'Rx5kzFEEgumDBeMJG3j9vVNG+c5XlOK/yZ3QttnWgpw='.decode('base64')
        mac = 'ksbanXkR4IN9fqyxvHAFNnROan78ntbNpNju3ATZ8Ys='.decode('base64')
        reader = EncryptingReader(StringReader(data), self.passphrase,
                                  self.salt, self.iv, self.key)
        self.assertEqual(reader.read(),
                         self.salt + self.salt + self.iv + ciphertext + mac)
        self.assertEqual(reader.read(), '')
        reader = EncryptingReader(StringReader(data), self.passphrase,
                                  self.salt, self.iv, self.key)
        self.assertEqual(reader.read(48 + 2),
                         self.salt + self.salt + self.iv + ciphertext[:2])
        self.assertEqual(reader.read(), ciphertext[2:] + mac)
        self.assertEqual(reader.read(), '')
        reader = EncryptingReader(StringReader(data), self.passphrase,
                                  self.salt, self.iv, self.key)
        self.assertEqual(reader.read(128),
                         self.salt + self.salt + self.iv + ciphertext + mac)
        self.assertEqual(reader.read(), '')
    
    def test_read_all_neg(self):
        data = '0123456789abcdef'
        ciphertext = 'Rx5kzFEEgumDBeMJG3j9vVNG+c5XlOK/yZ3QttnWgpw='.decode('base64')
        mac = 'ksbanXkR4IN9fqyxvHAFNnROan78ntbNpNju3ATZ8Ys='.decode('base64')
        reader = EncryptingReader(StringReader(data), self.passphrase,
                                  self.salt, self.iv, self.key)
        self.assertEqual(reader.read(-1),
                         self.salt + self.salt + self.iv + ciphertext + mac)
        self.assertEqual(reader.read(-1), '')
        reader = EncryptingReader(StringReader(data), self.passphrase,
                                  self.salt, self.iv, self.key)
        self.assertEqual(reader.read(48 + 2),
                         self.salt + self.salt + self.iv + ciphertext[:2])
        self.assertEqual(reader.read(-1), ciphertext[2:] + mac)
        self.assertEqual(reader.read(-1), '')
        reader = EncryptingReader(StringReader(data), self.passphrase,
                                  self.salt, self.iv, self.key)
        self.assertEqual(reader.read(128),
                         self.salt + self.salt + self.iv + ciphertext + mac)
        self.assertEqual(reader.read(-1), '')
    
    def test_rewind(self):
        data = '0123456789abcdef'
        ciphertext = 'Rx5kzFEEgumDBeMJG3j9vVNG+c5XlOK/yZ3QttnWgpw='.decode('base64')
        mac = 'ksbanXkR4IN9fqyxvHAFNnROan78ntbNpNju3ATZ8Ys='.decode('base64')
        reader = EncryptingReader(StringReader(data), self.passphrase,
                                  self.salt, self.iv, self.key)
        self.assertEqual(len(reader), 16 + (16 + 16 + (16 + 16)) + 32)
        self.assertEqual(reader.read(48 + 1),
                         self.salt + self.salt + self.iv + ciphertext[:1])
        reader.rewind()
        self.assertEqual(len(reader), 16 + (16 + 16 + (16 + 16)) + 32)
        self.assertEqual(reader.read(48 + 1),
                         self.salt + self.salt + self.iv + ciphertext[:1])
        self.assertEqual(reader.read(3), ciphertext[1:4])
        self.assertEqual(reader.read(1024), ciphertext[4:] + mac)
        self.assertEqual(reader.read(1024), '')
        reader.rewind()
        self.assertEqual(len(reader), 16 + (16 + 16 + (16 + 16)) + 32)
        self.assertEqual(reader.read(48 + 1),
                         self.salt + self.salt + self.iv + ciphertext[:1])
        self.assertEqual(reader.read(3), ciphertext[1:4])
        self.assertEqual(reader.read(1024), ciphertext[4:] + mac)
    
    def test_close(self):
        data = '0123456789abcdef'
        ciphertext = 'GrEi4QMwqyNQX1nODd1Qh9wog/6Gery0z3RWfq' \
            'Su+u4KasWWZO7euiuS+dllC2OY'.decode('base64')
        mac = 'yBpRfLybWw8Fuka5ir5e+HlKeckF+L0TuCJpQX6Fk5g='.decode('base64')
        reader = EncryptingReader(StringReader(data), self.passphrase,
                                  self.salt, self.iv, self.key)
        reader.read()
        reader.close()
        self.assertRaises(Exception, reader.read, 1)


class TestDecryptingReader(unittest.TestCase):
    def setUp(self):
        self.passphrase = 'passphrase'
        self.salt = 's' * 16
        self.iv = 'i' * 16
        self.key = 'k' * 32
        self.mac = 'm' * 32
    
    def test_no_header(self):
        input = StringReader('')
        self.assertRaises(DataTruncatedException, DecryptingReader, input,
                          self.passphrase, self.key)

    def test_no_salt_or_iv(self):
        input = StringReader(self.salt + self.mac)
        self.assertRaises(DataTruncatedException, DecryptingReader, input, 
                          self.passphrase, self.key)
    
    def test_no_padding(self):
        ciphertext = 'GrEi4QMwqyNQX1nODd1Qhw=='.decode('base64')
        mac = 'V/LKyFj8MoZ3ZS3WZtG3xqwogrPg8Bn2z0SY/Jp3IGE='.decode('base64')
        input = StringReader(self.salt + self.salt + self.iv + ciphertext + mac)
        reader = DecryptingReader(input, self.passphrase, self.key)
        self.assertRaises(DataDamagedException, reader.read, 1)
    
    def test_no_data(self):
        data = ''
        ciphertext = 'XdwcsHWSePqdnGOXLtXopA=='.decode('base64')
        mac = 'MZH3egS1YJG0I9DrMMFFVi/JvnGCu5ipmGY82vSveoA='.decode('base64')
        input = StringReader(self.salt + self.salt + self.iv + ciphertext + mac)
        reader = DecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(len(reader), 16)
        self.assertEqual(reader.read(1), '')
    
    def test_1_byte(self):
        data = 'a'
        ciphertext = 'wmCwhQl9IPU8KvuF1rZhWw=='.decode('base64')
        mac = 'Dk4tWUE1drYdtZ/6zPJXAxVw58sEuDbAQVrQNx3+rBs='.decode('base64')
        input = StringReader(self.salt + self.salt + self.iv + ciphertext + mac)
        reader = DecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(len(reader), 16)
        self.assertEqual(reader.read(1), 'a')
        self.assertEqual(reader.read(1), '')
    
    def test_partial_block(self):
        data = ''
        ciphertext = 'XdwcsHWSePqdnGOXLtXopA=='.decode('base64') + 'x'
        mac = 'JkCaQY5QRPkBgk79Jf9w5oFt6IkE9Xql48LUyEpF7fQ='.decode('base64')
        input = StringReader(self.salt + self.salt + self.iv + ciphertext + mac)
        reader = DecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(len(reader), 17)
        self.assertRaises(DataDamagedException, reader.read, 1)
    
    def test_16_bytes(self):
        data = '0123456789abcdef'
        ciphertext = 'Rx5kzFEEgumDBeMJG3j9vVNG+c5XlOK/yZ3QttnWgpw='.decode('base64')
        mac = 'ksbanXkR4IN9fqyxvHAFNnROan78ntbNpNju3ATZ8Ys='.decode('base64')
        input = StringReader(self.salt + self.salt + self.iv + ciphertext + mac)
        reader = DecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(len(reader), 32)
        self.assertEqual(reader.read(1), '0')
        self.assertEqual(reader.read(100), '123456789abcdef')
        self.assertEqual(reader.read(1), '')
    
    def test_16_bytes_plus_partial_block(self):
        data = '0123456789abcdef'
        ciphertext = 'Rx5kzFEEgumDBeMJG3j9vVNG+c5XlOK/yZ3QttnWgpw='.decode('base64') + 'x'
        mac = '/X4tGXAoj9x8hBgyFv/SjD+P4EkF/lJ8SzLIrGm8ucw='.decode('base64')
        input = StringReader(self.salt + self.salt + self.iv + ciphertext + mac)
        reader = DecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(len(reader), 33)
        self.assertEqual(reader.read(1), '0')
        self.assertEqual(reader.read(15), '123456789abcdef')
        self.assertRaises(DataDamagedException, reader.read, 1)
    
    def test_32_bytes(self):
        data = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
        ciphertext = 'J5+ATEVX9bnkx4xhMf88LJq4iEwEgIV+Z/AW0h+' \
            'fA8a5iqiAxgJBqlNiLbTzCib/'.decode('base64')
        mac = 'Zj4rhjIoI97LWoglO9TUcWHrEIP8yBh3ygzpRRINTWk='.decode('base64')
        input = StringReader(self.salt + self.salt + self.iv + ciphertext + mac)
        reader = DecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(len(reader), 48)
        self.assertEqual(reader.read(1024), data)
        self.assertEqual(reader.read(1), '')
    
    def test_16_bytes_with_real_key(self):
        data = '0123456789abcdef'
        ciphertext = '3poinep3R7LRLIfd+uSZf47+1N3S97MsxOx97k4rX9c='.decode('base64')
        mac = 'ImYdegy8QLCggXd9n0YrQY3eeYejMS5SWEPUv3XUOd4='.decode('base64')
        input = StringReader(self.salt + self.salt + self.iv + ciphertext + mac)
        reader = DecryptingReader(input, self.passphrase)
        self.assertEqual(len(reader), 32)
        self.assertEqual(reader.read(1024), data)
        self.assertEqual(reader.read(1), '')
    
    def test_read_all(self):
        data = '0123456789abcdef'
        ciphertext = 'Rx5kzFEEgumDBeMJG3j9vVNG+c5XlOK/yZ3QttnWgpw='.decode('base64')
        mac = 'ksbanXkR4IN9fqyxvHAFNnROan78ntbNpNju3ATZ8Ys='.decode('base64')
        input = StringReader(self.salt + self.salt + self.iv + ciphertext + mac)
        reader = DecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(reader.read(), '0123456789abcdef')
        self.assertEqual(reader.read(), '')
        input = StringReader(self.salt + self.salt + self.iv + ciphertext + mac)
        reader = DecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(reader.read(2), '01')
        self.assertEqual(reader.read(), '23456789abcdef')
        self.assertEqual(reader.read(), '')
        input = StringReader(self.salt + self.salt + self.iv + ciphertext + mac)
        reader = DecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(reader.read(16), '0123456789abcdef')
        self.assertEqual(reader.read(), '')
    
    def test_read_all_neg(self):
        data = '0123456789abcdef'
        ciphertext = 'Rx5kzFEEgumDBeMJG3j9vVNG+c5XlOK/yZ3QttnWgpw='.decode('base64')
        mac = 'ksbanXkR4IN9fqyxvHAFNnROan78ntbNpNju3ATZ8Ys='.decode('base64')
        input = StringReader(self.salt + self.salt + self.iv + ciphertext + mac)
        reader = DecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(reader.read(-1), '0123456789abcdef')
        self.assertEqual(reader.read(-1), '')
        input = StringReader(self.salt + self.salt + self.iv + ciphertext + mac)
        reader = DecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(reader.read(2), '01')
        self.assertEqual(reader.read(-1), '23456789abcdef')
        self.assertEqual(reader.read(-1), '')
        input = StringReader(self.salt + self.salt + self.iv + ciphertext + mac)
        reader = DecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(reader.read(16), '0123456789abcdef')
        self.assertEqual(reader.read(-1), '')
    
    def test_wrong_passphrase(self):
        data = '0123456789abcdef'
        ciphertext = 'Rx5kzFEEgumDBeMJG3j9vVNG+c5XlOK/yZ3QttnWgpw='.decode('base64')
        mac = 'ksbanXkR4IN9fqyxvHAFNnROan78ntbNpNju3ATZ8Ys='.decode('base64')
        input = StringReader(self.salt + self.salt + self.iv + ciphertext + mac)
        self.assertRaises(BadMacException, DecryptingReader, 
                          input, self.passphrase + 'x')
    
    def test_close(self):
        data = '0123456789abcdef'
        ciphertext = 'GrEi4QMwqyNQX1nODd1Qh9wog/6Gery0z3RWfq' \
            'Su+u4KasWWZO7euiuS+dllC2OY'.decode('base64')
        mac = 'yBpRfLybWw8Fuka5ir5e+HlKeckF+L0TuCJpQX6Fk5g='.decode('base64')
        input = StringReader(self.salt + self.salt + self.iv + ciphertext + mac)
        reader = DecryptingReader(input, self.passphrase, self.key)
        reader.read()
        reader.close()
        self.assertRaises(Exception, reader.read, 1)


class TestCryptingReaders(unittest.TestCase):
    def setUp(self):
        self.passphrase = 'passphrase'
        self.salt = 's' * 16
        self.iv = 'i' * 16
        self.key = 'k' * 32
    
    def test_1mb(self):
        data = os.urandom(1024*1024)
        input = StringReader(data)
        encrypting_reader = EncryptingReader(input, self.passphrase,
                                             self.salt, self.iv, self.key)
        decrypting_reader = DecryptingReader(encrypting_reader, self.passphrase, self.key)
        self.assertEqual(len(decrypting_reader), 1024*1024 + 16)
        self.assertEqual(decrypting_reader.read(1024*1024), data)
        self.assertEqual(decrypting_reader.read(1), '')
        self.assertEqual(decrypting_reader.read(1), '')
    
    def test_1mb_plus_some(self):
        data = os.urandom(1024*1024 + 42)
        input = StringReader(data)
        encrypting_reader = EncryptingReader(input, self.passphrase,
                                             self.salt, self.iv, self.key)
        decrypting_reader = DecryptingReader(encrypting_reader, self.passphrase, self.key)
        self.assertEqual(len(decrypting_reader), 1024*1024 + 48)
        self.assertEqual(decrypting_reader.read(42), data[:42])
        self.assertEqual(decrypting_reader.read(1024*1024), data[42:])
        self.assertEqual(decrypting_reader.read(1), '')
        self.assertEqual(decrypting_reader.read(1), '')


class TestPbkdf2(unittest.TestCase):
    def test_pbkdf2_256bit(self):
        salt = 's' * 16
        passphrase = "passphrase"
        # verify key length
        self.assertEqual(len(pbkdf2_256bit(passphrase, salt)), 32)
        # 1000 rounds
        key1 = pbkdf2_256bit(passphrase, salt, 1000).encode('base64').strip()
        key2 = 'XY0B6MwJylxvoD8GiHFblbAZ99/FAl/kGNih5ehc6OA='
        self.assertEqual(key1, key2)
        # default 4096 rounds
        key1 = pbkdf2_256bit(passphrase, salt).encode('base64').strip()
        key2 = 'H2emsRWOYFcO1iFe3V9AaimVe5UDGlR+OUH7dYjcUcI='
        self.assertEqual(key1, key2)

unittest.main()
