from restbackup import StringReader
from chlorocrypt import BadMacException
from chlorocrypt import DataDamagedException
from chlorocrypt import DataTruncatedException
from chlorocrypt import WrongPassphraseException
from chlorocrypt import MacAddingReader
from chlorocrypt import MacCheckingReader
from chlorocrypt import PaddingAddingReader
from chlorocrypt import PaddingStrippingReader
from chlorocrypt import NullBlockAddingReader
from chlorocrypt import NullBlockRemovingReader
from chlorocrypt import AesCbcEncryptingReader
from chlorocrypt import AesCbcDecryptingReader
from chlorocrypt import EncryptingReader
from chlorocrypt import DecryptingReader
from chlorocrypt import pbkdf2_256bit
import unittest

class TestMacAddingReader(unittest.TestCase):
    def setUp(self):
        self.passphrase = 'passphrase'
        self.salt = 's' * 16
        self.key = 'k' * 32
    
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
        mac = 'YQpcosYIuPVCQkP7gRXBwhCe0HYXXymYoCyKU162wmY='.decode('base64')
        reader = MacAddingReader(data, self.passphrase, self.salt, self.key)
        self.assertEqual(len(reader), 16 + 1024*1024 + 32)
        self.assertEqual(reader.read(16), self.salt)
        self.assertEqual(reader.read(1), 'a')
        self.assertEqual(reader.read(1023), 'a'*1023)
        self.assertEqual(reader.read(1023*1024), 'a'*1023*1024)
        self.assertEqual(reader.read(32), mac)
        self.assertEqual(reader.read(1), '')
    
    def test_real_key(self):
        data = StringReader('1234567')
        mac = 'pjhdkY3tLUUFuc3Yy7XNGv9OnNcRrvIdePDfsTwC5Jc='.decode('base64')
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
        mac = 'YQpcosYIuPVCQkP7gRXBwhCe0HYXXymYoCyKU162wmY='.decode('base64')
        input = StringReader(self.salt + 'a' * 1024*1024 + mac)
        reader = MacCheckingReader(input, self.passphrase, self.key)
        self.assertEqual(len(reader), 1024*1024)
        self.assertEqual(reader.read(1), 'a')
        self.assertEqual(reader.read(1023), 'a'*1023)
        self.assertEqual(reader.read(1024*1024), 'a'*1023*1024)
        self.assertEqual(reader.read(1), '')
        self.assertEqual(reader.read(1), '')
    
    def test_1mb_bad_mac(self):
        mac = 'XQpcosYIuPVCQkP7gRXBwhCe0HYXXymYoCyKU162wmY='.decode('base64')
        input = StringReader(self.salt + 'a' * 1024*1024 + mac)
        reader = MacCheckingReader(input, self.passphrase, self.key)
        self.assertRaises(BadMacException, reader.read, 1024*1024 + 1)
    
    def test_real_key(self):
        mac = 'pjhdkY3tLUUFuc3Yy7XNGv9OnNcRrvIdePDfsTwC5Jc='.decode('base64')
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


class TestNullBlockAddingReader(unittest.TestCase):
    def setUp(self):
        self.null_block = '\x00' * 16
    
    def test_no_bytes(self):
        reader = NullBlockAddingReader(StringReader(''))
        self.assertEqual(len(reader), 16 + 0)
        self.assertEqual(reader.read(16 + 0), self.null_block + '')
        self.assertEqual(reader.read(1), '')
    
    def test_1_byte(self):
        reader = NullBlockAddingReader(StringReader('a'))
        self.assertEqual(len(reader), 16 + 1)
        self.assertEqual(reader.read(16 + 1), self.null_block + 'a')
        self.assertEqual(reader.read(1), '')
    
    def test_7_bytes(self):
        data = '1234567'
        reader = NullBlockAddingReader(StringReader(data))
        self.assertEqual(len(reader), 16 + 7)
        self.assertEqual(reader.read(16), self.null_block)
        self.assertEqual(reader.read(1024), data)
        self.assertEqual(reader.read(1), '')
    
    def test_16_bytes(self):
        data = '0123456789abcdef'
        reader = NullBlockAddingReader(StringReader(data))
        self.assertEqual(len(reader), 16 + 16)
        self.assertEqual(reader.read(16), self.null_block)
        self.assertEqual(reader.read(1024), data)
        self.assertEqual(reader.read(1), '')
    
    def test_32_bytes(self):
        data = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
        reader = NullBlockAddingReader(StringReader(data))
        self.assertEqual(len(reader), 16 + 32)
        self.assertEqual(reader.read(16), self.null_block)
        self.assertEqual(reader.read(1024), data)
        self.assertEqual(reader.read(1), '')
    
    def test_read_all(self):
        data = '1234567'
        reader = NullBlockAddingReader(StringReader(data))
        self.assertEqual(len(reader), 16 + 7)
        self.assertEqual(reader.read(), self.null_block + data)
        self.assertEqual(reader.read(), '')
        reader = NullBlockAddingReader(StringReader(data))
        self.assertEqual(reader.read(18), self.null_block + data[:2])
        self.assertEqual(reader.read(), data[2:])
        self.assertEqual(reader.read(), '')
        reader = NullBlockAddingReader(StringReader(data))
        self.assertEqual(reader.read(25), self.null_block + data)
        self.assertEqual(reader.read(), '')
    
    def test_read_all_neg(self):
        data = '1234567'
        reader = NullBlockAddingReader(StringReader(data))
        self.assertEqual(len(reader), 16 + 7)
        self.assertEqual(reader.read(-1), self.null_block + data)
        self.assertEqual(reader.read(-1), '')
        reader = NullBlockAddingReader(StringReader(data))
        self.assertEqual(reader.read(18), self.null_block + data[:2])
        self.assertEqual(reader.read(-1), data[2:])
        self.assertEqual(reader.read(-1), '')
        reader = NullBlockAddingReader(StringReader(data))
        self.assertEqual(reader.read(25), self.null_block + data)
        self.assertEqual(reader.read(-1), '')
    
    def test_rewind(self):
        data = '1234567'
        reader = NullBlockAddingReader(StringReader(data))
        self.assertEqual(len(reader), 16 + 7)
        self.assertEqual(reader.read(16 + 1), self.null_block + '1')
        reader.rewind()
        self.assertEqual(len(reader), 16 + 7)
        self.assertEqual(reader.read(16 + 1), self.null_block + '1')
        self.assertEqual(reader.read(3), '234')
        self.assertEqual(reader.read(1024), '567')
        self.assertEqual(reader.read(1024), '')
        reader.rewind()
        self.assertEqual(len(reader), 16 + 7)
        self.assertEqual(reader.read(16 + 1), self.null_block + '1')
        self.assertEqual(reader.read(3), '234')
        self.assertEqual(reader.read(1024), '567')
        self.assertEqual(reader.read(1024), '')
    
    def test_close(self):
        reader = NullBlockAddingReader(StringReader('1234567'))
        reader.read()
        reader.close()
        self.assertRaises(Exception, reader.read, 1)


class TestNullBlockRemovingReader(unittest.TestCase):
    def setUp(self):
        self.null_block = '\x00' * 16
    
    def test_no_bytes(self):
        reader = NullBlockRemovingReader(StringReader(self.null_block + ''))
        self.assertEqual(len(reader), 0)
        self.assertEqual(reader.read(1), '')
    
    def test_1_byte(self):
        reader = NullBlockRemovingReader(StringReader(self.null_block + 'a'))
        self.assertEqual(len(reader), 1)
        self.assertEqual(reader.read(1), 'a')
        self.assertEqual(reader.read(1), '')
    
    def test_16_bytes(self):
        data = '0123456789abcdef'
        reader = NullBlockRemovingReader(StringReader(self.null_block + data))
        self.assertEqual(len(reader), 16)
        self.assertEqual(reader.read(1), data[:1])
        self.assertEqual(reader.read(1024), data[1:])
        self.assertEqual(reader.read(1), '')
    
    def test_32_bytes(self):
        data = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
        reader = NullBlockRemovingReader(StringReader(self.null_block + data))
        self.assertEqual(len(reader), 32)
        self.assertEqual(reader.read(1), data[:1])
        self.assertEqual(reader.read(1024), data[1:])
        self.assertEqual(reader.read(1), '')
    
    def test_read_all(self):
        data = '0123456789abcdef'
        reader = NullBlockRemovingReader(StringReader(self.null_block + data))
        self.assertEqual(len(reader), 16)
        self.assertEqual(reader.read(), data)
        self.assertEqual(reader.read(), '')
        reader = NullBlockRemovingReader(StringReader(self.null_block + data))
        self.assertEqual(reader.read(2), data[:2])
        self.assertEqual(reader.read(), data[2:])
        self.assertEqual(reader.read(), '')
        reader = NullBlockRemovingReader(StringReader(self.null_block + data))
        self.assertEqual(reader.read(16), data)
        self.assertEqual(reader.read(), '')
    
    def test_read_all_neg(self):
        data = '0123456789abcdef'
        reader = NullBlockRemovingReader(StringReader(self.null_block + data))
        self.assertEqual(len(reader), 16)
        self.assertEqual(reader.read(-1), data)
        self.assertEqual(reader.read(-1), '')
        reader = NullBlockRemovingReader(StringReader(self.null_block + data))
        self.assertEqual(reader.read(2), data[:2])
        self.assertEqual(reader.read(-1), data[2:])
        self.assertEqual(reader.read(-1), '')
        reader = NullBlockRemovingReader(StringReader(self.null_block + data))
        self.assertEqual(reader.read(16), data)
        self.assertEqual(reader.read(-1), '')
    
    def test_close(self):
        data = '1234567'
        reader = NullBlockRemovingReader(StringReader(self.null_block + data))
        reader.read()
        reader.close()
        self.assertRaises(Exception, reader.read, 1)
    
    def test_wrong_passphrase(self):
        non_null_block = '\x01' + '\x00' * 15
        data = '0123456789abcdef'
        input = StringReader(non_null_block + data)
        self.assertRaises(WrongPassphraseException, 
                          NullBlockRemovingReader, input)


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
        ciphertext = 'u2VlDewnDNd+6AzfKDCb+g=='.decode('base64')
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
        ciphertext = 'u2VlDewnDNd+6AzfKDCb+g=='.decode('base64')
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


class TestEncryptingReader(unittest.TestCase):
    def setUp(self):
        self.passphrase = 'passphrase'
        self.salt = 's' * 16
        self.iv = 'i' * 16
        self.key = 'k' * 32
    
    def test_no_bytes(self):
        data = ''
        ciphertext = 'GrEi4QMwqyNQX1nODd1Qhw3' \
            'xjWEjSUTA3L9TcQItP4E='.decode('base64')
        mac = 'JkQpFN1ZOVAt4F0bwLHHN9GgfFye/2pie83t7SpcAiU='.decode('base64')
        reader = EncryptingReader(StringReader(data), self.passphrase,
                                  self.salt, self.iv, self.key)
        self.assertEqual(len(reader), 16 + (16 + 16 + (16 + 0 + 16)) + 32)
        self.assertEqual(reader.read(16 + (16 + 16 + (16 + 0 + 16)) + 32),
                         self.salt + self.salt + self.iv + ciphertext + mac)
        self.assertEqual(reader.read(1), '')
    
    def test_1_byte(self):
        data = 'a'
        ciphertext = 'GrEi4QMwqyNQX1nODd1Qh3h' \
            'crQNnQM6uNF6Zxl5m21g='.decode('base64')
        mac = 'rUUeNV1NzbolYgPHp5IEKZ9ycfNYzmvqu1UsjLD1nZI='.decode('base64')
        reader = EncryptingReader(StringReader(data), self.passphrase,
                                  self.salt, self.iv, self.key)
        self.assertEqual(len(reader), 16 + (16 + 16 + (16 + 1 + 15)) + 32)
        self.assertEqual(reader.read(16 + (16 + 16 + (16 + 1 + 15)) + 32),
                         self.salt + self.salt + self.iv + ciphertext + mac)
        self.assertEqual(reader.read(1), '')
    
    def test_16_bytes(self):
        data = '0123456789abcdef'
        ciphertext = 'GrEi4QMwqyNQX1nODd1Qh9wog/6Gery0z3RWfq' \
            'Su+u4KasWWZO7euiuS+dllC2OY'.decode('base64')
        mac = 'yBpRfLybWw8Fuka5ir5e+HlKeckF+L0TuCJpQX6Fk5g='.decode('base64')
        reader = EncryptingReader(StringReader(data), self.passphrase,
                                  self.salt, self.iv, self.key)
        self.assertEqual(len(reader), 16 + (16 + 16 + (16 + 16 + 16)) + 32)
        self.assertEqual(reader.read(16), self.salt)
        self.assertEqual(reader.read(16 + 16), self.salt + self.iv)
        self.assertEqual(reader.read(16 + 16 + 16), ciphertext)
        self.assertEqual(reader.read(32), mac)
        self.assertEqual(reader.read(1), '')
    
    def test_32_bytes(self):
        data = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
        ciphertext = 'GrEi4QMwqyNQX1nODd1Qh0oUvRaX/+eX4DOJ+YFxYUUEHekxg/' \
            'dle9SRKPqC7V29KRD7mwxkp0tb\n685PgiE6rw=='.decode('base64')
        mac = 'qeRPmZx0WT2xy0LBEqAu4uNJvSt5XCHj2UHEbbU4JO4='.decode('base64')
        reader = EncryptingReader(StringReader(data), self.passphrase,
                                  self.salt, self.iv, self.key)
        self.assertEqual(len(reader), 16 + (16 + 16 + (16 + 32 + 16)) + 32)
        self.assertEqual(reader.read(16), self.salt)
        self.assertEqual(reader.read(16 + 16), self.salt + self.iv)
        self.assertEqual(reader.read(1024), ciphertext + mac)
        self.assertEqual(reader.read(1), '')
    
    def test_16_bytes_with_real_key(self):
        data = '0123456789abcdef'
        ciphertext = 'aQA5Gos0LVF2R4hGmZHc+bACchp86Xy1Qzhi' \
            'zXpYiavQywXMBOM+ZQhZotghph4R'.decode('base64')
        mac = 'h65UW7QMUnLUWKh9aTPCYIZ5NKY1x+vcMtEkDh2mjbg='.decode('base64')
        reader = EncryptingReader(StringReader(data), self.passphrase,
                                  self.salt, self.iv)
        self.assertEqual(len(reader), 16 + (16 + 16 + (16 + 16 + 16)) + 32)
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
        ciphertext = 'GrEi4QMwqyNQX1nODd1Qh9wog/6Gery0z3RWfq' \
            'Su+u4KasWWZO7euiuS+dllC2OY'.decode('base64')
        mac = 'yBpRfLybWw8Fuka5ir5e+HlKeckF+L0TuCJpQX6Fk5g='.decode('base64')
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
        ciphertext = 'GrEi4QMwqyNQX1nODd1Qh9wog/6Gery0z3RWfq' \
            'Su+u4KasWWZO7euiuS+dllC2OY'.decode('base64')
        mac = 'yBpRfLybWw8Fuka5ir5e+HlKeckF+L0TuCJpQX6Fk5g='.decode('base64')
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
        ciphertext = 'GrEi4QMwqyNQX1nODd1Qh9wog/6Gery0z3RWfq' \
            'Su+u4KasWWZO7euiuS+dllC2OY'.decode('base64')
        mac = 'yBpRfLybWw8Fuka5ir5e+HlKeckF+L0TuCJpQX6Fk5g='.decode('base64')
        reader = EncryptingReader(StringReader(data), self.passphrase,
                                  self.salt, self.iv, self.key)
        self.assertEqual(len(reader), 16 + (16 + 16 + (16 + 16 + 16)) + 32)
        self.assertEqual(reader.read(48 + 1),
                         self.salt + self.salt + self.iv + ciphertext[:1])
        reader.rewind()
        self.assertEqual(len(reader), 16 + (16 + 16 + (16 + 16 + 16)) + 32)
        self.assertEqual(reader.read(48 + 1),
                         self.salt + self.salt + self.iv + ciphertext[:1])
        self.assertEqual(reader.read(3), ciphertext[1:4])
        self.assertEqual(reader.read(1024), ciphertext[4:] + mac)
        self.assertEqual(reader.read(1024), '')
        reader.rewind()
        self.assertEqual(len(reader), 16 + (16 + 16 + (16 + 16 + 16)) + 32)
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
    
    def test_no_null_block(self):
        input = StringReader(self.salt + self.salt + self.iv + self.mac)
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
        ciphertext = 'GrEi4QMwqyNQX1nODd1Qhw3' \
            'xjWEjSUTA3L9TcQItP4E='.decode('base64')
        mac = 'JkQpFN1ZOVAt4F0bwLHHN9GgfFye/2pie83t7SpcAiU='.decode('base64')
        input = StringReader(self.salt + self.salt + self.iv + ciphertext + mac)
        reader = DecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(len(reader), 16)
        self.assertEqual(reader.read(1), '')
    
    def test_1_byte(self):
        data = 'a'
        ciphertext = 'GrEi4QMwqyNQX1nODd1Qh3h' \
            'crQNnQM6uNF6Zxl5m21g='.decode('base64')
        mac = 'rUUeNV1NzbolYgPHp5IEKZ9ycfNYzmvqu1UsjLD1nZI='.decode('base64')
        input = StringReader(self.salt + self.salt + self.iv + ciphertext + mac)
        reader = DecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(len(reader), 16)
        self.assertEqual(reader.read(1), 'a')
        self.assertEqual(reader.read(1), '')
    
    def test_partial_block(self):
        data = ''
        ciphertext = 'GrEi4QMwqyNQX1nODd1Qhw3' \
            'xjWEjSUTA3L9TcQItP4E='.decode('base64') + 'x'
        mac = 'JkQpFN1ZOVAt4F0bwLHHN9GgfFye/2pie83t7SpcAiU='.decode('base64')
        input = StringReader(self.salt + self.salt + self.iv + ciphertext + mac)
        reader = DecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(len(reader), 17)
        self.assertRaises(DataDamagedException, reader.read, 1)
    
    def test_16_bytes(self):
        data = '0123456789abcdef'
        ciphertext = 'GrEi4QMwqyNQX1nODd1Qh9wog/6Gery0z3RWfq' \
            'Su+u4KasWWZO7euiuS+dllC2OY'.decode('base64')
        mac = 'yBpRfLybWw8Fuka5ir5e+HlKeckF+L0TuCJpQX6Fk5g='.decode('base64')
        input = StringReader(self.salt + self.salt + self.iv + ciphertext + mac)
        reader = DecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(len(reader), 32)
        self.assertEqual(reader.read(1), '0')
        self.assertEqual(reader.read(100), '123456789abcdef')
        self.assertEqual(reader.read(1), '')
    
    def test_16_bytes_plus_partial_block(self):
        data = '0123456789abcdef'
        ciphertext = 'GrEi4QMwqyNQX1nODd1Qh9wog/6Gery0z3RWfq' \
            'Su+u4KasWWZO7euiuS+dllC2OY'.decode('base64') + 'x'
        mac = 'yBpRfLybWw8Fuka5ir5e+HlKeckF+L0TuCJpQX6Fk5g='.decode('base64')
        input = StringReader(self.salt + self.salt + self.iv + ciphertext + mac)
        reader = DecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(len(reader), 33)
        self.assertEqual(reader.read(1), '0')
        self.assertEqual(reader.read(15), '123456789abcdef')
        self.assertRaises(DataDamagedException, reader.read, 1)
    
    def test_32_bytes(self):
        data = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'
        ciphertext = 'GrEi4QMwqyNQX1nODd1Qh0oUvRaX/+eX4DOJ+YFxYUUEHekxg/' \
            'dle9SRKPqC7V29KRD7mwxkp0tb\n685PgiE6rw=='.decode('base64')
        mac = 'qeRPmZx0WT2xy0LBEqAu4uNJvSt5XCHj2UHEbbU4JO4='.decode('base64')
        input = StringReader(self.salt + self.salt + self.iv + ciphertext + mac)
        reader = DecryptingReader(input, self.passphrase, self.key)
        self.assertEqual(len(reader), 48)
        self.assertEqual(reader.read(1024), data)
        self.assertEqual(reader.read(1), '')
    
    def test_16_bytes_with_real_key(self):
        data = '0123456789abcdef'
        ciphertext = 'aQA5Gos0LVF2R4hGmZHc+bACchp86Xy1Qzhi' \
            'zXpYiavQywXMBOM+ZQhZotghph4R'.decode('base64')
        mac = 'h65UW7QMUnLUWKh9aTPCYIZ5NKY1x+vcMtEkDh2mjbg='.decode('base64')
        input = StringReader(self.salt + self.salt + self.iv + ciphertext + mac)
        reader = DecryptingReader(input, self.passphrase)
        self.assertEqual(len(reader), 32)
        self.assertEqual(reader.read(1024), data)
        self.assertEqual(reader.read(1), '')
    
    def test_read_all(self):
        data = '0123456789abcdef'
        ciphertext = 'GrEi4QMwqyNQX1nODd1Qh9wog/6Gery0z3RWfq' \
            'Su+u4KasWWZO7euiuS+dllC2OY'.decode('base64')
        mac = 'yBpRfLybWw8Fuka5ir5e+HlKeckF+L0TuCJpQX6Fk5g='.decode('base64')
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
        ciphertext = 'GrEi4QMwqyNQX1nODd1Qh9wog/6Gery0z3RWfq' \
            'Su+u4KasWWZO7euiuS+dllC2OY'.decode('base64')
        mac = 'yBpRfLybWw8Fuka5ir5e+HlKeckF+L0TuCJpQX6Fk5g='.decode('base64')
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
        ciphertext = 'aQA5Gos0LVF2R4hGmZHc+bACchp86Xy1Qzhi' \
            'zXpYiavQywXMBOM+ZQhZotghph4R'.decode('base64')
        mac = 'h65UW7QMUnLUWKh9aTPCYIZ5NKY1x+vcMtEkDh2mjbg='.decode('base64')
        input = StringReader(self.salt + self.salt + self.iv + ciphertext + mac)
        self.assertRaises(WrongPassphraseException, DecryptingReader, 
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

class TestPbkdf2(unittest.TestCase):
    def test_pbkdf2_256bit(self):
        salt = 's' * 16
        passphrase = "passphrase"
        self.assertEqual(len(pbkdf2_256bit(passphrase, salt)), 32)
        key1 = pbkdf2_256bit(passphrase, salt).encode('base64').strip()
        key2 = 'XY0B6MwJylxvoD8GiHFblbAZ99/FAl/kGNih5ehc6OA='
        self.assertEqual(key1, key2)

unittest.main()
