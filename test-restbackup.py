import os
import os.path
from restbackup import FileObjectReader
from restbackup import FileReader
from restbackup import StringReader
import tempfile
import unittest

class TestFileObjectReader(unittest.TestCase):
    class FakeFileObject():
        def __init__(self, data):
            self.data = data
            self.seek(0)
            
        def read(self, size=-1):
            if size < 0:
                size = len(self.data)
            first_byte_index = self.next_byte_index
            self.next_byte_index += size
            return self.data[first_byte_index:self.next_byte_index]
        
        def seek(self, offset):
            self.next_byte_index = offset
            
        def close(self):
            pass
    
    def test_empty_file(self):
        data = ''
        reader = FileObjectReader(self.FakeFileObject(data), len(data))
        self.assertEqual(len(reader), 0)
        self.assertEqual(reader.read(1024), '')
    
    def test_one_byte(self):
        data = 'a'
        reader = FileObjectReader(self.FakeFileObject(data), len(data))
        self.assertEqual(len(reader), 1)
        self.assertEqual(reader.read(0), '')
        self.assertEqual(reader.read(1024), 'a')
        self.assertEqual(reader.read(1024), '')
    
    def test_seven_bytes(self):
        data = '1234567'
        reader = FileObjectReader(self.FakeFileObject(data), len(data))
        self.assertEqual(len(reader), 7)
        self.assertEqual(reader.read(1), '1')
        self.assertEqual(reader.read(3), '234')
        self.assertEqual(reader.read(1024), '567')
        self.assertEqual(reader.read(1024), '')
    
    def test_one_mb(self):
        data = 'a' * 1024*1024
        reader = FileObjectReader(self.FakeFileObject(data), len(data))
        self.assertEqual(len(reader), 1024*1024)
        self.assertEqual(reader.read(1), 'a')
        self.assertEqual(reader.read(1023), 'a'*1023)
        self.assertEqual(reader.read(1023*1024), 'a'*1023*1024)
        self.assertEqual(reader.read(1), '')
    
    def test_read_all(self):
        data = '1234567'
        reader = FileObjectReader(self.FakeFileObject(data), len(data))
        self.assertEqual(reader.read(), '1234567')
        self.assertEqual(reader.read(), '')
        self.assertEqual(reader.read(1), '')
        reader.rewind()
        self.assertEqual(reader.read(-1), '1234567')
        self.assertEqual(reader.read(-1), '')
        self.assertEqual(reader.read(1), '')
    
    def test_rewind(self):
        data = '1234567'
        reader = FileObjectReader(self.FakeFileObject(data), len(data))
        self.assertEqual(len(reader), 7)
        self.assertEqual(reader.read(1), '1')
        reader.rewind()
        self.assertEqual(len(reader), 7)
        self.assertEqual(reader.read(1), '1')
        self.assertEqual(reader.read(3), '234')
        self.assertEqual(reader.read(1024), '567')
        self.assertEqual(reader.read(1024), '')
        reader.rewind()
        self.assertEqual(len(reader), 7)
        self.assertEqual(reader.read(1), '1')
        self.assertEqual(reader.read(3), '234')
        self.assertEqual(reader.read(1024), '567')
        self.assertEqual(reader.read(1024), '')
    
    def test_close(self):
        data = '1234567'
        reader = FileObjectReader(self.FakeFileObject(data), len(data))
        self.assertEqual(len(reader), 7)
        self.assertEqual(reader.read(1), '1')
        reader.close()


class TestFileReader(unittest.TestCase):
    def setUp(self):
        # This is os.tempnam() without the RuntimeWarning
        file = tempfile.NamedTemporaryFile()
        self.filename = file.name
        file.close()
    
    def test_missing_file(self):
        self.assertRaises(IOError, FileReader, self.filename)
    
    def test_empty_file(self):
        open(self.filename, 'wb').close()
        reader = FileReader(self.filename)
        self.assertEqual(len(reader), 0)
        self.assertEqual(reader.read(1024), '')
    
    def test_one_byte(self):
        file = open(self.filename, 'wb')
        file.write('a')
        file.close()
        reader = FileReader(self.filename)
        self.assertEqual(len(reader), 1)
        self.assertEqual(reader.read(0), '')
        self.assertEqual(reader.read(1024), 'a')
        self.assertEqual(reader.read(1024), '')
    
    def test_seven_bytes(self):
        file = open(self.filename, 'wb')
        file.write('1234567')
        file.close()
        reader = FileReader(self.filename)
        self.assertEqual(len(reader), 7)
        self.assertEqual(reader.read(1), '1')
        self.assertEqual(reader.read(3), '234')
        self.assertEqual(reader.read(1024), '567')
        self.assertEqual(reader.read(1024), '')
    
    def test_one_mb(self):
        file = open(self.filename, 'wb')
        file.write('a' * 1024*1024)
        file.close()
        reader = FileReader(self.filename)
        self.assertEqual(len(reader), 1024*1024)
        self.assertEqual(reader.read(1), 'a')
        self.assertEqual(reader.read(1023), 'a'*1023)
        self.assertEqual(reader.read(1023*1024), 'a'*1023*1024)
        self.assertEqual(reader.read(1), '')
    
    def test_read_all(self):
        file = open(self.filename, 'wb')
        file.write('1234567')
        file.close()
        reader = FileReader(self.filename)
        self.assertEqual(reader.read(), '1234567')
        self.assertEqual(reader.read(), '')
        self.assertEqual(reader.read(1), '')
        reader.rewind()
        self.assertEqual(reader.read(-1), '1234567')
        self.assertEqual(reader.read(-1), '')
        self.assertEqual(reader.read(1), '')
    
    def test_rewind(self):
        file = open(self.filename, 'wb')
        file.write('1234567')
        file.close()
        reader = FileReader(self.filename)
        self.assertEqual(len(reader), 7)
        self.assertEqual(reader.read(1), '1')
        reader.rewind()
        self.assertEqual(len(reader), 7)
        self.assertEqual(reader.read(1), '1')
        self.assertEqual(reader.read(3), '234')
        self.assertEqual(reader.read(1024), '567')
        self.assertEqual(reader.read(1024), '')
        reader.rewind()
        self.assertEqual(len(reader), 7)
        self.assertEqual(reader.read(1), '1')
        self.assertEqual(reader.read(3), '234')
        self.assertEqual(reader.read(1024), '567')
        self.assertEqual(reader.read(1024), '')
    
    def test_close(self):
        file = open(self.filename, 'wb')
        file.write('1234567')
        file.close()
        reader = FileReader(self.filename)
        self.assertEqual(len(reader), 7)
        self.assertEqual(reader.read(1), '1')
        reader.close()
    
    def tearDown(self):
        if os.path.exists(self.filename):
            os.remove(self.filename)


class TestStringReader(unittest.TestCase):
    def test_non_string(self):
        self.assertRaises(TypeError, StringReader, 123)
    
    def test_unicode_string(self):
        self.assertRaises(TypeError, StringReader, u'abc')
    
    def test_empty_string(self):
        reader = StringReader('')
        self.assertEqual(len(reader), 0)
        self.assertEqual(reader.read(1024), '')
    
    def test_one_byte(self):
        reader = StringReader('a')
        self.assertEqual(len(reader), 1)
        self.assertEqual(reader.read(0), '')
        self.assertEqual(reader.read(1024), 'a')
        self.assertEqual(reader.read(1024), '')
    
    def test_seven_bytes(self):
        reader = StringReader('1234567')
        self.assertEqual(len(reader), 7)
        self.assertEqual(reader.read(1), '1')
        self.assertEqual(reader.read(3), '234')
        self.assertEqual(reader.read(1024), '567')
        self.assertEqual(reader.read(1024), '')
    
    def test_1mb(self):
        reader = StringReader('a' * 1024*1024)
        self.assertEqual(len(reader), 1024*1024)
        self.assertEqual(reader.read(1), 'a')
        self.assertEqual(reader.read(1023), 'a'*1023)
        self.assertEqual(reader.read(1023*1024), 'a'*1023*1024)
        self.assertEqual(reader.read(1), '')
    
    def test_read_all(self):
        reader = StringReader('1234567')
        self.assertEqual(len(reader), 7)
        self.assertEqual(reader.read(2), '12')
        self.assertEqual(reader.read(), '34567')
        self.assertEqual(reader.read(1024), '')
        reader.rewind()
        self.assertEqual(reader.read(-1), '1234567')
        self.assertEqual(reader.read(1024), '')
    
    def test_rewind(self):
        reader = StringReader('1234567')
        self.assertEqual(len(reader), 7)
        self.assertEqual(reader.read(1), '1')
        self.assertEqual(reader.read(3), '234')
        self.assertEqual(len(reader), 7)
        reader.rewind()
        self.assertEqual(len(reader), 7)
        self.assertEqual(reader.read(1), '1')
        self.assertEqual(reader.read(3), '234')
        self.assertEqual(reader.read(1024), '567')
        self.assertEqual(reader.read(1024), '')
        self.assertEqual(len(reader), 7)
        reader.close()

unittest.main()
