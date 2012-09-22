#!/usr/bin/env python
"""
RestBackup(tm) Client Library

This module provides convenient classes for making calls to the
RestBackup(tm) Backup API.  The API is documented
at http://www.restbackup.com/api

Example usage:

import restbackup
access_url = 'https://9WQ:By7brh@us.restbackup.com/'
backup_api = restbackup.BackupApiCaller(access_url, user_agent="Demo/1.0")

# Backup a string
backup_api.put(name='/data-20110211', data='a string with data')

# Retrieve the backup
print backup_api.get(name='/data-20110211').read()

# List backups
for (name,size,createtime) in backup_api.list():
    print name, size, createtime

# Backup a file
reader = restbackup.FileReader('data-20110211.zip')
backup_api.put('/data-20110211.zip', reader)

# Restore the file
reader = backup_api.get('/data-20110211.zip')
local_file = open('restored.data-20110211.zip', 'wb')
while True:
    chunk = reader.read(65536)
    if not chunk:
        break
    local_file.write(chunk)
local_file.close()

# Encrypt and Backup a file
reader = restbackup.FileReader('data-20110211.zip')
backup_api.put_encrypted('passphrase', '/data-20110211.zip.encrypted', reader)

# Restore and decrypt the file
reader = backup_api.get_encrypted('passphrase', '/data-20110211.zip.encrypted')
local_file = open('restored.decrypted.data-20110211.zip', 'wb')
while True:
    chunk = reader.read(65536)
    if not chunk:
        break
    local_file.write(chunk)
local_file.close()
"""

__author__ = 'Michael Leonhard'
__license__ = 'Copyright (C) 2011 Rest Backup LLC.  Use of this software is subject to the RestBackup.com Terms of Use, http://www.restbackup.com/terms'
__version__ = '1.4'

import httplib
import json
import os.path
import re
import sys
import time
import urllib

MAX_ATTEMPTS = 5
FIRST_RETRY_DELAY_SECONDS = 1

class RestBackupException(IOError): pass
class RestBackup401NotAuthorizedException(RestBackupException): pass
class RestBackup404NotFoundException(RestBackupException): pass
class RestBackup405MethodNotAllowed(RestBackupException): pass

ACCESS_URL_REGEX = r'^(https?)://([a-zA-Z0-9]+):([a-zA-Z0-9]+)@([-.a-zA-Z0-9]+(?::[0-9]+)?)/$'

def parse_access_url(access_url):
    match_obj = re.match(ACCESS_URL_REGEX, access_url)
    if not match_obj:
        raise ValueError("Invalid access url %r" % (access_url))
    return match_obj

class HttpCaller:
    """Base class that performs HTTP requests to RestBackup(tm)
    access-urls with authentication
    
    Use BackupApiCaller instead of this class.
    """
    
    def __init__(self, access_url, user_agent):
        """Access_url must be a url of the form
        'https://USER:PASS@host/'.  Raises ValueError if access url is
        malformed."""
        match_obj = parse_access_url(access_url)
        (scheme, username, password, host) = match_obj.groups()
        self.access_url = access_url
        self.scheme = scheme
        self.host = host
        self.precomputed_headers = {}
        self.set_user_pass(username, password)
        
        module_version = "restbackup-python/%s" % (__version__)
        python_version = "Python/%s.%s.%s" % \
            (sys.version_info.major, sys.version_info.minor, sys.version_info.micro)
        os_version = sys.platform # "win32", "linux2", "darwin", etc.
        full_user_agent = "%s %s %s %s" % \
            (user_agent, module_version, python_version, os_version)
        self.precomputed_headers['User-Agent'] = full_user_agent
    
    def set_user_pass(self, username, password):
        encoded_userpass = (username + ":" + password).encode('base64').strip().replace('\n','')
        self.precomputed_headers['Authorization'] = "Basic " + encoded_userpass
    
    def get_http_connection(self):
        if self.scheme == 'http':
            return httplib.HTTPConnection(self.host)
        else:
            return httplib.HTTPSConnection(self.host)
    
    def call(self, method, uri, body=None, extra_headers={}):
        """Performs an HTTP request, retrying on 5xx error, with
        exponential backoff.  Body may be None, a string, or a
        RewindableSizedInputStream.
        
        Raises RestBackupException on error.
        """
        # HTTP PUT from Python explained in:
        # http://infomesh.net/2001/QuickPut/QuickPut.txt
        encoded_uri = uri.encode('utf-8')
        quoted_uri = urllib.quote(encoded_uri)
        headers = self.precomputed_headers.copy()
        headers.update(extra_headers)
        retry_delay_seconds = FIRST_RETRY_DELAY_SECONDS
        for attempt in xrange(0, MAX_ATTEMPTS):
            try:
                h = self.get_http_connection()
                h.request(method, quoted_uri, body, headers)
                response = h.getresponse()
            except Exception, e:
                (e_type, e_value, e_traceback) = sys.exc_info()
                raise RestBackupException(e), None, e_traceback
            if response.status >= 200 and response.status < 300:
                return response # 2xx success
            elif response.status >= 500 and response.status < 600:
                pass # 5xx retry
            elif response.status == 401:
                description = "%s %s" % (response.status, response.reason)
                raise RestBackup401NotAuthorizedException(description)
            elif response.status == 405:
                description = "%s %s" % (response.status, response.reason)
                raise RestBackup405MethodNotAllowed(description)
            elif response.status == 404:
                description = "%s %s" % (response.status, response.reason)
                raise RestBackup404NotFoundException(description)
            else: # 4xx fail
                description = "%s %s" % (response.status, response.reason)
                raise RestBackupException(description)
            
            time.sleep(retry_delay_seconds)
            retry_delay_seconds *= 2 # exponential backoff
            if hasattr(body, "read"):
                body.rewind()
        
        # raise last 5xx
        raise RestBackupException("Gave up after attempt %s failed: %s %s"
                                  % (attempt, response.status, response.reason))
    
    def post(self, uri, params_dict):
        """Perform an HTTP POST request.  Params_dict must be a
        dictionary with string keys values.
        
        Raises RestBackupException on error.
        """
        body = urllib.urlencode(params_dict)
        extra_header = {'Content-Type':'application/x-www-form-urlencoded'}
        return self.call('POST', uri, body, extra_header)


class BackupApiCaller(HttpCaller):
    """Interface class for the RestBackup(tm) Management API
    
    Instantiate like this:
    access_url = 'https://JCC597:QCrr3yYSApik0fKP@us.restbackup.com/'
    backup_api = restbackup.BackupApiCaller(access_url)
    """
    def __init__(self, access_url, user_agent):
        """Access_url must have the form 'https://USER:PASS@host/'.
        Raises ValueError if access url is malformed."""
        HttpCaller.__init__(self, access_url, user_agent)
    
    def put(self, name, data):
        """Uploads the provided data to the backup account, storing it
        with the specified name.  Data may be a byte string or a
        RewindableSizedInputStream object.  Returns a string
        containing the response body.  Raises RestBackupException on
        error.
        """
        extra_headers = {'Content-Length':str(len(data))}
        response = self.call('PUT', name, data, extra_headers)
        return response.read()
    
    def put_encrypted(self, passphrase, name, data):
        """Encrypts and uploads the provided data to the backup
        account, storing it with the specified name.  Data may be a
        byte string or RewindableSizedInputStream object.  Returns a
        string containing the response body.
        
        Uses AES for confidentiality, SHA-256 HMAC for authentication,
        and PBKDF2 with 4096 rounds of HMAC-SHA-256 for key
        generation.  Raises RestBackupException on error.
        """
        import chlorocrypt
        if not hasattr(data, 'read'):
            data = StringReader(data)
        encrypted = chlorocrypt.EncryptingReader(data, passphrase)
        crypto_ver = 'chlorocrypt/' + chlorocrypt.__version__
        user_agent = self.precomputed_headers['User-Agent'] + ' ' + crypto_ver
        extra_headers = {
            'Content-Length':str(len(encrypted)),
            'User-Agent' : user_agent
            }
        response = self.call('PUT', name, encrypted, extra_headers)
        return response.read()
    
    def get(self, name):
        """Retrieves the specified file.  Returns a SizedInputStream
        object.
        
        Use len(stream_obj) to find the length of the file.  Call
        stream_obj.read([size]) to get the data.  Raises
        RestBackupException on error."""
        response = self.call('GET', name)
        return HttpResponseReader(response)
    
    def get_encrypted(self, passphrase, name):
        """Retrieves the specified file and decrypts it.  Returns a
        SizedInputStream object.
        
        Raises RestBackupException on network error.  Raises
        WrongPassphraseException if the provided passphrase is
        incorrect.  Raises DataDamagedException if file was corrupted
        on the network.  Due to padding, the stream may yield up to 16
        bytes less than the value of len(stream).
        """
        import chlorocrypt
        crypto_ver = 'chlorocrypt/' + chlorocrypt.__version__
        user_agent = self.precomputed_headers['User-Agent'] + ' ' + crypto_ver
        extra_headers = { 'User-Agent' : user_agent }
        http_response = self.call('GET', name, extra_headers=extra_headers)
        http_reader = HttpResponseReader(http_response)
        decrypted = chlorocrypt.DecryptingReader(http_reader, passphrase)
        return decrypted
    
    def list(self):
        """Lists the files available on the backup account.  Returns a
        list of tuples: (name,size,createtime).
        
        Raises DataDamagedException
        """
        extra_headers = {'Accept':'application/json'}
        response = self.call('GET', '/', extra_headers=extra_headers)
        response_body = response.read()
        array = json.loads(response_body)
        return [(obj['name'],obj['size'],obj['createtime']) for obj in array]
    
    def __str__(self):
        return "backup api %r" % (self.access_url)
    
    def __repr__(self):
        return "BackupApiCaller(access_url=%r)" % (self.access_url)


class InputStream(object):
    """Interface for sized input stream classes.  Subclasses should
    inherit from this class and override read_once(size).  This class
    provides a default read(size) method that calls read_once(size)
    and performs minimal buffering.
    """
    def __init__(self):
        self.parent_read_buffer = ''
    
    def read(self, size=-1):
        """Reads the stream's data source and returns a non-unicode
        string up to size bytes.  Returns less than size bytes or ''
        on EOF.  Reads all data up to EOF if size is negative or
        omitted.  Raises IOError on error."""
        if size == 0:
            return ''
        if size < 0:
            chunks = [self.parent_read_buffer]
            self.parent_read_buffer = ''
            while True:
                chunk = self.read_once(128*1024)
                if not chunk:
                    break
                chunks.append(chunk)
            return ''.join(chunks)
        else:
            while(len(self.parent_read_buffer) < size):
                bytes_needed = size - len(self.parent_read_buffer)
                chunk = self.read_once(bytes_needed)
                if not chunk:
                    break
                self.parent_read_buffer = self.parent_read_buffer + chunk
            chunk = self.parent_read_buffer[:size]
            self.parent_read_buffer = self.parent_read_buffer[size:]
            return chunk
    
    def read_once(self, size):
        """Reads the stream's data source and returns a non-unicode
        string up to size bytes.  May return less than size bytes.
        Returns '' on EOF.  Size must be an integer greater than zero.
        Raises IOError on error.
        
        Subclasses should override this method.
        """
        raise NotImplementedError()

    def close(self):
        """Closes the stream and releases resources.  This method may
        be called multiple times with no negative effects.  Do not
        call any other methods on the object after calling this
        method."""
        pass


class SizedInputStream(InputStream):
    """Interface for input streams with a known size.  Raises IOError
    on read if the bytes are not available."""
    def __init__(self, stream_length):
        InputStream.__init__(self)
        self.stream_length = stream_length
    
    def __len__(self):
        """Returns the total number of bytes contained in the stream.
        This must not change over the lifetime of the object."""
        return self.stream_length
    
    def __nonzero__(self):
        return True


class RewindableSizedInputStream(SizedInputStream):
    """Interface for rewindable input streams with a known size."""
    def __init__(self, stream_length):
        SizedInputStream.__init__(self, stream_length)
    
    def rewind(self):
        """Rewinds the stream back to the beginning.  This method
        allows us to retry network requests."""
        raise NotImplementedError()


class StringReader(RewindableSizedInputStream):
    """Rewindable sized Input stream that sources its data from a string."""
    def __init__(self, data):
        """Data must be a byte string"""
        if not isinstance(data, str):
            raise TypeError('StringReader supports only str data')
        stream_length = len(data)
        RewindableSizedInputStream.__init__(self, stream_length)
        self.data = data
        self.rewind()
    
    def read(self, size=-1):
        if size < 0:
            size = len(self.data)
        first_byte_index = self.next_byte_index
        self.next_byte_index += size
        return self.data[first_byte_index:self.next_byte_index]
    
    def read_once(self, size):
        return self.read(size)
    
    def rewind(self):
        self.next_byte_index = 0


class FileObjectReader(RewindableSizedInputStream):
    """Rewindable sized input stream that sources its data from a file
    object.  The file object must support the seek(0) method."""
    def __init__(self, f, size):
        self.file = f
        RewindableSizedInputStream.__init__(self, size)
    
    def read(self, size=-1):
        return self.file.read(size)
    
    def read_once(self, size):
        return self.read(size)
    
    def close(self):
        self.file.close()
        self.file = None
    
    def rewind(self):
        self.file.seek(0)


class FileReader(FileObjectReader):
    """Rewindable sized input stream that sources its data from a file
    with the specified name."""
    def __init__(self, filename):
        f = open(filename, 'rb')
        size = os.path.getsize(filename)
        FileObjectReader.__init__(self, f, size)


class HttpResponseReader(SizedInputStream):
    """Sized input stream that sources its data from an
    http.HTTPResponse object."""
    def __init__(self, http_response):
        content_length = http_response.getheader('Content-Length')
        stream_size = int(content_length)
        SizedInputStream.__init__(self, stream_size)
        self.http_response = http_response
    
    def read_once(self, size=-1):
        return self.http_response.read(size)

