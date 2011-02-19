#!/usr/bin/env python
"""
RestBackup(tm) Client Library

This module provides convenient classes for making calls to the
RestBackup(tm) Backup and Management APIs.  These APIs are documented
at http://dev.restbackup.com/developers

Example usage:

import restbackup
man_api_access_url = 'https://HF7X7S:7IQ5d11Mxw7xxQEW@us.restbackup.com/'
man_api = restbackup.ManagementApiCaller(man_api_access_url)
backup_api = man_api.create_backup_account('My Backup Account')

backup_api.put(name='/data-20110211', data='a string with data')
print backup_api.get(name='/data-20110211').read()
for (name,size,date,createtime,deletetime) in backup_api.list():
    print name, size, date

backup_api = restbackup.BackupApiCaller('https://9WQ:By7brh@us.restbackup.com/')
reader = restbackup.FileReader('file-to-encrypt-and-upload')
backup_api.put_encrypted('passphrase', '/encrypted-file', reader)

reader = backup_api.get_encrypted('passphrase', '/encrypted-file')
local_file = open('downloaded-and-decrypted-file', 'wb')
while True:
    chunk = reader.read(1024)
    if not chunk:
        break
    local_file.write(chunk)
"""

__author__ = 'Michael Leonhard'
__license__ = 'Copyright (C) 2011 Rest Backup LLC.  Use of this software is subject to the RestBackup.com Terms of Use, http://www.restbackup.com/terms'
__version__ = '1.2'

import httplib
import json
import os.path
import re
import sys
import time
import urllib

MAX_ATTEMPTS = 5
FIRST_RETRY_DELAY_SECONDS = 1
NEW_ACCOUNT_DELAY_SECONDS = 5

def make_http_user_agent_string():
    module_version = "restbackup-python/%s" % (__version__)
    (major,minor,micro) = sys.version_info[0:3]
    python_version = "Python/%s.%s.%s" % (major,minor,micro)
    os_version = sys.platform # build-time value: win32, linux2, darwin, etc.
    return "%s %s %s" % (module_version, python_version, os_version)

HTTP_USER_AGENT = make_http_user_agent_string()

class RestBackupException(Exception): pass

class HttpCaller:
    """Base class that performs HTTP requests to RestBackup(tm)
    access-urls with authentication
    
    Use BackupApiCaller and ManagementApiCaller classes instead of this class.
    """
    
    def __init__(self, access_url):
        ACCESS_URL_REGEX = r'^(https?)://([a-zA-Z0-9]+):([a-zA-Z0-9]+)' \
            r'@([-.a-zA-Z0-9]+(?::[0-9]+)?)/$'
        match_obj = re.match(ACCESS_URL_REGEX, access_url)
        if not match_obj:
            raise RestBackupException("Invalid access url %r" % (access_url))
        (scheme, username, password, host) = match_obj.groups()
        self.access_url = access_url
        self.scheme = scheme
        self.host = host
        encoded_userpass = (username + ":" + password).encode('base64').strip()
        self.precomputed_headers = {
            'Authorization' : "Basic " + encoded_userpass,
            'User-Agent' : HTTP_USER_AGENT
            }
    
    def get_http_connection(self):
        if self.scheme == 'http':
            return httplib.HTTPConnection(self.host)
        else:
            return httplib.HTTPSConnection(self.host)
    
    def call(self, method, uri, body=None, extra_headers={}):
        # HTTP PUT from Python explained in:
        # http://infomesh.net/2001/QuickPut/QuickPut.txt
        encoded_uri = uri.encode('utf-8')
        headers = self.precomputed_headers.copy()
        headers.update(extra_headers)
        retry_delay_seconds = FIRST_RETRY_DELAY_SECONDS
        for attempt in xrange(0, MAX_ATTEMPTS):
            try:
                h = self.get_http_connection()
                h.request(method, encoded_uri, body, headers)
                response = h.getresponse()
            except Exception, e:
                raise RestBackupException(e)
            if response.status >= 200 and response.status < 300:
                return response # 2xx success
            elif response.status >= 500 and response.status < 600:
                pass # 5xx retry
            else: # 4xx fail
                description = "%s %s" % (response.status, response.reason)
                raise RestBackupException(description)
            
            time.sleep(retry_delay_seconds)
            retry_delay_seconds *= 2 # exponential backoff
        
        # raise last 5xx
        raise RestBackupException("Gave up after attempt %s failed: %s %s"
                                  % (attempt, response.status, response.reason))
    
    def post(self, uri, params_dict):
        """Perform an HTTP POST request to the API"""
        body = urllib.urlencode(params_dict)
        extra_header = {'Content-Type':'application/x-www-form-urlencoded'}
        return self.call('POST', uri, body, extra_header)


class ManagementApiCaller(HttpCaller):
    """Interface class for the RestBackup(tm) Management API
    
    Instantiate like this:
    management_api_access_url = 'https://HF7X7S:7I1Mxw7xxQEW@us.restbackup.com/'
    management_api = restbackup.ManagementApiCaller(management_api_access_url)
    """
    
    def create_backup_account(self, description, retain_uploads_days=365,
                              delay_seconds=NEW_ACCOUNT_DELAY_SECONDS):
        """Adds a backup account, returns a BackupApiCaller object
        
        You can obtain the new backup account details from the returned object:
        b = management_api.create_backup_account('My Backup Account')
        print b.access_url, b.description, b.retain_uploads_days, b.account_id
        """
        params = {'description':description, 'retaindays':retain_uploads_days}
        response = self.post('/', params)
        response_body = response.read()
        obj = json.loads(response_body)
        time.sleep(delay_seconds)
        return BackupApiCaller(obj['access-url'], obj['retaindays'],
                               obj['description'], obj['account'])
    
    def get_backup_account(self, account_id):
        """Looks up the backup account with the specified account id,
        returns a BackupApiCaller object
        
        You can obtain the backup account details from the returned object:
        b = management_api.get_backup_account('/171633a5-233f-9098-bac14260013')
        print b.access_url, b.description, b.retain_uploads_days, b.account_id
        """
        response = self.call('GET', account_id)
        response_body = response.read()
        obj = json.loads(response_body)
        return BackupApiCaller(obj['access-url'], obj['retaindays'], 
                               obj['description'], obj['account'])
    
    def delete_backup_account(self, account_id):
        """Deletes the backup account with the specified account id.
        Returns a string containing the response body."""
        response = self.call('DELETE', account_id)
        return response.read()
    
    def list_backup_accounts(self):
        """Downloads the list of backup accounts.  Returns a list
        3-tuples: (account_id, retain_uploads_days, description)"""
        response = self.call('GET', '/')
        response_body = response.read()
        array = json.loads(response_body)
        return [(obj['account'],obj['retaindays'],obj['description'])
                for obj in array]
    
    def __str__(self):
        return "management api %r" % (self.access_url)
    
    def __repr__(self):
        return "ManagementApiCaller(access_url=%r)" % (self.access_url)


class BackupApiCaller(HttpCaller):
    """Interface class for the RestBackup(tm) Management API
    
    Instantiate like this:
    access_url = 'https://JCC597:QCrr3yYSApik0fKP@us.restbackup.com/'
    backup_api = restbackup.BackupApiCaller(access_url)
    """
    def __init__(self, access_url, retain_uploads_days=None, description=None,
                 account_id=None):
        self.access_url = access_url
        self.retain_uploads_days = retain_uploads_days
        self.description = description
        self.account_id = account_id
        HttpCaller.__init__(self, access_url)
    
    def put(self, name, data):
        """Uploads the provided data to the backup account, storing it
        with the specified name.  Data may be a byte string or a
        RewindableSizedInputStream object.  Returns a string
        containing the response body.
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
        and PBKDF2 with 1000 rounds of HMAC-SHA-256 for key
        generation.  Raises RestBackupException on error.
        """
        import chlorocrypt
        if not hasattr(data, 'read'):
            data = StringReader(data)
        encrypted = chlorocrypt.EncryptingReader(data, passphrase)
        extra_headers = {'Content-Length':str(len(encrypted))}
        response = self.call('PUT', name, encrypted, extra_headers)
        return response.read()
    
    def get(self, name):
        """Retrieves the specified file.  Returns a SizedInputStream
        object.
        
        Use len(stream_obj) to find the length of the file.  Call
        stream_obj.read([size]) to get the data."""
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
        http_response = self.call('GET', name)
        http_reader = HttpResponseReader(http_response)
        decrypted = chlorocrypt.DecryptingReader(http_reader, passphrase)
        return decrypted
    
    def list(self):
        """Lists the files available on the backup account.  Returns a
        list of tuples: (name,size,date,createtime,deletetime)
        """
        extra_headers = {'Accept':'application/json'}
        response = self.call('GET', '/', extra_headers=extra_headers)
        response_body = response.read()
        array = json.loads(response_body)
        return [(obj['name'],obj['size'],obj['date'],obj['createtime'],
                 obj['deletetime']) for obj in array]
    
    def __str__(self):
        return "backup api %r" % (self.access_url)
    
    def __repr__(self):
        return "BackupApiCaller(access_url=%r,retain_uploads_days=%r," \
            "description=%r,account_id=%r)" \
            % (self.access_url,self.retain_uploads_days,
               self.description,self.account_id)


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

