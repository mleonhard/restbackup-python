#!/usr/bin/env python
"""
RestBackup(tm) Client Library

This module provides convenient classes for making calls to the
RestBackup(tm) Backup and Management APIs.  These APIs are documented
at http://dev.restbackup.com/developers

Example usage:

import restbackup
man_api_access_url = 'https://HF7X7S:7IQ5d11Mxw7xxQEW@us.restbackup.com/'
man_api = restbackup.ManagementApiCaller(management_api_access_url)
backup_api = man_api.create_backup_account('My Backup Account')
backup_api.put(name='/data-20110211', data='some data')
data = backup_api.get(name='/data-20100823').read()
for (name,size,date,createtime,deletetime) in backup_account.list():
    print name, size, date
"""

__author__ = 'Michael Leonhard'
__license__ = 'Copyright (C) 2011 Rest Backup LLC.  Use of this software is subject to the RestBackup.com Terms of Use, http://www.restbackup.com/terms'
__version__ = '1.0'

import httplib
import json
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

# HTTP PUT from Python explained in:
# http://infomesh.net/2001/QuickPut/QuickPut.txt

class HttpCaller:
    """Base class that performs HTTP requests to RestBackup(tm)
    access-urls with authentication
    
    Use BackupApiCaller and ManagementApiCaller classes instead of this class.
    """
    
    def __init__(self, access_url):
        ACCESS_URL_REGEX=r'^(https?)://([a-zA-Z0-9]+):([a-zA-Z0-9]+)@([-.a-zA-Z0-9]+(?::[0-9]+)?)/$'
        match_obj = re.match(ACCESS_URL_REGEX, access_url)
        if not match_obj:
            raise RestBackupException("Invalid access url: '" + access_url + "'")
        (scheme, username, password, host) = match_obj.groups()
        self.access_url = access_url
        self.scheme = scheme
        self.host = host
        self.precomputed_headers = {
            'Authorization' : "Basic " + (username + ":" + password).encode('base64').strip(),
            'User-Agent' : HTTP_USER_AGENT
            }
    
    def get_http_connection(self):
        if self.scheme == 'http':
            return httplib.HTTPConnection(self.host)
        else:
            return httplib.HTTPSConnection(self.host)
    
    def call(self, method, uri, body=None, extra_headers={}):
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
                return response # success
            elif response.status >= 500 and response.status < 600:
                pass # retry
            else:
                raise RestBackupException("%s %s" % (response.status, response.reason))
            
            time.sleep(retry_delay_seconds)
            retry_delay_seconds *= 2 # exponential backoff
        
        raise RestBackupException("%s %s" % (response.status, response.reason))
    
    def post(self, uri, params_dict):
        """Perform an HTTP POST request to the API"""
        extra_header = {'Content-Type':'application/x-www-form-urlencoded'}
        body = urllib.urlencode(params_dict)
        return self.call('POST', uri, body, extra_header)


class ManagementApiCaller(HttpCaller):
    """Interface class for the RestBackup(tm) Management API
    
    Instantiate like this:
    management_api_access_url = 'https://HF7X7S:7IQ5d11Mxw7xxQEW@us.restbackup.com/'
    management_api = restbackup.ManagementApiCaller(management_api_access_url)
    """
    
    def create_backup_account(self, description, retain_uploads_days=365, delay_seconds=NEW_ACCOUNT_DELAY_SECONDS):
        """Adds a backup account, returns a BackupApiCaller object
        
        You can obtain the new backup account details from the returned object:
        b = management_api.create_backup_account('My Backup Account')
        print b.access_url, b.description, b.retain_uploads_days, b.account_id
        """
        response = self.post('/', {'description':description, 'retaindays':retain_uploads_days})
        response_body = response.read()
        obj = json.loads(response_body)
        time.sleep(delay_seconds)
        return BackupApiCaller(obj['access-url'], obj['retaindays'], obj['description'], obj['account'])
    
    def get_backup_account(self, account_id):
        """Looks up the backup account with the specified account id,
        returns a BackupApiCaller object
        
        You can obtain the backup account details from the returned object:
        b = management_api.get_backup_account('/171633a5-233f-4510-9098-bac142260013')
        print b.access_url, b.description, b.retain_uploads_days, b.account_id
        """
        response = self.call('GET', account_id)
        response_body = response.read()
        obj = json.loads(response_body)
        return BackupApiCaller(obj['access-url'], obj['retaindays'], obj['description'], obj['account'])
    
    def delete_backup_account(self, account_id):
        """Deletes the backup account with the specified account id"""
        response = self.call('DELETE', account_id)
        response.read()
    
    def list_backup_accounts(self):
        """Downloads the list of backup accounts, returns a list
        tuples of the form (account_id, retain_uploads_days,
        description)"""
        response = self.call('GET', '/')
        response_body = response.read()
        array = json.loads(response_body)
        return [(obj['account'],obj['retaindays'],obj['description']) for obj in array]
    
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
    def __init__(self, access_url, retain_uploads_days=None, description=None, account_id=None):
        self.access_url = access_url
        self.retain_uploads_days = retain_uploads_days
        self.description = description
        self.account_id = account_id
        HttpCaller.__init__(self, access_url)
    
    def put(self, name, data, size_bytes=None):
        """Uploads the provided data to the backup account, storing it with the specified name."""
        if size_bytes == None:
            size_bytes = len(data)
        response = self.call('PUT', name, data, {'Content-Length':str(size_bytes)})
        response.read()
    
    def get(self, name):
        """Retrieves the specified file.  Returns an httplib.HTTPResponse object."""
        return self.call('GET', name)
    
    def list(self):
        """Lists the files available on the backup account.  Returns a
        list of tuples of the form
        (name,size,date,createtime,deletetime)"""
        response = self.call('GET', '/', extra_headers={'Accept':'application/json'})
        response_body = response.read()
        array = json.loads(response_body)
        return [(obj['name'],obj['size'],obj['date'],obj['createtime'],obj['deletetime']) for obj in array]
    
    def __str__(self):
        return "backup api %r" % (self.access_url)
    
    def __repr__(self):
        return "BackupApiCaller(access_url=%r,retain_uploads_days=%r,description=%r,account_id=%r)" % (self.access_url,self.retain_uploads_days,self.description,self.account_id)

