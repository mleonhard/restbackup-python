RestBackup(tm) Client Library and Command-Line Tools
====================================================

This package provides:

1. Client library for making calls to the RestBackup(tm) Backup API

1. Restbackup-cli tool for using the service from the command-line

1. Restbackup-tar tool for performing incremental encrypted backups to
RestBackup(tm) and restoring from any point in time

1. Chlorocrypt module and command-line tool for performing
industry-standard encryption of your backups

Installation
============

Unix & Mac:

1. Install Python 2.7
1. Install the python-setuptools and python-crypto packages
1. Download the tar.gz file, extract it, and install with
    
        sudo python setup.py install --single-version-externally-managed --root=/

1. Test the restbackup and chlorocrypt libraries
    
        python -m test-restbackup
        python -m test-chlorocrypt

Windows:

1. Install [Python 2.7](http://www.python.org/download/)
1. Install [PyCrypto for Windows](http://www.voidspace.org.uk/python/modules.shtml#pycrypto)
1. Install restbackup-python EXE or MSI from [Downloads](downloads/)
1. Add C:\Python27\Scripts\ to your PATH


Client Library
==============

The restbackup.py module provides convenient classes for making calls
to the RestBackup(tm) Backup API.  These API is documented at
[http://www.restbackup.com/api](http://www.restbackup.com/api).

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


Restbackup-CLI
==============

The restbackup-cli program lets you interact with the Backup API from
the command line.  It can also encrypt your backup archives using the
Chlorocrypt library.

CLI Help:

    Usage: restbackup-cli [OPTIONS] COMMAND [args]
    
    Commands:
      put LOCAL_FILE [REMOTE_FILE]   Upload LOCAL_FILE and store as REMOTE_FILE
      get REMOTE_FILE [LOCAL_FILE]   Download REMOTE_FILE and save as LOCAL_FILE
      list                           List uploaded files
      encrypt-and-put LOCAL [REMOTE] Encrypt LOCAL file and upload as REMOTE
      get-and-decrypt REMOTE [LOCAL] Download REMOTE, decrypt, and save as LOCAL
      make-random-passphrase         Generate a random 35-bit passphrase
    
    Options:
      -b BACKUP_URL_FILE  file with backup api access url, default
                          ~\.restbackup-backup-api-access-url
      -u ACCESS_URL       access url, ignores -b and -m arguments
      -f                  allow overwrite of local file
      -p PASSPHRASE_FILE  file with encryption passphrase, default
                          ~\.restbackup-file-encryption-passphrase
      -h, --help          show the help message and usage examples
    
    Encryption is performed by the Chlorocrypt library.  Uses AES in CBC mode for
    confidentiality.  Derives keys from passphrase using 128-bit salt and PBKDF2
    with 4096 rounds of HMAC-SHA-256.  Uses PKCS#5 padding.  Verifies file
    integrity with SHA-256 HMACs.
    
    For faster operation, install the PyCrypto library:
    http://www.dlitz.net/software/pycrypto/
    http://www.voidspace.org.uk/python/modules.shtml#pycrypto
    
    Examples:
      restbackupcli.py put data-20110615.tar.gz
      restbackupcli.py get /data-20110615.tar.gz ~/restored/data-20110615.tar.gz
      restbackupcli.py list
    
      restbackupcli.py make-random-passphrase >~/.restbackup-file-encryption-passphrase
      cat ~/.restbackup-file-encryption-passphrase
      (Write down the passphrase and keep a copy off-site!)
      restbackupcli.py encrypt-and-put data-20110615.tgz
      restbackupcli.py get-and-decrypt /data-20110615.tgz ~/restored-data-20110615.tgz


Restbackup-tar Incremental Backup Tool
======================================

Restbackup-tar is a command-line tool for performing incremental encrypted
backups to RestBackup(tm) and restoring from any point in time. Get your backup
account at http://www.restbackup.com/

Encryption is performed by the Chlorocrypt library.  It provides confidentiality
with AES in CBC mode with a random IV.  Keys are derived with PBKDF2 using
128-bit salts and 4096 rounds of HMAC-SHA-256.  Data is padded using the
standard PKCS#5 method.  HMAC-SHA-256 is used for authentication and file
integrity verification.

This tool works on Linux and Mac.  Windows is not supported at this time.

    Usage: restbackup-tar [OPTIONS] COMMAND [args]
    
    Commands:
     --full FILE1 FILE2 ...        Perform a full backup
     --incremental FILE1 ...       Perform an incremental backup
     --list                        List backup archives
     --restore ARCHIVE [FILE1 ...] Restore files from archive
     --help                        Show this message
     --example                     Show example usage
    
    Options:
     -u ACCESS_URL       a RestBackup(tm) backup account access url such as
                         https://Z2J3BB:R0GaTKS0vM3l3FgY@us.restbackup.com/
     -b ACCESS_URL_FILE  file with backup account access url, default
                         ~/.restbackup-backup-api-access-url
     -n NAME             name for the set of backups, eg. leonhard-email, git-repos.
                         Default: backup
     -s SNAPSHOT_FILE    Tar incremental snapshot file, default
                         ~/.restbackup-tar/NAME.snapshot
     -e                  Encrypt archives before upload and decrypt on download
     -p PASSPHRASE_FILE  file with encryption passphrase, default
                         ~/.restbackup-file-encryption-passphrase
                         Generate one with "restbackup-cli make-random-passphrase"

Setup:

    $ echo https://WPJXX3:INzIsdEE77vZgih7@us.restbackup.com/ >~/.restbackup-backup-api-access-url
    $ chmod 600 ~/.restbackup-backup-api-access-url
    $ mkdir data
    $ echo "initial data" >data/file1

Full Backup:

    $ restbackup-tar -n data -s data.snapshot --full data/
    Performing full backup to 'data-20110621T133947Z-full.tar.gz'
    Writing archive to temporary file
    Uploading 182 byte archive to https://us.restbackup.com/data-20110621T133947Z-full.tar.gz
    Done.

Incremental Backups:

    $ echo "new data" >data/file2
    $ restbackup-tar -n data -s data.snapshot --incremental data/
    Performing incremental backup to 'data-20110621T133947Z-inc1.tar.gz'
    Writing archive to temporary file
    Uploading 186 byte archive to https://us.restbackup.com/data-20110621T133947Z-inc1.tar.gz
    Done.
    $ echo "a modification" >>data/file1
    $ rm -f data/file2
    $ echo "more new data" >data/file3
    $ restbackup-tar -n data -s data.snapshot --incremental data/
    ...

Restore:

    $ restbackup-tar --list
    2011-06-21T13:39:48Z    182     /data-20110621T133947Z-full.tar.gz
    2011-06-21T13:40:41Z    186     /data-20110621T133947Z-inc1.tar.gz
    2011-06-21T13:42:00Z    240     /data-20110621T133947Z-inc2.tar.gz
    $ restbackup-tar --restore data-20110621T133947Z
    Restoring to 'data-20110621T133947Z/'
    Retrieving https://us.restbackup.com/data-20110621T133947Z-full.tar.gz
    data/
    data/file1
    Retrieving https://us.restbackup.com/data-20110621T133947Z-inc1.tar.gz
    data/
    data/file2
    Retrieving https://us.restbackup.com/data-20110621T133947Z-inc2.tar.gz
    data/
    tar: Deleting `data/file2'
    data/file1
    data/file3
    Retrieving https://us.restbackup.com/data-20110621T133947Z-inc3.tar.gz
    Not found
    Done.
    $ ls data-20110621T133947Z/data/
    file1  file3
    $ cat data-20110621T133947Z/data/file1
    initial data
    a modification


Chlorocrypt Encryption Library and Tool
=======================================

Chlorocrypt is a library and command-line tool for performing
industry-standard encryption of your backups.  The chlorocrypt program
can encrypt, verify, and decrypt files from the command line.  The
chlorocrypt.py module provides classes which perform streaming
encryption, verification, and decryption.

Chlorocrypt provides confidentiality with AES in CBC mode with a
random IV.  Keys are derived with PBKDF2 using 128-bit salts and 4096
rounds of HMAC-SHA-256.  Data is padded using the standard PKCS#5
algorithm.  HMAC-SHA-256 is used for authentication and file integrity
verificaiton.

Chlorocrypt Usage:

    Usage: chlorocrypt -e|-d [INFILE [OUTFILE [PASSPHRASEFILE]]]

Library Usage:

    def encrypt(passphrase, input, output):
        encrypted = chlorocrypt.EncryptingReader(input, passphrase)
        while True:
            chunk = encrypted.read(65536)
            if not chunk:
                break
            output.write(chunk)
        return 0
    
    def decrypt(passphrase, input, output):
        decrypted = chlorocrypt.DecryptingReader(input, passphrase)
        while True:
            chunk = decrypted.read(65536)
            if not chunk:
                break
            output.write(chunk)
        return 0

    def encrypt_and_backup(access_url, passphrase, filename):
        backup_api = restbackup.BackupApiCaller(access_url)
        reader = restbackup.FileReader(filename)
        backup_api.put_encrypted(passphrase, '/' + filename, reader)
    
    def restore_and_decrypt(access_url, passphrase, filename):
        backup_api = restbackup.BackupApiCaller(access_url)
        reader = backup_api.get_encrypted(passphrase, '/' + filename)
        with open(filename, 'wb') as local_file:
            while True:
                chunk = reader.read(65536)
                if not chunk:
                    break
                local_file.write(chunk)
