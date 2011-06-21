#!/usr/bin/env python
__author__ = 'Michael Leonhard'
__license__ = 'Copyright (C) 2011 Rest Backup LLC.  Use of this software is subject to the RestBackup.com Terms of Use, http://www.restbackup.com/terms'
__version__ = '1.0'

import datetime
import getopt
import os
import os.path
import re
import subprocess
import sys
import tempfile
import threading

import restbackup
import restbackupcli

DESCRIPTION="""Restbackup-tar is a command-line tool for performing incremental encrypted
backups to RestBackup(tm) and restoring from any point in time. Get your backup
account at http://www.restbackup.com/

Encryption is performed by the Chlorocrypt library.  It provides confidentiality
with AES in CBC mode with a random IV.  Keys are derived with PBKDF2 using
128-bit salts and 4096 rounds of HMAC-SHA-256.  Data is padded using the
standard PKCS#5 method.  HMAC-SHA-256 is used for authentication and file
integrity verificaiton.
"""

USAGE="""Usage: restbackup-tar [OPTIONS] COMMAND [args]

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
"""

EXAMPLE="""Restbackup-tar Example Usage

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
 2011-06-21T13:39:48Z	182	/data-20110621T133947Z-full.tar.gz
 2011-06-21T13:40:41Z	186	/data-20110621T133947Z-inc1.tar.gz
 2011-06-21T13:42:00Z	240	/data-20110621T133947Z-inc2.tar.gz
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
"""

DEFAULT_URL_FILE=os.path.join("~", ".restbackup-backup-api-access-url")
DEFAULT_SNAPSHOT_DIR=os.path.join("~",".restbackup-tar")
DEFAULT_SNAPSHOT_FILE=os.path.join(DEFAULT_SNAPSHOT_DIR, "%(NAME)s.snapshot")
DEFAULT_PASS_FILE=os.path.join("~", ".restbackup-file-encryption-passphrase")
DEFAULT_NAME="backup"

def cli_error(reason):
    print >>sys.stderr, str(reason)
    print >>sys.stderr, USAGE
    return 2

def main(args):
    # No arguments
    if not args:
        print DESCRIPTION
        print USAGE
        return 0
    
    # Parse arguments
    try:
        short_args = "u:b:n:s:ep:"
        long_args = ["full","incremental","list","restore","help","example"]
        opts, args = getopt.gnu_getopt(args, short_args, long_args)
    except getopt.GetoptError, e:
        return cli_error(e)
    
    command=None
    url=None
    name=DEFAULT_NAME
    snapshot_file=None
    encrypt=False
    passphrase=None
    
    for option, value in opts:
        if option == "--full":
            command = "full"
        elif option == "--incremental":
            command = "incremental"
        elif option == "--list":
            command = "list"
        elif option == "--restore":
            command = "restore"
        elif option == "--help":
            print DESCRIPTION
            print USAGE
            return 0
        elif option == "--example":
            print EXAMPLE
            return 0
        elif option == "-u":
            url=value
        elif option == "-b":
            url = restbackupcli.read_secret_from_file(value)
        elif option == "-n":
            name = value
        elif option == "-s":
            snapshot_file = value
        elif option == "-e":
            encrypt=True
        elif option == "-p":
            passphrase = restbackupcli.read_secret_from_file(value)
        else:
            assert False, "unhandled option %r" % ((option,value),)
    
    if encrypt and passphrase == None:
        passphrase = restbackupcli.read_secret_from_file(DEFAULT_PASS_FILE)
    if not encrypt:
        passphrase = None
    
    if url == None:
        url = restbackupcli.read_secret_from_file(DEFAULT_URL_FILE)
    
    if snapshot_file == None:
        snapshot_file = DEFAULT_SNAPSHOT_FILE % {"NAME" : name}
        snapshot_dir = os.path.expanduser(DEFAULT_SNAPSHOT_DIR)
        if not os.path.isdir(snapshot_dir):
            os.mkdir(snapshot_dir)
    snapshot_file = os.path.expanduser(snapshot_file)
    
    try:
        if command == None:
            return cli_error("ERROR: You must specify a command")
        elif command == "full":
            if not args:
                return cli_error("ERROR: No files specified")
            return backup(command, url, name, snapshot_file, passphrase, args)
        elif command == "incremental":
            if not args:
                return cli_error("ERROR: No files specified")
            return backup(command, url, name, snapshot_file, passphrase, args)
        elif command == "list":
            if args:
                return cli_error("ERROR: Unexpected arguments %r" % args)
            return list_files(url)
        elif command == "restore":
            if not args:
                return cli_error("ERROR: No archive specified")
            return restore(url, passphrase, args)
        else:
            assert False, "Unimplemented command %r" % command
    except restbackup.RestBackupException, e:
        print >>sys.stdout, "ERROR: %s" % str(e)
        return 1

def list_files(access_url):
    backup_api = restbackup.BackupApiCaller(access_url)
    for (name,size,date,createtime,deletetime) in backup_api.list():
        print "%s\t%s\t%s" % (date, size, name)
    return 0

def backup(command, url, name, snapshot_file, passphrase, files):
    backup_api = restbackup.BackupApiCaller(url)
    backup_name_file = snapshot_file + ".backupname"
    last_backup_level_file = snapshot_file + ".lastbackuplevel"
    
    if command == "full":
        timestamp = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        backup_name = "%s-%s" % (name, timestamp)
        with open(backup_name_file, "w") as f:
            f.write(backup_name)
        
        level = 0
        
        archive_name = backup_name + "-full.tar.gz"
        print "Performing full backup to %r" % archive_name
        
        if os.path.exists(snapshot_file):
            os.unlink(snapshot_file)
    elif command == "incremental":
        if not os.path.exists(backup_name_file):
            print >>sys.stderr, \
                "ERROR: Cannot find file %r." % backup_name_file, \
                "Have you already performed a full backup?"
            return 1
        with open(backup_name_file, "r") as f:
            backup_name = f.read()
        
        if not os.path.exists(last_backup_level_file):
            print >>sys.stderr, \
                "ERROR: Cannot find file %r." % last_backup_level_file, \
                "Have you already performed a full backup?"
            return 1
        with open(last_backup_level_file, "r") as f:
            last_backup_level = int(f.read().strip())
        level = last_backup_level + 1
        
        archive_name = "%s-inc%s.tar.gz" % (backup_name, level)
        print "Performing incremental backup to %r" % archive_name
    else:
        assert False, "Unimplemented command %r" % command
    
    with tempfile.TemporaryFile(prefix='restbackup-tar.') as f:
        # http://www.gnu.org/software/automake/manual/tar/Incremental-Dumps.html
        print "Writing archive to temporary file"
        args = ["tar","-czg", snapshot_file] + files
        tar = subprocess.Popen(args, stdout=f.fileno())
        tar.wait()
        if tar.returncode != 0:
            return 1
        
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(0)
        reader = restbackup.FileObjectReader(f, size)
        
        remote_file_name = "/" + archive_name
        endpoint = "%s://%s/" % (backup_api.scheme, backup_api.host)
        print "Uploading %s byte archive to %s%s" % (size,endpoint,archive_name)
        if passphrase == None:
            backup_api.put(name=remote_file_name, data=reader)
        else:
            backup_api.put_encrypted(passphrase, name=remote_file_name,
                                     data=reader)
    
    with open(last_backup_level_file, "w") as level_file:
        level_file.write(str(level))
    print "Done."
    return 0

def restore(access_url, passphrase, args):
    backup_api = restbackup.BackupApiCaller(access_url)
    endpoint = "%s://%s" % (backup_api.scheme, backup_api.host)
    archive_name = args[0]
    files = args[1:]
    
    max_level = 99
    level_specified = False
    if re.match(r"^.*-full(\.tar\.gz)?$", archive_name):
        max_level = 0
        level_specified = True
    else:
        m = re.match(r"^.*-inc([0-9]+)(\.tar\.gz)?$", archive_name)
        if m:
            max_level = int(m.group(1))
            level_specified = True
    
    backup_name = re.match(r"/?(.*?)(-full|-inc[0-9]+)*(\.tar\.gz)*$",
                           archive_name).group(1)
    restore_dir = backup_name.replace("/", "#")
    print "Restoring to %r" % (restore_dir + "/")
    if not os.path.isdir(restore_dir):
        os.mkdir(restore_dir)
    
    remote_files = ["/%s-full.tar.gz" % backup_name]
    for n in range(1, max_level + 1):
        remote_files.append("/%s-inc%s.tar.gz" % (backup_name, n))
    
    first = True
    for remote_file in remote_files:
        print "Retrieving %s%s" % (endpoint, remote_file)
        try:
            if passphrase == None:
                reader = backup_api.get(name=remote_file)
            else:
                reader = backup_api.get_encrypted(passphrase, name=remote_file)
            first = False
        except restbackup.RestBackupException, e:
            if str(e).startswith("404") and not level_specified and not first:
                print "Not found"
                break
            else:
                raise
        
        sys.stdout.flush()
        sys.stderr.flush()
        args = ["tar","-xzvGC", restore_dir] + files
        tar = subprocess.Popen(args, stdin=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        
        flag = {'value':False}
        stderr_reader = threading.Thread(target=stderr_filter,
                                         args=(tar.stderr,flag))
        stderr_reader.daemon = True
        stderr_reader.start()
        
        while True:
            chunk = reader.read(65536)
            if not chunk:
                break
            tar.stdin.write(chunk)
        
        tar.stdin.flush()
        tar.stdin.close()
        tar.wait()
        stderr_reader.join()
        if tar.returncode != 0:
            if files and not flag['value']:
                # When restoring specific files from a set of
                # incremental backups, ignore "not found in archive"
                # and process all requested archives, since desired
                # files may not appear in every archive
                print "Ignoring tar errors"
            else:
                return 1
    
    print "Done."
    return 0

def stderr_filter(stderr, flag):
    """Reads stderr pipe and sets flag if tar or its child emits an unexpected
    error message"""
    for line in stderr:
        if "Exiting with failure status due to previous errors" in line:
            continue
        sys.stderr.write(line)
        sys.stderr.flush()
        if line and not "Not found in archive" in line:
            flag['value'] = True

def entry_point():
    sys.exit(main(sys.argv[1:]))

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
