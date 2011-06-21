#!/usr/bin/env python
__author__ = 'Michael Leonhard'
__license__ = 'Copyright (C) 2011 Rest Backup LLC.  Use of this software is subject to the RestBackup.com Terms of Use, http://www.restbackup.com/terms'
__version__ = '1.0'

import optparse
import os.path
import sys

import restbackup

USAGE="""restbackup-cli [OPTIONS] COMMAND [args]

Backup API Commands:
  put LOCAL_FILE [REMOTE_FILE]   Upload LOCAL_FILE and store as REMOTE_FILE
  get REMOTE_FILE [LOCAL_FILE]   Download REMOTE_FILE and save as LOCAL_FILE
  list                           List uploaded files
  encrypt-and-put LOCAL [REMOTE] Encrypt LOCAL file and upload as REMOTE
  get-and-decrypt REMOTE [LOCAL] Download REMOTE, decrypt, and save as LOCAL
  make-random-passphrase         Generate a random 35-bit passphrase

Management API Commands:
  create-backup-account DESCRIPTION RETAIN_UPLOADS_DAYS
  get-backup-account ACCOUNT_ID
  delete-backup-account ACCOUNT_ID
  list-backup-accounts"""

EXAMPLES="""
Encryption is performed by the Chlorocrypt library.  Uses AES in CBC mode for
confidentiality.  Derives keys from passphrase using 128-bit salt and PBKDF2
with 4096 rounds of HMAC-SHA-256.  Uses PKCS#5 padding.  Verifies file
integrity with SHA-256 HMACs.

Examples:
  %(prog)s put backup-20110615.tar.gz
  %(prog)s get /backup-20110615.tar.gz ~/restored/backup-20110615.tar.gz"""

DEFAULT_BACKUP_URL_FILE=os.path.join("~", ".restbackup-backup-api-access-url")
DEFAULT_MAN_URL_FILE=os.path.join("~", ".restbackup-management-api-access-url")
DEFAULT_PASS_FILE=os.path.join("~", ".restbackup-file-encryption-passphrase")

def main(args):
    parser = optparse.OptionParser(usage=USAGE, add_help_option=False)
    parser.set_defaults(backup_url_file=DEFAULT_BACKUP_URL_FILE,
                        man_url_file=DEFAULT_MAN_URL_FILE,
                        passphrase_file=DEFAULT_PASS_FILE,
                        access_url=None)
    parser.add_option("-b", action="store", type="string",
                      dest="backup_url_file",
                      help="file with backup api access url, default   %s" \
                          % DEFAULT_BACKUP_URL_FILE)
    parser.add_option("-m", action="store", type="string", dest="man_url_file",
                      help="file with management api access url, default %s" \
                          % DEFAULT_MAN_URL_FILE)
    parser.add_option("-u", action="store", type="string", dest="access_url",
                      help="access url, ignores -b and -m arguments")
    parser.add_option("-f", action="store_true", dest="force", 
                      help="allow overwrite of local file")
    parser.add_option("-p", action="store", type="string",
                      dest="passphrase_file",
                      help="file with encryption passphrase, default   %s" \
                          % DEFAULT_PASS_FILE)
    parser.add_option("-h", "--help", action="store_true", dest="help", 
                      help="show the help message and usage examples")
    (options, args) = parser.parse_args()
    
    if options.help or not args:
        parser.print_help()
        print >>sys.stdout, EXAMPLES % {'prog' : os.path.basename(sys.argv[0])}
        return 1
    
    try:
        command = args[0]
        params = args[1:]
        access_url = options.access_url
        if command == "make-random-passphrase" and not params:
            return make_random_passphrase()
        elif command in ["put", "encrypt-and-put", "get", "get-and-decrypt",
                         "list", "make-random-passphrase"]:
            if access_url == None:
                access_url = read_secret_from_file(options.backup_url_file)
            if command == "put" and len(params) in (1,2):
                return put_file(access_url, None, *params)
            if command == "encrypt-and-put" and len(params) in (1,2):
                passphrase = read_secret_from_file(options.passphrase_file)
                return put_file(access_url, passphrase, *params)
            elif command == "get" and len(params) in (1,2):
                return get_file(access_url, None, options.force, *params)
            elif command == "get-and-decrypt" and len(params) in (1,2):
                passphrase = read_secret_from_file(options.passphrase_file)
                return get_file(access_url, passphrase, options.force, *params)
            elif command == "list" and not params:
                return list_files(access_url)
            else:
                parser.error("Incorrect number of arguments for %r command" \
                                 % command)
        elif command in ["create-backup-account", "get-backup-account", 
                         "delete-backup-account", "list-backup-accounts"]:
            if access_url == None:
                access_url = read_secret_from_file(options.man_url_file)
            if command == "create-backup-account" and len(params) == 2:
                return create_backup_account(access_url, params[0], params[1])
            elif command == "get-backup-account" and len(params) == 1:
                return get_backup_account(access_url, params[0])
            elif command == "delete-backup-account" and len(params) == 1:
                return delete_backup_account(access_url, params[0])
            elif command == "list-backup-accounts" and not params:
                return list_backup_accounts(access_url)
            else:
                parser.error("Incorrect number of arguments for %r command" 
                             % command)
        else:
            parser.error("Unknown command %r" % command)
    except restbackup.RestBackupException, e:
        if str(e).startswith("405"):
            print >>sys.stdout, "ERROR: %s (Cannot overwrite existing file)" \
                % str(e)
            return -1
        else:
            print >>sys.stdout, "ERROR: %s" % str(e)

def make_random_passphrase():
    """Make three random passwords, each with 35 bits of entropy"""
    import random
    prng = random.SystemRandom()
    templates = ['aababbab', 'aabbabab', 'aabbabba', 'abaabbab', 'abababab',
                 'abababba', 'ababbaab', 'ababbaba', 'abbaabab', 'abbaabba',
                 'abbabaab', 'abbababa', 'abbabbaa', 'baababab', 'baababba',
                 'baabbaab', 'baabbaba', 'babaabab', 'babaabba', 'bababaab',
                 'babababa', 'bababbaa', 'babbaaba', 'babbabaa']
    alphabet = {'a':"aeiou", 'b':list("bcdfghjklmnprsvwxyz") + ["ch","ph","st"]}
    for n in (1,2,3):
        template = prng.choice(templates)
        password = "".join([prng.choice(alphabet[c]) for c in template])
        print password.capitalize() + prng.choice("0123456789"),
    return 0

def read_secret_from_file(filename):
    with open(os.path.expanduser(filename), "rb") as f:
        return f.read().strip()

def put_file(access_url, passphrase, local_file_name, remote_file_name=None):
    backup_api = restbackup.BackupApiCaller(access_url)
    reader = restbackup.FileReader(local_file_name)
    if remote_file_name == None:
        remote_file_name = os.path.basename(local_file_name)
    if not remote_file_name.startswith('/'):
        remote_file_name = '/' + remote_file_name
    try:
        if passphrase == None:
            backup_api.put(name=remote_file_name, data=reader)
        else:
            backup_api.put_encrypted(passphrase, name=remote_file_name,
                                     data=reader)
        return 0
    except restbackup.RestBackupException, e:
        if str(e).startswith("405"):
            print >>sys.stdout, "ERROR: %s (Cannot overwrite existing file)" \
                % str(e)
            return -1
        raise

def get_file(access_url, passphrase, force, remote_file_name,
             local_file_name=None):
    backup_api = restbackup.BackupApiCaller(access_url)
    if not remote_file_name.startswith('/'):
        remote_file_name = '/' + remote_file_name
    if local_file_name == None:
        local_file_name = remote_file_name.split("/")[-1]
    if os.path.exists(local_file_name) and not force:
        print >>sys.stderr, "Refusing to overwrite file %r" % local_file_name
        return -1
    if passphrase == None:
        reader = backup_api.get(name=remote_file_name)
    else:
        reader = backup_api.get_encrypted(passphrase, name=remote_file_name)
    with open(local_file_name, "wb") as local_file:
        while True:
            chunk = reader.read(65536)
            if not chunk:
                break
            local_file.write(chunk)
    return 0

def list_files(access_url):
    backup_api = restbackup.BackupApiCaller(access_url)
    for (name,size,date,createtime,deletetime) in backup_api.list():
        print date, size, name
    return 0

def create_backup_account(access_url, description, retain_uploads_days):
    try:
        man_api = restbackup.ManagementApiCaller(access_url)
        b = man_api.create_backup_account(description, retain_uploads_days)
        print "account_id retain_uploads_days access_url description"
        print b.account_id, b.retain_uploads_days, b.access_url, b.description
        return 0
    except restbackup.RestBackupException, e:
        if str(e).startswith("405"):
            print >>sys.stdout, "ERROR: %s (Wrong access url type) Check " \
                "that you are specifying a Management API Access URL, not a" \
                "Backup API Access URL.)" % str(e)
            return -1
        raise

def get_backup_account(access_url, account_id):
    man_api = restbackup.ManagementApiCaller(access_url)
    b = man_api.get_backup_account(account_id)
    print "account_id retain_uploads_days access_url description"
    print b.account_id, b.retain_uploads_days, b.access_url, b.description
    return 0

def delete_backup_account(access_url, account_id):
    man_api = restbackup.ManagementApiCaller(access_url)
    b = man_api.delete_backup_account(account_id)
    print "Deleted", account_id
    return 0

def list_backup_accounts(access_url):
    man_api = restbackup.ManagementApiCaller(access_url)
    accounts = man_api.list_backup_accounts()
    print "account_id retain_uploads_days description"
    for (account_id, retain_uploads_days, description) in accounts:
        print account_id, retain_uploads_days, description
    return 0

def entry_point():
    sys.exit(main(sys.argv[1:]))

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
