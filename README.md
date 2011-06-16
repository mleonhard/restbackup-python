RestBackup(tm) Client Library and CLI
=====================================


This module provides convenient classes for making calls to the
RestBackup(tm) Backup and Management APIs.  These APIs are documented
at [http://www.restbackup.com/developers](http://www.restbackup.com/developers).
It also provides the restbackup-cli tool for interacting with the service.

Client library example usage:

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
        chunk = reader.read(65536)
        if not chunk:
            break
        local_file.write(chunk)

CLI Help:

    Usage: restbackupcli.py [OPTIONS] COMMAND [args]
    
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
      list-backup-accounts
    
    Options:
      -b BACKUP_URL_FILE  file with backup api access url, default
                          ~\.restbackup-backup-api-access-url
      -m MAN_URL_FILE     file with management api access url, default
                          ~\.restbackup-management-api-access-url
      -u ACCESS_URL       access url, ignores -b and -m arguments
      -f                  allow overwrite of local file
      -p PASSPHRASE_FILE  file with encryption passphrase, default
                          ~\.restbackup-file-encryption-passphrase
      -h, --help          show the help message and usage examples
    
    Encryption is performed by the Chlorocrypt library.  Uses AES in CBC mode for
    confidentiality.  Derives keys from passphrase using 128-bit salt and PBKDF2
    with 4096 rounds of HMAC-SHA-256.  Uses PKCS#5 padding.  Verifies file
    integrity with SHA-256 HMACs.
    
    Examples:
      restbackupcli.py put backup-20110615.tar.gz
      restbackupcli.py get /backup-20110615.tar.gz ~/restored/backup-20110615.tar.gz
