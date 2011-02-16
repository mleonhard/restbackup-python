RestBackup(tm) Client Library
=============================


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