from distutils.core import setup
setup(
    name='restbackup',
    version='1.1',
    license = 'Copyright (C) 2011 Rest Backup LLC.  Use of this software is subject to the RestBackup.com Terms of Use, http://www.restbackup.com/terms',
    description = 'RestBackup(tm) Client Library',
    long_description = __doc__,
    author = 'Michael Leonhard',
    author_email = 'mike@restbackup.com',
    platforms = 'any',
    py_modules=['pyaes', 'chlorocrypt', 'restbackup'],
    classifiers = [
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: System',
        'Topic :: System :: Archiving',
        'Topic :: System :: Archiving :: Backup',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
