from setuptools import setup, find_packages
setup(
    name='restbackup-python',
    version='1.2',
    packages = find_packages(),
    description = 'RestBackup(tm) Client Library and Command Line Interface',
    url = 'https://github.com/mleonhard/restbackup-python',
    keywords = 'restbackup backup encryption client',
    author = 'Michael Leonhard',
    author_email = 'mike@restbackup.com',
    license = 'Copyright (C) 2011 Rest Backup LLC.  Use of this software is subject to the RestBackup.com Terms of Use, http://www.restbackup.com/terms',
    platforms = 'any',
    py_modules=['pyaes', 'chlorocrypt', 'restbackup', 'restbackupcli'],
    entry_points = {
        'console_scripts': ['restbackup-cli = restbackupcli:entry_point'],
        'gui_scripts': []
    },
    install_requires = ['pycrypto>=2.1.0'],
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
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
