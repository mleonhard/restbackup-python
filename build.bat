setup.py sdist --formats=gztar,zip
setup.py bdist --formats=msi,wininst
rm -rf build restbackup_python.egg-info
