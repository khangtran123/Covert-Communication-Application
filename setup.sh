cd ~/Documents/
wget https://bitbucket.org/squeaky/portable-pypy/downloads/pypy-6.0.0-linux_x86_64-portable.tar.bz2
chmod 755 pypy-6.0.0-linux_x86_64-portable.tar.bz2
tar xvjf pypy-6.0.0-linux_x86_64-portable.tar.bz2
cd pypy-6.0.0-linux_x86_64-portable/bin/
./pypy -m ensurepip
./pip install scapy
./pip install watchdog
ln -s -T ~/Documents/pypy-6.0.0-linux_x86_64-portable/bin/pypy  ~/Documents/py
#wget THE SPOOF FILE
