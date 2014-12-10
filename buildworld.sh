#!/bin/sh

#GLOBALS
oinkcode=""				#Enter in oinkcode to use ETPRO
user="cuckoo"				#Needs to be cuckoo for now
sniff_sub="192.168.56.0/24"		#Subnet that suricata should treat as internal
sniff_net="vboxnet0"			#Network that your vm traffic is going over
out_int="eth0"				#Outbound interface of VM Host

### Moloch Config Variables ###
es_mem="10G"                                    # How much memory should elasticsearch for moloch have? (< 32GB)
moloch_password="OmG_3t_Rul3z!1!"               # Password for Moloch
moloch_fqdn="etcuckoo.localhost"                # FQDN for Moloch Cert
moloch_country="US"                       # Country for Moloch Cert
moloch_state="WIN"                              # State for Moloch Cert
moloch_orgname="ETcuckoo"                          # Org Name for Moloch Cert
moloch_orgunit="ETcuckoo"             # Org unit for Moloch Cert
moloch_locality="EARTH"                         # Locality for Moloch Cert

#check for cuckoo user
if [ `whoami` != $user ]; then
 echo "Please create and run this script as the user 'cuckoo'."
 exit 0
fi

#setup oinkcode
if ["$oinkcode" = ""]; then
 rule_url="https://rules.emergingthreatspro.com/|emerging.rules.tar.gz|open"
else
 rule_url="https://rules.emergingthreatspro.com/|etpro.rules.tar.gz|$oinkcode"
fi

#Update Ubuntu
sudo apt-get update -y && sudo apt-get upgrade -y

#Deps
sudo apt-get install -y vim screen unzip python python-dpkt python-jinja2 python-magic python-pymongo python-gridfs python-libvirt python-bottle python-chardet tcpdump clamav-daemon clamav-unofficial-sigs clamav clamav-base libcap2-bin python-dev build-essential subversion pcregrep libpcre++-dev python-pip ssdeep libfuzzy-dev git automake libtool autoconf libapr1 libapr1-dev libnspr4-dev libnss3-dev libwww-Perl libcrypt-ssleay-perl python-dev python-scapy python-yaml bison libpcre3-dev bison flex libdumbnet-dev autotools-dev libnet1-dev libpcap-dev libyaml-dev libnetfilter-queue-dev libprelude-dev zlib1g-dev libz-dev libcap-ng-dev libmagic-dev python-mysqldb lua-zip-dev lua-zip luarocks cmake libjansson-dev libswitch-perl libcdio-utils mongodb-server python-simplejson p7zip-full 

#Setup tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

#Pip install deps
sudo pip install bottle django==1.6.7 pycrypto clamd

#Install PEfile 
#src:https://pefile.googlecode.com/files/pefile-1.2.10-139.tar.gz
tar -xzvf pefile-1.2.10-139.tar.gz
cd pefile-1.2.10-139
python setup.py build
sudo python setup.py install

#Install Distrom3 
#src:https://distorm.googlecode.com/files/distorm3.zip
unzip distorm3.zip
cd distorm3
python setup.py build
sudo python setup.py install
cd ..

#Install Yara 2.1.0 
#src:https://github.com/plusvic/yara/archive/2.1.0.tar.gz
tar -zxf v3.1.0.tar.gz
cd yara-3.1.0
./bootstrap.sh
chmod +x build.sh
./build.sh
sudo make install

echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/cuckoo
sudo ldconfig
cd yara-python
python setup.py build
sudo python setup.py install
cd ../..

#wget http://volatility.googlecode.com/files/volatility-2.3.1.tar.gz
tar -zxf volatility-2.4.tar.gz
cd volatility-2.4
python setup.py build
sudo python setup.py install
cd ..

git clone https://github.com/kbandla/pydeep.git
cd pydeep
python setup.py build
sudo python setup.py install
cd ..

sudo mkdir -p /usr/local/suricata/bin
sudo mkdir -p /usr/local/suricata/lib
sudo mkdir -p /usr/local/suricata/lib
sudo mkdir -p /usr/local/suricata/include/linux
sudo mkdir -p /usr/local/suricata/sbin
sudo mkdir -p /usr/local/suricata/etc/
sudo mkdir -p /usr/local/suricata/etc/
sudo mkidr -p /usr/local/suricata/et-luajit-scripts/
sudo mkdir -p /usr/local/suricata/var/log
sudo mkdir -p /usr/local/suricata/var/run/suricata/
sudo mkdir -p /data/etc/
sudo apt-get install build-essential libapr1 libapr1-dev libnspr4-dev libnss3-dev libwww-Perl libcrypt-ssleay-perl python-dev python-scapy python-yaml bison libpcre3-dev bison flex libdumbnet-dev autotools-dev libnet1-dev libpcap-dev libyaml-dev libnetfilter-queue-dev libprelude-dev zlib1g-dev  libz-dev libcap-ng-dev libmagic-dev python-mysqldb lua-zip-dev luarocks cmake openvswitch-switch libaprutil1-dev libaprutil1-dbd-sqlite3 libapreq2-3 libapreq2-dev liblua5.1-0 liblua5.1-0-dev libapr1 libaprutil1 libaprutil1-dev libaprutil1-dbd-sqlite3 libapreq2-3 libapreq2-dev xrdp python-sqlalchemy -y 

#wget ftp://ftp.csx.cam.ac.uk/pub/software/programming/pcre/pcre-8.35.tar.gz
tar -xzvf pcre-8.35.tar.gz
cd pcre-8.35
./configure --prefix=/usr/local/pcre-8.35/ --enable-jit --enable-utf8 --enable-unicode-properties
make -j && sudo make install
cd ..

#wget http://luajit.org/download/LuaJIT-2.0.3.tar.gz
tar -xzvf LuaJIT-2.0.3.tar.gz
cd LuaJIT-2.0.3
make -j
sudo make install
cd ..
sudo ldconfig
echo "/usr/local/luajit20/lib/" | sudo tee /etc/ld.so.conf.d/suricata.conf
echo "/usr/local/pce-8.35/lib/" | sudo tee -a /etc/ld.so.conf.d/suricata.conf

sudo ldconfig

sudo luarocks install struct
sudo luarocks install lua-apr

mkdir lua-zlib
cd lua-zlib
git clone https://github.com/brimworks/lua-zlib.git
cmake lua-zlib
sudo make install
cd ..

git clone https://github.com/mkottman/ltn12ce
cd ltn12ce
mkdir build
cd build
cmake .. -DBUILD_ZLIB=Off
make
sudo make install
cd ../..

sudo ln -s /usr/lib/x86_64-linux-gnu/lua/5.1/zip.so /usr/local/lib/lua/5.1/zip.so
sudo ln -s /usr/local/lib/lua/apr /usr/local/lib/lua/5.1/apr
sudo ln -s /usr/local/lib/lua/ltn12ce /usr/local/lib/lua/5.1/ltn12ce 
sudo ln -s /usr/local/share/lua/cmod/zlib.so /usr/local/lib/lua/5.1/zlib.so

#wget http://www.openinfosecfoundation.org/download/suricata-2.0.4.tar.gz
tar -xzvf suricata-2.0.4.tar.gz
cd suricata-2.0.4
./configure LD_RUN_PATH="/usr/local/pcre-8.35/lib:/usr/local/luajit20/lib/:/usr/local/lib/:/usr/lib:/usr/local/lib" --enable-pcre-jit --with-libpcre-libraries=/usr/local/pcre-8.35/lib/ --with-libpcre-includes=/usr/local/pcre-8.35/include/ --enable-profiling --prefix=/usr/local/suricata/ --with-libnss-includes=/usr/include/nss --with-libnss-libs=/usr/lib/nss --with-libnspr-includes=/usr/include/nspr --with-libnspr-libraries=/usr/lib/nspr --enable-luajit --with-libluajit-includes=/usr/local/include/luajit-2.0/ --with-libluajit-libraries=/usr/local/lib/ --enable-unix-socket && make -j && sudo make install
sudo cp ../suricata.yaml /usr/local/suricata/etc/
sudo cp reference.config /usr/local/suricata/etc/
sudo cp classification.config /usr/local/suricata/etc/
echo "alert http any any -> any any (msg:\"FILE store all\"; filestore; flowbits:noalert; sid:44444; rev:1;)" > local.rules
sudo cp local.rules /usr/local/suricata/etc/
#cp rules/files.rules /usr/local/suricata/etc/etpro/
cd ..

sudo git clone https://github.com/EmergingThreats/et-luajit-scripts /usr/local/suricata/et-luajit-scripts
sudo cp /usr/local/suricata/et-luajit-scripts/* /usr/local/suricata/etc/

echo "rule_url=$rule_url
ignore=local.rules
temp_path=/tmp
rule_path=/usr/local/suricata/etc/all.rules
sid_msg=/usr/local/suricata/etc/sid-msg.map
sid_changelog=/usr/local/suricata/var/log/etpro_sid_changes.log
disablesid=/usr/local/suricata/etc/disablesid.conf
engine=suricata
suricata_version=2.0.4
version=0.6.0
" > pp.config

#wget https://pulledpork.googlecode.com/files/pulledpork-0.6.1.tar.gz
tar -xzvf pulledpork-0.6.1.tar.gz
cd pulledpork-0.6.1
patch -p1 < ../pulledpork-etpro-fix.diff
sudo cp -f pulledpork.pl /usr/local/bin/
echo "#!/bin/sh
/usr/local/bin/pulledpork.pl -c /usr/local/suricata/etc/pp.config
cd /usr/local/suricata/et-luajit-scripts/ && git pull
" > ruleupdates.sh
chmod +x ruleupdates.sh
echo "pcre:SURICATA (STMP|IP|TCP|ICMP|HTTP|STREAM)" >> etc/disablesid.conf 
sudo cp ruleupdates.sh /usr/local/bin/
sudo cp ../pp.config /usr/local/suricata/etc/
sudo cp etc/modifysid.conf /usr/local/suricata/etc/
sudo cp etc/enablesid.conf /usr/local/suricata/etc/
sudo cp etc/disablesid.conf /usr/local/suricata/etc/
cd ..
ruleupdates.sh

#Moloch Stuff
git clone https://github.com/aol/moloch.git
cd moloch
cp ../easybutton-config.sh .
sed -i 's,freeSpaceG = 600,freeSpaceG = 5,' single-host/etc/config.ini.template
sed -i 's/echo -n "Use pfring?.*$/USEPFRING=no/' easybutton-singlehost.sh
sed -i 's/read USEPFRING//' easybutton-singlehost.sh
sed -i 's/echo -n "Memory to give to elasticsearch, box MUST have more then this available: [512M] "//' easybutton-singlehost.sh
sed -i "s,read ESMEM,ESMEM=\"$es_mem\"," easybutton-singlehost.sh
sed -i "s,USERNAME=CHANGEME,USERNAME=cuckoo," easybutton-config.sh
sed -i "s,GROUPNAME=CHANGEME,GROUPNAME=cuckoo," easybutton-config.sh
sed -i "s,PASSWORD=CHANGEME,PASSWORD=${moloch_password}," easybutton-config.sh
sed -i "s,INTERFACE=CHANGEME,INTERFACE=not_needed," easybutton-config.sh
sed -i "s,FQDN=CHANGEME,FQDN=${moloch_fqdn}," easybutton-config.sh
sed -i "s,COUNTRY=CHANGEME,COUNTRY=${moloch_country}," easybutton-config.sh
sed -i "s,STATE=CHANGEME,STATE=${moloch_state}," easybutton-config.sh
sed -i "s,ORG_NAME=CHANGEME,ORG_NAME=${moloch_orgname}," easybutton-config.sh
sed -i "s,ORG_UNIT=CHANGEME,ORG_UNIT=${moloch_orgunit}," easybutton-config.sh
sed -i "s,LOCALITY=CHANGEME,LOCALITY=${moloch_locality}," easybutton-config.sh
sudo ./easybutton-singlehost.sh
cd ..
sudo pkill -f "/data/moloch/bin/node viewer.js"
sudo pkill -f "/data/moloch/elasticsearch"

sudo git clone https://github.com/EmergingThreats/cuckoo-1.1.git /data/cuckoo

rm pcre-8.35 -Rf
rm suricata-2.0.4 -Rf
rm pulledpork-0.6.1 -Rf
rm LuaJIT-2.0.3 -Rf
rm lua-zlib -Rf
rm ltn12ce -Rf
rm yara-3.1.0 -Rf
sudo rm volatility-2.4 -Rf
rm pydeep -Rf
rm distorm3 -Rf
sudo rm moloch -Rf
rm pp.config

chmod +x services/*
sudo cp services/* /etc/init.d/
sudo update-rc.d suricata defaults

#add stuff to rc.local
echo "etc/init.d/moloch start
/etc/init.d/cuckoo start
iptables -A FORWARD -o $out_int -i $sniff_net -s $sniff_sub -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A POSTROUTING -t nat -j MASQUERADE
sysctl -w net.ipv4.ip_forward=1
exit 0" | sudo tee /etc/rc.local

CURRENT_USER=`whoami`
sudo chown $CURRENT_USER:$CURRENT_USER /usr/local/suricata/ -Rf
sudo chown $CURRENT_USER:$CURRENT_USER /data/moloch -Rf
sudo chown $CURRENT_USER:$CURRENT_USER /data/cuckoo -Rf
sudo usermod -a -G cuckoo clamav

echo "/data/cuckoo/storage/** r," | sudo tee /etc/apparmor.d/local/usr.sbin.clamd

echo "deb http://download.virtualbox.org/virtualbox/debian trusty contrib" |sudo tee -a /etc/apt/sources.list
wget -q http://download.virtualbox.org/virtualbox/debian/oracle_vbox.asc -O- | sudo apt-key add -
sudo apt-get update
sudo apt-get install virtualbox-4.3 -y

echo xfce4-session > ~/.xsession
sudo service xrdp restart

echo "#!/bin/sh
su cuckoo -c \"/usr/local/bin/ruleupdates.sh\" && /etc/init.d/suricata restart" | sudo tee /etc/cron.daily/ruleupdates
sudo chmod +x /etc/cron.daily/ruleupdates

#Configure Iptables to allow networking to work
sudo iptables -A FORWARD -o $out_int -i $sniff_net -s $sniff_sub -m conntrack --ctstate NEW -j ACCEPT
sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A POSTROUTING -t nat -j MASQUERADE
sudo sysctl -w net.ipv4.ip_forward=1
