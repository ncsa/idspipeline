#!/bin/bash

#must run script as root

OS=$(lsb_release -si)
VER=$(lsb_release -sr)

##################
#Ubuntu Install
##################
if [ $OS == 'Ubuntu' ]; then
  echo "Running Ubuntu Install";
  apt-get -y update
  apt-get install -y git build-essential curl cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev golang-go ntp

  ##install/configure Bro
  wget https://www.bro.org/downloads/release/bro-2.4.1.tar.gz
  tar -xzvf bro-2.4.1.tar.gz
  cd bro-2.4.1
  ./configure
  make
  make install
  cd ..
  chmod 755 ../bro_scripts/*
  cp ../bro_scripts/*.bro /usr/local/bro/share/bro/site/ 
  cp ../bro_scripts/bro /etc/init.d/
  update-rc.d bro defaults
  
  #install/configure criticalstack
  curl https://packagecloud.io/install/repositories/criticalstack/critical-stack-intel/script.deb.sh | bash
  apt-get -y install critical-stack-intel
  cp ../__load__.bro /opt/critical-stack/frameworks/intel/
  critical-stack-intel api 255d37eb-9699-4b74-4fef-3474efdce18e
  critical-stack-intel pull
  critical-stack-intel config --set bro.restart=true
  service critical-stack-intel restart
  
  service bro restart

  #clean up
  rm -rf bro-2.4*

##################
#CentOS Install
##################
elif [ $OS == 'CentOS' ]; then
  echo "Running CentOS Install";
  yum -y update
  yum install -y cmake gcc g++ gcc-c++ flex bison swig zlib libpcap libpcap-devel python-devel openssl-devel
  yum install -y git build-essential curl cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev golang-go ntp

  ##install/configure Bro
  wget https://www.bro.org/downloads/release/bro-2.4.1.tar.gz
  tar -xzvf bro-2.4.1.tar.gz
  cd bro-2.4.1
  ./configure
  make
  make install
  cd ..
  chmod 755 ../bro_scripts/*
  cp ../bro_scripts/*.bro /usr/local/bro/share/bro/site/ 
  cp ../bro_scripts/bro /etc/init.d/
  chkconfig --add ../bro_scripts/bro
  chkconfig bro on
  
  #install/configure criticalstack
  #curl --silent https://packagecloud.io/install/repositories/criticalstack/critical-stack-intel/script.rpm | sudo bash
  wget https://packagecloud.io/install/repositories/criticalstack/critical-stack-intel/script.rpm.sh; chmod 755 script.rpm.sh; ./script.rpm.sh; rm script.rpm.sh;
  yum -y install critical-stack-intel
  cp ../__load__.bro /opt/critical-stack/frameworks/intel/
  critical-stack-intel api 255d37eb-9699-4b74-4fef-3474efdce18e
  critical-stack-intel pull
  critical-stack-intel config --set bro.restart=true
  service critical-stack-intel restart
  
  service bro restart

  #clean up
  rm -rf bro-2.4*

##########################################################################
##########################################################################

else 
  echo "Don't recognize Linux Distro '$OS'. Not Ubuntu or CentOS";
  exit 1;
fi
