###################!/bin/bash

#Must run script as root
OS=$(lsb_release -si)
VER=$(lsb_release -sr)
IP=$(ifconfig eth0 | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1')

##################
#Ubuntu Install
##################
if [ $OS == 'Ubuntu' ]; then
  echo "Running Ubuntu Install";

  #Add new source(s)
  echo 'deb http://packages.elasticsearch.org/logstashforwarder/debian stable main' | tee /etc/apt/sources.list.d/logstashforwarder.list
  apt-get update
  
  #install dependencies
  apt-get install -y git curl cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev golang-go ntp
  
  #install/configure logstash-forwarder
  wget -O - http://packages.elasticsearch.org/GPG-KEY-elasticsearch | apt-key add -
  apt-get -y --force-yes install logstash-forwarder
  sed -ri "s/\"host\": \"([0-9]*\.){3}[0-9]*\"/\"host\": \"$IP\"/g" logstash-forwarder/logstash-forwarder.conf
  cp logstash-forwarder/logstash-forwarder.conf /etc/
  mkdir -p /etc/pki/tls/certs
  cp logstash-forwarder/logstash-forwarder.crt /etc/pki/tls/certs/
  service logstash-forwarder restart
  
  
  #install/configure Snoopy
  rm -f snoopy-install.sh
  wget -q -O snoopy-install.sh https://github.com/a2o/snoopy/raw/install/doc/install/bin/snoopy-install.sh
  chmod 755 snoopy-install.sh
  ./snoopy-install.sh stable
  cp snoopy.ini /etc
  snoopy-enable
  
  #install/configure OSSEC
  #wget -U ossec http://www.ossec.net/files/ossec-hids-2.8.2.tar.gz
  #tar -xzvf ossec-hids-2.8.2.tar.gz
  #cd ossec-hids-2.8.2
  git clone https://github.com/ossec/ossec-hids.git
  cd ossec-hids
  ./install.sh
  cd ..
  chmod 755 ossec/*
  cp ossec/local_decoder.xml /var/ossec/etc/
  cp ossec/ossec.conf /var/ossec/etc/
  cp ossec/local_rules.xml /var/ossec/rules
  cp ossec/ossec /etc/init.d/
  update-rc.d ossec defaults
  service ossec restart
  
  #install/configure Bro
  #wget https://www.bro.org/downloads/release/bro-2.4.tar.gz
  #tar -xzvf bro-2.4.tar.gz
  #cd bro-2.4
  #./configure
  #make
  #make install
  #cd ..
  #chmod 755 bro_scripts/*
  #cp bro_scripts/*.bro /usr/local/bro/share/bro/site/ 
  #cp bro_scripts/bro /etc/init.d/
  #update-rc.d bro defaults
  #service bro restart
  
  #install/configure criticalstack
  #curl https://packagecloud.io/install/repositories/criticalstack/critical-stack-intel/script.deb.sh | bash
  #apt-get install critical-stack-intel
  #critical-stack-intel api 255d37eb-9699-4b74-4fef-3474efdce18e
  #critical-stack-intel pull
  #critical-stack-intel config --set bro.restart=true
  #service critical-stack-intel restart
  
  #install rkhunter
  wget http://sourceforge.net/projects/rkhunter/files/latest/download  && mkdir rkhunter_src && tar -xvzf download -C rkhunter_src --strip-components 1 && rm download
  cd rkhunter_src
  ./installer.sh --install
  cd ..
  echo "*/60 * * * * /usr/local/bin/rkhunter --cronjob --update --quiet" >> /etc/cron.d/rkhunter
  cp rkhunter/rkhunter.conf /etc/
  service cron restart
  
  
  #configure bash
  cat bash_additions/bash.bashrc >> /etc/bash.bashrc
  
  #configure logrotate
  chmod 756 logrotate/*
  cp logrotate/* /etc/logrotate.d/
  
  #configure rsyslog
  chmod 755 rsyslog/*
  cp rsyslog/conf/* /etc/rsyslog.d/
  cp rsyslog/ubuntu-rsyslog.conf /etc/rsyslog.conf
  service rsyslog restart
  
  #clean up
  rm -rf snoopy-* 
  #rm -rf bro-2.4* 
  rm -rf ossec-hids*
  rm -rf rkhunter_src*
##########################################################################
##########################################################################


##################
#CentOS Install
##################
elif [ $OS == 'CentOS' ]; then
  echo "Running CentOS Install";

  #Add new source(s)
  rpm --import http://packages.elasticsearch.org/GPG-KEY-elasticsearch
  echo '[logstash-forwarder]
name=logstash-forwarder repository
baseurl=http://packages.elasticsearch.org/logstashforwarder/centos
gpgcheck=1
gpgkey=http://packages.elasticsearch.org/GPG-KEY-elasticsearch
enabled=1' >> /etc/yum.repos.d/logstash-forwarder.repo
  
  #install dependencies
  #yum install -y git curl cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev golang-go
  yum install -y epel-release.noarch
  yum install -y git ntp socat
  yum install -y vixie-cron
  yum -y update
  
  #install/configure logstash-forwarder
  yum -y install logstash-forwarder
  sed -ri "s/\"host\": \"([0-9]*\.){3}[0-9]*\"/\"host\": \"$IP\"/g" logstash-forwarder/logstash-forwarder.conf
  cp logstash-forwarder/logstash-forwarder.conf /etc/
  mkdir -p /etc/pki/tls/certs
  cp logstash-forwarder/logstash-forwarder.crt /etc/pki/tls/certs/
  service logstash-forwarder restart

  #Add the syslog user for it to write logs
  useradd syslog
  
  #install/configure Snoopy
  wget -q -O snoopy-install.sh https://github.com/a2o/snoopy/raw/install/doc/install/bin/snoopy-install.sh
  chmod 755 snoopy-install.sh
  ./snoopy-install.sh stable
  cp snoopy.ini /etc
  snoopy-enable
  
  #install/configure OSSEC
  #wget -U ossec http://www.ossec.net/files/ossec-hids-2.8.2.tar.gz
  #tar -xzvf ossec-hids-2.8.2.tar.gz
  #cd ossec-hids-2.8.2
  git clone https://github.com/ossec/ossec-hids.git
  cd ossec-hids
  ./install.sh
  cd ..
  chmod 755 ossec/*
  cp ossec/local_decoder.xml /var/ossec/etc/
  cp ossec/ossec.conf /var/ossec/etc/
  cp ossec/local_rules.xml /var/ossec/rules
  cp ossec/ossec /etc/init.d/
    #update-rc.d ossec defaults
  service ossec restart
  
  #install/configure Bro
  #wget https://www.bro.org/downloads/release/bro-2.4.tar.gz
  #tar -xzvf bro-2.4.tar.gz
  #cd bro-2.4
  #./configure
  #make
  #make install
  #cd ..
  #chmod 755 bro_scripts/*
  #cp bro_scripts/*.bro /usr/local/bro/share/bro/site/ 
  #cp bro_scripts/bro /etc/init.d/
  #update-rc.d bro defaults
  #service bro restart
  
  #install/configure criticalstack
  #curl https://packagecloud.io/install/repositories/criticalstack/critical-stack-intel/script.deb.sh | bash
  #apt-get install critical-stack-intel
  #critical-stack-intel api 255d37eb-9699-4b74-4fef-3474efdce18e
  #critical-stack-intel pull
  #critical-stack-intel config --set bro.restart=true
  #service critical-stack-intel restart
  
  #install rkhunter
  wget http://sourceforge.net/projects/rkhunter/files/latest/download  && mkdir rkhunter_src && tar -xvzf download -C rkhunter_src --strip-components 1 && rm download
  cd rkhunter_src
  ./installer.sh --install
  cd ..
  echo "*/60 * * * * /usr/local/bin/rkhunter --cronjob --update --quiet" >> /etc/cron.d/rkhunter
  cp rkhunter/rkhunter.conf /etc/ 
  service crond restart
  
  
  #configure bash
  cat bash_additions/bash.bashrc >> /etc/bashrc
  
  #configure logrotate
  chmod 755 logrotate/*
  cp logrotate/* /etc/logrotate.d/
  
  #configure rsyslog
  chmod 755 rsyslog/*
  cp rsyslog/conf/* /etc/rsyslog.d/
  cp rsyslog/centos-rsyslog.conf /etc/rsyslog.conf
  service rsyslog restart
  
  #clean up
  rm -rf snoopy-* 
  #rm -rf bro-2.4* 
  rm -rf ossec-hids*
  rm -rf rkhunter_src*
##########################################################################
##########################################################################



else 
  echo "Don't recognize Linux Distro '$OS'. Not Ubuntu or CentOS";
  exit 1;
fi





