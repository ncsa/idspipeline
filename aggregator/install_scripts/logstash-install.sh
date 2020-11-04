#!/bin/bash

#must run script as root

OS=$(lsb_release -si)
VER=$(lsb_release -sr)

##################
#Ubuntu Install
##################
if [ $OS == 'Ubuntu' ]; then
  echo "Running Ubuntu Install";

  add-apt-repository -y ppa:webupd8team/java
  wget -O - http://packages.elasticsearch.org/GPG-KEY-elasticsearch | sudo apt-key add -
  echo 'deb http://packages.elasticsearch.org/logstash/1.5/debian stable main' | sudo tee /etc/apt/sources.list.d/logstash.list
  apt-get update
  
  apt-get -y install default-jre
  apt-get -y install logstash
  
  
  #install/configure Logstash
  update-rc.d logstash defaults
  /opt/logstash/bin/plugin install logstash-filter-translate
  cp ../logstash/* /etc/logstash/conf.d/

  #install SSL certificate(s)

  service logstash restart

##################
#CentOS Install
##################
elif [ $OS == 'CentOS' ]; then
  echo "Running CentOS Install";

  #Add new source(s)
  echo '[logstash-1.5]
name=Logstash repository for 1.5.x packages
baseurl=http://packages.elasticsearch.org/logstash/1.5/centos
gpgcheck=1
gpgkey=http://packages.elasticsearch.org/GPG-KEY-elasticsearch
enabled=1' >> /etc/yum.repos.d/logstash.repo

  yum -y update
  yum -y install java-1.7.0-openjdk
  yum -y install wget

  #install/configure Logstash
  yum -y install logstash
  #update-rc.d logstash defaults
  /opt/logstash/bin/plugin install logstash-filter-translate
  cp ../logstash/* /etc/logstash/conf.d/


  #install SSL certificate(s)

  service logstash restart
  
  if [[ $VER == '7'* ]]; then
    systemctl daemon-reload
  fi

##########################################################################
##########################################################################

else 
  echo "Don't recognize Linux Distro '$OS'. Not Ubuntu or CentOS";
  exit 1;
fi
