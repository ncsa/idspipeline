#!/bin/bash

#must run script as root

if hash lsb_release 2>/dev/null; then
    echo "foo"
    OS=$(lsb_release -si)
    VER=$(lsb_release -sr)
else
    echo "bar"
    yum install -y redhat-lsb-core
    OS=$(lsb_release -si)
    VER=$(lsb_release -sr)
fi


##################
#Ubuntu Install
##################
if [ $OS == 'Ubuntu' ]; then
  echo "Running Ubuntu Install";

  add-apt-repository -y ppa:webupd8team/java
  wget -O - http://packages.elasticsearch.org/GPG-KEY-elasticsearch | sudo apt-key add -
  echo 'deb http://packages.elasticsearch.org/elasticsearch/1.4/debian stable main' | sudo tee /etc/apt/sources.list.d/elasticsearch.list
  echo 'deb http://packages.elasticsearch.org/logstash/1.5/debian stable main' | sudo tee /etc/apt/sources.list.d/logstash.list
  apt-get update
  
  apt-get -y install oracle-java8-installer
  apt-get -y install elasticsearch
  apt-get -y install logstash
  
  
  #install/configure Logstash
  update-rc.d logstash defaults
  /opt/logstash/bin/plugin install logstash-filter-translate
  cp logstash/* /etc/logstash/conf.d/
  
  #install SSL cert
  
  #Restart logstash with new cert
  service logstash restart

  #install logrotate scripts for raw logs
  cp logrotate/* /etc/logrotate.d/
  
  #install/configure Elasticsearch
  update-rc.d elasticsearch defaults
  service elasticsearch restart
  
  #install/configure Kibana
  wget https://download.elasticsearch.org/kibana/kibana/kibana-4.0.1-linux-x64.tar.gz
  tar xvf kibana-*.tar.gz
  mkdir -p /opt/kibana
  cp -R kibana-4*/* /opt/kibana/
  wget https://gist.githubusercontent.com/thisismitch/8b15ac909aed214ad04a/raw/bce61d85643c2dcdfbc2728c55a41dab444dca20/kibana4
  chmod +x kibana4
  cp kibana4 /etc/init.d/
  update-rc.d kibana4 defaults
  service kibana4 restart
  
  #install/configure Kafka
  wget "http://mirror.symnds.com/software/Apache/kafka/0.8.2.1/kafka_2.11-0.8.2.1.tgz" -O kafka.tgz
  mkdir kafka && tar -C kafka -xvzf kafka.tgz --strip-components 1
  #kafka/bin/zookeeper-server-start.sh kafka/config/zookeeper.properties &
  #kafka/bin/kafka-server-start.sh kafka/config/server.properties &
  rm kafka.tgz
  
##########################################################################
##########################################################################



##################
#CentOS Install
##################
elif [ $OS == 'CentOS' ]; then
  echo "Running CentOS Install";

  #Add new source(s)
  rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch
  echo '[elasticsearch-1.7]
name=Elasticsearch repository for 1.7.x packages
baseurl=http://packages.elasticsearch.org/elasticsearch/1.7/centos
gpgcheck=1
gpgkey=http://packages.elasticsearch.org/GPG-KEY-elasticsearch
enabled=1' >> /etc/yum.repos.d/elasticsearch.repo

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
  cp logstash/* /etc/logstash/conf.d/
  
  #install SSL cert

  #install logrotate scripts for raw logs
  cp logrotate/* /etc/logrotate.d/
  
  #Restart logstash with new cert
  service logstash restart

  #install/configure Elasticsearch
  yum -y install elasticsearch
  #update-rc.d elasticsearch defaults
  service elasticsearch restart
  
  #install/configure Kibana
  wget https://download.elastic.co/kibana/kibana/kibana-4.1.2-linux-x64.tar.gz -O kibana.tgz
  mkdir kibana && tar -C kibana -xvzf kibana.tgz --strip-components 1
  mv kibana /opt/kibana

  wget https://raw.githubusercontent.com/Xaway/script/master/init_kibana -O kibana4
  chmod +x kibana4
  mv kibana4 /etc/init.d/
  service kibana4 restart
  
  #install/configure Kafka
  wget "http://mirror.symnds.com/software/Apache/kafka/0.8.2.1/kafka_2.11-0.8.2.1.tgz" -O kafka.tgz
  mkdir kafka && tar -C kafka -xvzf kafka.tgz --strip-components 1
  #kafka/bin/zookeeper-server-start.sh kafka/config/zookeeper.properties &
  #kafka/bin/kafka-server-start.sh kafka/config/server.properties &
  

  #cleanup
  rm kafka.tgz
  rm kibana.tgz 
  rm -r kibana

  if [[ $VER == '7'* ]]; then
    systemctl daemon-reload
  fi


##########################################################################
##########################################################################

else 
  echo "Don't recognize Linux Distro '$OS'. Not Ubuntu or CentOS";
  exit 1;
fi
