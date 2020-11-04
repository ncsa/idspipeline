This directory contains the necessary scripts to install the aggregator 
and also the network-based monitoring tools. In our pipeline deployment, 
these were both run on the bare-metal of the same machine that the 
honeypots were run on, so we have included both of them in this directory 
(install\_scripts/{bro-install.sh, logstash-install.sh}). However, 
these do not both need to be installed on the same machine and, in fact, 
do not need to be run on the bare-metal of the machine that houses the 
honeypots. 

To replicate our deployment, run the agg-install.sh script, which will 
install the Bro network monitoring tool along with the Critical-stack 
Intel feed. It will also install Logstash, which ingests alerts from 
both Bro (by tailing the Bro files) and the honeypot (via 
logstash-forwarder over SSL). You will need to create/configure the SSL 
certificates in Logstash for it to work properly between the honeypot and 
also between the collector. The configuration can be found in 
'/etc/logstash/conf.d/' in the "input" and "output" configuration files. 
