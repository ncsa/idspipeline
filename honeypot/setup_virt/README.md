This directory contains the necessary script and configuration files to 
setup a VM (or bare-metal OS) with all of the pipeline monitoring 
and shipping tools. The script 'install.sh' will work on both the 
ubuntu and centos VMs. The main packages it installs/configures 
are the following:

**NOTE** This script does NOT set up the iptables rules on the bare-metal 
to disallow egress. 

Monitoring Tools:
These tools monitor the honeypot and create log files that contain useful 
information related to security events. All of these host-based alerts 
are aggregated by OSSEC. OSSEC will write the alerts to 
'/var/ossec/logs/alerts/alerts.log'
  Snoopy Logger
    https://github.com/a2o/snoopy
    /var/log/snoopy.log
  OSSEC
    http://ossec.github.io/
    /var/ossec/logs/alerts/alerts.log
  RKHunter
    http://rkhunter.sourceforge.net/
    /var/log/rkhunter.log
  BASH logging
    /var/log/commands.log
  Logrotate
  Rsyslog

Shipping Tools:
This tool is used to send the monitoring tool alerts off of the honeypot. 
This is done over SSL and the certificates need to be configured 
on each endpoint for this to work. The certificate configuration process 
is NOT automated by 'install.sh'. Refer to the following guide for help 
on creating the SSL certificates: https://www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-elk-stack-on-centos-7
  Logstash-forwarder
    https://github.com/elastic/logstash-forwarder
    /var/log/logstash-forwarder
